import json
from types import SimpleNamespace as NS
import pytest
from forensic_assistant.ai import cloud_worker, readiness, provider_diagnostics as d
from forensic_assistant.ai.settings import PROVIDERS, defaults

@pytest.mark.parametrize('provider,expected', [('gemini',[256,512,1024,1024]),('openai',[64,64,256,256]),('deepseek',[64,64,64,64])])
def test_stage_budgets_and_normal_requests(monkeypatch,provider,expected):
    monkeypatch.setenv(PROVIDERS[provider][1],'synthetic-key')
    schemas=[readiness.SCHEMA]+[p[1] for p in readiness.openai_probes()]
    for schema,budget in zip(schemas,expected):
        request=dict(provider=provider,model='synthetic',messages=readiness.MESSAGES,schema=schema,timeout=15,handshake=True)
        assert cloud_worker.request_kwargs(request)['max_tokens']==budget
        request['handshake']=False
        assert cloud_worker.request_kwargs(request)['max_tokens']==1024

@pytest.mark.parametrize('budget',[256,512,1024])
def test_truncation_logs_no_payload(monkeypatch,budget):
    result=NS(choices=[NS(finish_reason='length',message=NS(content='PRIVATE RESPONSE EVIDENCE'))])
    sdk=NS(completion=lambda **kw:result)
    with pytest.raises(d.ProviderFailure) as error:
        cloud_worker.complete(dict(custom_llm_provider='gemini',max_tokens=budget,messages='PRIVATE PROMPT'),sdk)
    exc=error.value
    assert exc.category=='output_truncated'
    assert exc.stage=='provider_generation'
    detail=exc.metadata['gemini_response']
    assert detail['json_parse']==detail['wire_validation']=='not_attempted'
    assert detail['finish_reason']=='length'
    captured=[]
    monkeypatch.setattr(d.diagnostics,'append',lambda path,text:captured.append(text))
    d.record('gemini','synthetic',exc.stage,exc.category,operation='handshake',metadata=exc.metadata)
    text=d.render(captured[0])
    assert 'Max output tokens: '+str(budget) in text
    assert 'truncated before a complete structured response' in text
    assert 'PRIVATE' not in text and 'PRIVATE' not in captured[0]
    assert 'structured_validation_failed' not in text


def test_generate_retains_truncation_metadata(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY','synthetic-key')
    sdk=NS(completion=lambda **kw:NS(choices=[NS(finish_reason='length',message=NS(content='secret'))]))
    with pytest.raises(d.ProviderFailure) as error:
        cloud_worker.generate(dict(provider='gemini',model='synthetic',messages=readiness.MESSAGES,schema=readiness.SCHEMA,timeout=15,handshake=True),sdk)
    assert error.value.category=='output_truncated'
    assert error.value.metadata['max_output_tokens']==256


def test_quota_separate():
    assert d.classify(NS(status_code=429))=='rate_limited'
    assert d.classify(NS(code='insufficient_quota'))=='quota_or_billing'


def test_stop_still_extracts_string():
    sdk=NS(completion=lambda **kw:NS(choices=[NS(finish_reason='stop',message=NS(content='{"status":"ok"}'))]))
    assert cloud_worker.complete(dict(custom_llm_provider='gemini',max_tokens=256),sdk)['text']=='{"status":"ok"}'


def test_truncation_stops_readiness(monkeypatch):
    from forensic_assistant.ai.backend import ModelBackend
    readiness.reset()
    monkeypatch.setenv('GEMINI_API_KEY','synthetic-key')
    calls=[]
    def fail(*args,**kwargs):
        calls.append(kwargs)
        raise d.ProviderFailure('output_truncated','provider_generation',metadata={'max_output_tokens':256})
    monkeypatch.setattr(ModelBackend,'_cloud',fail)
    monkeypatch.setattr(readiness,'record',lambda *a,**k:None)
    result=readiness.check({**defaults(),'provider':'gemini','model':'synthetic','cloud_acknowledged':True})
    assert len(calls)==1
    assert result['readiness_category']=='output_truncated'
    assert 'truncated' in result['readiness_reason']
    assert result['locard_compatibility']!='ready'
    readiness.reset()

import json
from types import SimpleNamespace as NS
import pytest
from forensic_assistant.ai import cloud_worker, readiness, provider_diagnostics as d
from forensic_assistant.ai.gemini_usage import safe

@pytest.mark.parametrize('finish',['length','stop'])
@pytest.mark.parametrize('present',[True,False])
def test_usage_counts_only(finish,present,monkeypatch):
    usage=NS(prompt_tokens=42,completion_tokens=512,total_tokens=554,
        completion_tokens_details=NS(reasoning_tokens=491,reasoning='SECRET'),
        prompt_tokens_details=NS(cached_tokens=10),raw='SECRET') if present else None
    result=NS(choices=[NS(finish_reason=finish,message=NS(content='{"status":"ok"}',reasoning_content='SECRET'))],usage=usage)
    sdk=NS(completion=lambda **kw:result)
    if finish=='length':
        with pytest.raises(d.ProviderFailure) as err:
            cloud_worker.complete({'custom_llm_provider':'gemini','max_tokens':512},sdk)
        metadata=err.value.metadata
        assert err.value.category=='output_truncated'
    else:
        metadata=cloud_worker.complete({'custom_llm_provider':'gemini','max_tokens':512},sdk)
    counts=metadata.get('gemini_usage',{})
    assert counts==({'prompt_tokens':42,'completion_tokens':512,'total_tokens':554,'reasoning_tokens':491,'cached_tokens':10} if present else {})
    captured=[]
    monkeypatch.setattr(d.diagnostics,'append',lambda path,text:captured.append(text))
    d.record('gemini','synthetic','provider_generation','output_truncated',metadata=metadata)
    assert 'SECRET' not in captured[0] and 'status' not in json.dumps(d.safe_metadata(metadata))
    if present: assert 'Reasoning tokens: 491' in d.render(captured[0])


def test_untrusted_counts():
    assert safe({'reasoning_tokens':'SECRET','cached_tokens':True,'total_tokens':-1,'prompt_tokens':10000001,'completion_tokens':2,'raw':'SECRET'})=={'completion_tokens':2}


def test_success_validation_logged(monkeypatch):
    from forensic_assistant.ai.backend import ModelBackend
    from forensic_assistant.ai.settings import defaults
    monkeypatch.setenv('GEMINI_API_KEY','synthetic')
    client=ModelBackend(config={**defaults(),'provider':'gemini','model':'synthetic','cloud_acknowledged':True})
    monkeypatch.setattr(client,'_cloud_request',lambda *a,**k:{'text':'{"status":"ok"}','usage':{},'gemini_usage':{'reasoning_tokens':400},'max_output_tokens':512,'gemini_response':{'finish_reason':'stop','json_parse':'not_attempted','wire_validation':'not_attempted'}})
    captured=[]
    monkeypatch.setattr(d.diagnostics,'append',lambda path,text:captured.append(text))
    client._cloud(readiness.MESSAGES,readiness.SCHEMA,handshake=True)
    text=d.render(captured[0])
    for expected in ('Finish reason: stop','Max output tokens: 512','Json parse: success','Wire validation: passed','Canonical validation: passed'):
        assert expected in text


def test_gemini_worker_success_ipc(monkeypatch):
    import importlib.util
    from forensic_assistant.ai import backend as b
    from forensic_assistant.ai.settings import defaults
    monkeypatch.setenv('GEMINI_API_KEY','synthetic')
    payload={'text':'{"status":"ok"}','usage':{},'gemini_usage':{},'max_output_tokens':512,'gemini_response':{'finish_reason':'stop'}}
    process=NS(pid=123,returncode=0,communicate=lambda *a,**k:(json.dumps(payload).encode(),None),poll=lambda:0,wait=lambda **k:0)
    monkeypatch.setattr(importlib.util,'find_spec',lambda name:True)
    monkeypatch.setattr(b.subprocess,'Popen',lambda *a,**k:process)
    monkeypatch.setattr(b,'WorkerJob',lambda pid:NS(close=lambda:None))
    client=b.ModelBackend(config={**defaults(),'provider':'gemini','model':'synthetic','cloud_acknowledged':True})
    assert client._cloud_request(readiness.MESSAGES,readiness.SCHEMA,handshake=True)==payload
    payload['unexpected']='SECRET'
    with pytest.raises(d.ProviderFailure):
        client._cloud_request(readiness.MESSAGES,readiness.SCHEMA,handshake=True)

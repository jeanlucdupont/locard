"""Capability and canonical-validation matrix; all provider responses are synthetic."""
import copy
import json
from types import SimpleNamespace
import pytest
from forensic_assistant.ai import capabilities, cloud_worker, readiness, settings, diagnostics
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.ai.provider_diagnostics import ProviderFailure, request_features
from forensic_assistant.ai.response_contract import validate


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    for _, name in settings.PROVIDERS.values():
        if name:
            monkeypatch.setenv(name, 'PRIVATE-SYNTHETIC-KEY')
    readiness.reset()
    yield
    readiness.reset()


def config(provider):
    return {**settings.defaults(), 'provider': provider, 'model': 'unchanged-id', 'cloud_acknowledged': True}


def probe_responses(provider):
    replies = ['{"status":"ok"}']
    if provider == 'openai':
        for family, _, expected, _ in readiness.openai_probes():
            replies.append(json.dumps({'proposal': expected} if family == 'investigation' else expected))
    else:
        replies.append('{"status":"ok","message":"locard"}')
    return replies


def mock_transport(monkeypatch, replies, calls):
    responses = iter(replies)
    def transport(self, messages, schema, **kw):
        calls.append((messages, schema, cloud_worker.request_kwargs(dict(
            provider=self.provider_name, model=self.model_name, messages=messages,
            schema=schema, timeout=kw['timeout'], handshake=kw.get('handshake', False)))))
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return {'text': response, 'usage': {}}
    monkeypatch.setattr(ModelBackend, '_cloud_request', transport)


@pytest.mark.parametrize('provider,mode', [(p,c.mode) for p,c in capabilities.CAPABILITIES.items()])
def test_probe_and_normal_use_identical_mode_and_canonical_contract(provider,mode,monkeypatch):
    calls=[]
    mock_transport(monkeypatch, probe_responses(provider) + ['{"status":"ok","message":"locard"}'], calls)
    schema=copy.deepcopy(readiness.COMPAT_SCHEMA)
    before=copy.deepcopy(schema)
    client=ModelBackend(config=config(provider))
    assert json.loads(client.complete([{'role':'user','content':'SYNTHETIC EVIDENCE'}],schema))=={'status':'ok','message':'locard'}
    assert len(calls)==len(probe_responses(provider))+1
    assert all(request_features(call[2])['structured_output']==mode for call in calls)
    assert all('SYNTHETIC EVIDENCE' not in json.dumps(call) for call in calls[:-1])
    assert calls[-1][1]==schema==before
    assert client.config['model']=='unchanged-id'
    assert calls[-1][2]['model']==provider+'/unchanged-id'
    assert all('tools' not in c[2] and c[2]['num_retries']==0 for c in calls)
    assert readiness.status(client.config)['locard_compatibility']=='ready'
    log=diagnostics.tail('provider.log')
    assert mode in log and 'SYNTHETIC EVIDENCE' not in log and 'PRIVATE-SYNTHETIC-KEY' not in log


@pytest.mark.parametrize('provider', capabilities.CAPABILITIES)
@pytest.mark.parametrize('response,category', [('not json','response_parse_failed'),
    ('{"status":"ok","message":4}','structured_validation_failed'),
    ('{"status":"ok","message":"locard","extra":1}','structured_validation_failed')])
def test_every_provider_response_locally_validated(provider,response,category,monkeypatch):
    calls=[]
    mock_transport(monkeypatch,probe_responses(provider)+[response],calls)
    client=ModelBackend(config=config(provider))
    with pytest.raises(ProviderFailure) as failure:
        client.complete([{'role':'user','content':'SECRET-EVIDENCE'}],readiness.COMPAT_SCHEMA)
    assert failure.value.category==category and len(calls)==len(probe_responses(provider))+1
    assert readiness.status(client.config)['provider_readiness']=='unchecked'
    log=diagnostics.tail('provider.log')
    assert capabilities.CAPABILITIES[provider].mode in log
    assert 'SECRET-EVIDENCE' not in log and 'PRIVATE-SYNTHETIC-KEY' not in log


def test_failed_compatibility_blocks_evidence_and_cache(monkeypatch):
    calls=[]
    mock_transport(monkeypatch,['{"status":"ok"}','{"status":"ok"}'],calls)
    client=ModelBackend(config=config('deepseek'))
    for _ in range(2):
        with pytest.raises(ProviderFailure,match='connected.*not compatible'):
            client.complete([{'role':'user','content':'NEVER SEND EVIDENCE'}],readiness.COMPAT_SCHEMA)
    assert len(calls)==2
    assert all('NEVER SEND' not in json.dumps(c) for c in calls)
    assert readiness.status(client.config)['locard_compatibility']=='failed'


def test_no_fallback_or_silent_reprobe_after_real_failure(monkeypatch):
    calls=[]
    mock_transport(monkeypatch,probe_responses('openai')+[
        ProviderFailure('structured_output_unsupported'),'{"status":"wrong"}'],calls)
    provider='openai'
    client=ModelBackend(config=config(provider))
    with pytest.raises(ProviderFailure):client.complete([],readiness.COMPAT_SCHEMA)
    assert len(calls)==len(probe_responses(provider))+1
    with pytest.raises(ProviderFailure):client.complete([],readiness.COMPAT_SCHEMA)
    assert len(calls)==len(probe_responses(provider))+1
    assert readiness.status(client.config)['provider_readiness']=='unchecked'
    assert all(c[2]['response_format']['type']=='json_schema' for c in calls)


@pytest.mark.parametrize('text', ['{"status":"ok","status":"ok"}', '{"status":NaN}',
    '{"status":Infinity}', '{"status":-Infinity}', '```json\n{}\n```'])
def test_parser_rejects_noncanonical_json(text):
    with pytest.raises(ProviderFailure):validate(text,readiness.SCHEMA)


def test_nested_contract_and_external_references_fail_closed():
    schema={'type':'object','required':['items'],'additionalProperties':False,
        'properties':{'items':{'type':'array','minItems':1,'maxItems':1,'items':{
            'oneOf':[{'type':'integer'},{'type':'string','enum':['allowed']}]}}}}
    assert validate('{"items":["allowed"]}',schema)=={'items':['allowed']}
    for text in ('{"items":[true]}','{"items":["wrong"]}','{"items":[]}', '{"items":[1,2]}'):
        with pytest.raises(ProviderFailure):validate(text,schema)
    with pytest.raises(ProviderFailure):validate('{}',{'$ref':'https://never-fetch.invalid/schema'})


def test_key_model_and_mode_changes_require_new_check(monkeypatch):
    calls=[]
    replies=['{"status":"ok"}','{"status":"ok","message":"locard"}']*4
    mock_transport(monkeypatch,replies,calls)
    value=config('deepseek')
    readiness.check(value)
    readiness.check(value)
    assert len(calls)==2
    monkeypatch.setenv('DEEPSEEK_API_KEY','NEW-PRIVATE-KEY')
    readiness.check(value)
    readiness.check({**value,'model':'new-model'})
    assert len(calls)==6
    monkeypatch.setitem(capabilities.CAPABILITIES,'deepseek',capabilities.Capability('deepseek','json_schema',True,True))
    readiness.check(value)
    assert len(calls)==8


def test_local_unchanged_no_cloud_validator(monkeypatch):
    client=ModelBackend(endpoint='http://127.0.0.1:8000')
    monkeypatch.setattr(readiness,'check',lambda *a,**k:pytest.fail('cloud check for local'))
    from forensic_assistant.llm.client import LocalClient
    def local(self,*a,**k):
        self.last_metadata={}
        return 'local unchanged'
    monkeypatch.setattr(LocalClient,'complete',local)
    assert client.complete([])=='local unchanged'

@pytest.mark.parametrize('provider', capabilities.CAPABILITIES)
def test_schema_valid_ungrounded_conclusion_still_rejected(provider,tmp_path,monkeypatch):
    from forensic_assistant.investigation_ai import controller
    from forensic_assistant.investigation_ai.state import Budget
    from test_investigation_assessment import RecordingWorker
    from test_investigation_grounding_ux import unsupported
    calls=[]
    mock_transport(monkeypatch,probe_responses(provider)+[
        json.dumps({'proposal': unsupported()} if provider == 'openai' else unsupported())],calls)
    client=ModelBackend(config=config(provider))
    result=controller.run({},'Inspect synthetic evidence',tmp_path/'runs',
        client=client,budget=Budget(steps=1),worker_factory=RecordingWorker)
    assert result['state']['final_grounding_rejections']==1
    assert result['state']['final_grounding_reasons']==['unexposed_field']
    assert result['termination']!='ANSWER_SUPPORTED'
    assert len(calls)==len(probe_responses(provider))+1


def test_cancelled_probe_preserves_cancellation(monkeypatch):
    monkeypatch.setattr(readiness,'check',lambda *a,**kw:{'readiness_category':'cancelled'})
    with pytest.raises(KeyboardInterrupt):ModelBackend(config=config('deepseek')).prepare()

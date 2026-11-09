"""Synthetic SDK/IPC diagnostics; no provider requests or payload logging."""
import json
from types import SimpleNamespace as N
import pytest
from forensic_assistant.ai import cloud_worker, provider_diagnostics as pd, settings
from forensic_assistant.ai.response_envelope import safe, LIMIT
from forensic_assistant import briefing as b, briefing_cli


class SDK:
    def __init__(self,result):self.result=result
    def completion(self,**kwargs):return self.result


def envelope(finish='stop',text='{"items":[]}',**calls):
    return N(choices=[N(finish_reason=finish,message=N(content=text,**calls))])


class Broken:
    @property
    def choices(self):raise RuntimeError('SECRET MODEL BODY sk-private')


CASES=[
    (envelope('length','SECRET MODEL BODY'),'output_truncated'),
    (envelope('PRIVATE FINISH'),'unexpected_finish_reason'),
    (N(),'missing_response_message'),
    (N(choices=[]),'missing_response_message'),
    (N(choices=[N(finish_reason='stop')]),'missing_response_message'),
    (N(choices=[N(finish_reason='stop',message=N())]),'missing_response_content'),
    (envelope(text=''),'empty_response_content'),
    (envelope(text={'SECRET':'BODY'}),'invalid_content_type'),
    (envelope(text='z'*(LIMIT+2)),'response_size_exceeded'),
    (envelope(tool_calls=['SECRET TOOL']),'unexpected_tool_call'),
    (envelope(function_call={'SECRET':'ARG'}),'unexpected_tool_call'),
    (Broken(),'invalid_response_envelope'),
]


@pytest.mark.parametrize('result,rule',CASES,ids=[r+'-'+str(i) for i,(_,r) in enumerate(CASES)])
def test_envelope_checks_and_briefing_output(result,rule,monkeypatch):
    # Load modules holding validator aliases before the temporary guard, so it
    # cannot become a persistent import-time alias in unrelated provider tests.
    from forensic_assistant.ai import anthropic_strategy
    from forensic_assistant.ai import response_contract
    monkeypatch.setattr(response_contract,'validate',lambda *a,**k:pytest.fail('JSON validation reached'))
    with pytest.raises(pd.ProviderFailure) as caught:
        cloud_worker.complete({'custom_llm_provider':'openai','max_tokens':1024},SDK(result))
    exc=caught.value;detail=exc.metadata['response_envelope']
    assert exc.stage=='response_envelope'
    assert exc.category==('output_truncated' if rule=='output_truncated' else 'response_envelope_failed')
    assert detail['rule']==rule and detail['json_parse']==detail['canonical_validation']=='not_attempted'
    assert detail['output_token_limit']==1024
    class Client:
        provider_name='openai'
        def complete(self,*args):raise exc
    packet=b.extract('baje.ps1');b.interpret(packet,Client(),allow_cloud=True)
    assert packet['ai_status']=='failed' and packet['leads'] and not packet['ai_items']
    assert packet['ai_error']['envelope']==detail
    rendered=briefing_cli.render(packet)
    assert rule in rendered and 'not_attempted' in rendered
    assert all(v not in json.dumps(packet['ai_error'])+rendered for v in ('SECRET','PRIVATE FINISH','sk-private'))


@pytest.mark.parametrize('finish',['stop','end_turn'])
def test_success_unchanged(finish):
    result=cloud_worker.complete({'custom_llm_provider':'openai','max_tokens':1024},SDK(envelope(finish)))
    assert result=={'text':'{"items":[]}','usage':{},'finish_reason':finish}


def test_allowlist_and_optional_values():
    assert safe({'rule':'SECRET','finish_reason':'SECRET','content_type':'SECRET','raw':'SECRET',
                 'content_bytes':True,'output_token_limit':999999,'json_parse':'SECRET'})=={}
    assert safe(None)=={}


def test_generate_ipc_parent_log_and_briefing_roundtrip(tmp_path,monkeypatch):
    from forensic_assistant.ai.backend import ModelBackend
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path));monkeypatch.setenv('OPENAI_API_KEY','SYNTHETIC-SECRET')
    request=dict(provider='openai',model='synthetic',messages=[],schema=b.SCHEMA,timeout=45)
    with pytest.raises(pd.ProviderFailure) as caught:
        cloud_worker.generate(request,SDK(envelope('length','SECRET MODEL CONTENT')))
    # Same bounded error envelope serialized by cloud_worker.main and reconstructed
    # by ModelBackend._cloud_request; no SDK objects or exception strings cross IPC.
    exc=caught.value
    wire=json.dumps({'error':pd.classify(exc),'stage':exc.stage,'metadata':pd.error_metadata(exc)})
    assert 'SECRET' not in wire
    value=json.loads(wire)
    restored=pd.ProviderFailure(value['error'],value['stage'],metadata=value['metadata'])
    config={**settings.defaults(),'provider':'openai','model':'synthetic','cloud_acknowledged':True}
    backend=ModelBackend(config=config)
    def reply(*args,**kwargs):raise restored
    monkeypatch.setattr(backend,'_cloud_request',reply)
    with pytest.raises(pd.ProviderFailure) as logged:backend._cloud([],b.SCHEMA)
    raw=(settings.root()/'provider.log').read_text()
    assert 'SECRET' not in raw and 'output_truncated' in pd.render(raw)
    assert json.loads(raw.splitlines()[-1])['response_envelope']['output_token_limit']==b.OPENAI_OUTPUT_TOKENS
    assert logged.value.metadata['response_envelope']==restored.metadata['response_envelope']


def test_uniqueness_instruction_and_budget_unchanged(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','SYNTHETIC')
    kwargs=cloud_worker.request_kwargs(dict(provider='openai',model='synthetic',messages=[],schema=b.SCHEMA,timeout=45))
    assert kwargs['max_tokens']==b.OPENAI_OUTPUT_TOKENS and kwargs['num_retries']==0
    assert 'No duplicate interpretation items or repeated entity IDs' in b.SYSTEM

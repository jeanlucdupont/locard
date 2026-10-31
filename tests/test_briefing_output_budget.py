"""Operation-specific budget and response capacity; synthetic requests only."""
import json
from types import SimpleNamespace as N
import pytest
from forensic_assistant import briefing as b, briefing_cli
from forensic_assistant.ai import cloud_worker, readiness, settings
from forensic_assistant.ai.openai_schema import response
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from forensic_assistant.investigation_ai import contracts


def request(provider,schema,handshake=False):
    return dict(provider=provider,model='synthetic',schema=schema,messages=[],timeout=45,handshake=handshake)


@pytest.mark.parametrize('provider',['openai','anthropic','gemini','deepseek','xai'])
def test_only_openai_briefing_budget_changes(provider,monkeypatch):
    monkeypatch.setenv(settings.PROVIDERS[provider][1],'synthetic')
    assert cloud_worker.request_kwargs(request(provider,b.SCHEMA))['max_tokens']==(4096 if provider=='openai' else 1024)
    for schema in (readiness.SCHEMA,contracts.schema(list(contracts.TOOLS))):
        assert cloud_worker.request_kwargs(request(provider,schema))['max_tokens']==1024
    if provider=='openai':
        assert cloud_worker.request_kwargs(request('openai',b.SCHEMA,True))['max_tokens']==64


def test_budget_reaches_sdk_and_no_retry(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','synthetic');calls=[]
    class SDK:
        def completion(self,**kwargs):
            calls.append(kwargs)
            return N(choices=[N(finish_reason='length',message=N(content=''))])
    with pytest.raises(ProviderFailure) as caught:cloud_worker.generate(request('openai',b.SCHEMA),SDK())
    assert len(calls)==1 and calls[0]['max_tokens']==4096 and calls[0]['num_retries']==0
    assert caught.value.category=='output_truncated'
    assert caught.value.metadata['response_envelope']['output_token_limit']==4096
    class Client:
        provider_name='openai'
        def complete(self,*args):raise caught.value
    p=b.extract('baje.ps1');b.interpret(p,Client(),allow_cloud=True)
    assert p['leads'] and p['ai_status']=='failed' and '4096' in briefing_cli.render(p)


def large_response():
    # Escaped whitespace deliberately exceeds the old byte bound while obeying
    # all per-string and item constraints; token counts are not inferred from bytes.
    text='Analyst assertion '+('\t'*380)+'uncertain'
    values=[dict(category='hypothesis',start=0,end=len(text),quote=text,text=text,
                 basis='explicit',entity_ids=[],uncertainty='Unverified '+str(i)+' '+('\t'*270)) for i in range(12)]
    return text,json.dumps({'items':values},ensure_ascii=True)


def test_larger_valid_response_and_unchanged_default_parser_bound():
    text,raw=large_response()
    assert 16384<len(raw.encode())<b.OPENAI_RESPONSE_BYTES
    with pytest.raises(ValueError):contracts.loads(raw)
    response('openai',raw,b.SCHEMA)
    class Client:
        provider_name='openai'
        calls=0
        def complete(self,*args):self.calls+=1;return raw
    client=Client();p=b.extract(text);b.interpret(p,client,allow_cloud=True)
    assert client.calls==1 and p['ai_status']=='success' and len(p['ai_items'])==12
    assert all(r['verification']=='UNVERIFIED AI INTERPRETATION' for r in p['ai_items'])
    assert 'hypothesis' in briefing_cli.render(p)


def test_openai_briefing_size_bound_remains_hard():
    class Client:
        provider_name='openai'
        def complete(self,*args):return ' '* (b.OPENAI_RESPONSE_BYTES+1)
    p=b.extract('baje.ps1');b.interpret(p,Client(),allow_cloud=True)
    assert p['ai_error']['rule']=='response_size_limit'

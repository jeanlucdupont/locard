"""Common adapter shape and handshake-only compatibility; no provider traffic."""
from types import SimpleNamespace
import json
import pytest
from forensic_assistant.ai import cloud_worker, readiness, settings, provider_diagnostics as pd
from forensic_assistant.ai.backend import ModelBackend


@pytest.fixture(autouse=True)
def isolated(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    monkeypatch.setenv('DEEPSEEK_API_KEY','SECRET-KEY')
    monkeypatch.setenv('OPENAI_API_KEY','OTHER-KEY')
    readiness.reset()
    yield
    readiness.reset()


def request(handshake=True,provider='deepseek'):
    return dict(provider=provider,model='deepseek-flash',messages=[{'role':'user','content':'SECRET PROMPT EVIDENCE'}],schema={'type':'object','description':'SECRET SCHEMA EVIDENCE'},timeout=15,handshake=handshake)


def sdk_response(text='{"status":"ok"}'):
    return SimpleNamespace(choices=[SimpleNamespace(finish_reason='stop',message=SimpleNamespace(content=text))])


def test_deepseek_handshake_only_selection():
    calls=[]
    def completion(**kw):
        calls.append(kw)
        if kw['response_format']['type']=='json_schema':
            error=type('BadRequestError',(Exception,),{'status_code':400,'body':{'error':{'code':'unsupported_parameter','param':'response_format'}}})('DO NOT LOG')
            raise error
        return sdk_response()
    sdk=SimpleNamespace(completion=completion)
    assert cloud_worker.generate(request(),sdk)['text']=='{"status":"ok"}'
    assert calls[0]['response_format']=={'type':'json_object'}
    assert calls[0]['model']=='deepseek/deepseek-flash'
    assert calls[0]['custom_llm_provider']=='deepseek'
    assert calls[0]['max_tokens']==64 and calls[0]['num_retries']==0 and calls[0]['drop_params'] is False
    with pytest.raises(pd.ProviderFailure) as failure:cloud_worker.generate(request(False),sdk)
    assert len(calls)==2  # No retry/fallback after the normal strict request fails.
    assert failure.value.category=='structured_output_unsupported'
    assert failure.value.metadata['rejected_parameter']=='response_format'
    assert failure.value.metadata['request_features']['structured_output']=='json_schema'
    assert calls[1]['response_format']['json_schema']['strict'] is True
    assert calls[1]['response_format']['json_schema']['schema']==request(False)['schema']
    assert calls[1]['max_tokens']==1024


def test_other_provider_handshake_keeps_strict_mode():
    kwargs=cloud_worker.request_kwargs(request(provider='openai'))
    assert kwargs['response_format']['type']=='json_schema'
    assert kwargs['response_format']['json_schema']['strict'] is True
    assert 'tools' not in kwargs and 'tool_choice' not in kwargs and 'temperature' not in kwargs
    assert 'api_base' not in kwargs and 'base_url' not in kwargs and 'extra_headers' not in kwargs


def test_features_values_and_raw_payloads_cannot_leak():
    kwargs=cloud_worker.request_kwargs(request(False))
    features=pd.request_features(kwargs)
    assert features==dict(structured_output='json_schema',json_schema=True,tools=False,tool_choice=False,streaming=False,timeout=True,temperature=False,custom_endpoint=False,extra_headers=False,max_token_parameter='max_tokens',provider_route='deepseek',provider_prefix='deepseek')
    pd.record('deepseek','deepseek-flash','provider_request','request_rejected',metadata={'request_features':{**features,'messages':'SECRET MESSAGE','schema':'SECRET SCHEMA','headers':'SECRET HEADERS'}})
    text=(settings.root()/'provider.log').read_text()
    assert 'SECRET' not in text and 'OTHER-KEY' not in text
    assert 'json_schema' in pd.render(text)
    assert 'Request features:' in pd.render(text)
    assert json.loads(text)['request_features']==features
    assert pd.safe_features({'structured_output':'SECRET','provider_route':'SECRET','max_token_parameter':'SECRET','tools':'SECRET'})=={}


@pytest.mark.parametrize('param',['response_format','response_format.type','json_schema','max_tokens','temperature'])
def test_rejected_parameter_allowlist(param):
    error=type('BadRequestError',(Exception,),{})('SECRET')
    error.status_code=400;error.body={'error':{'param':param,'code':'unsupported_parameter'}}
    assert pd.error_metadata(error)['rejected_parameter']==param
    assert pd.classify(error)==('structured_output_unsupported' if param.startswith('response_format') or param=='json_schema' else 'unsupported_parameter')
    error.body={'error':{'param':param}}
    assert pd.classify(error)=='request_rejected'  # A name alone does not prove unsupported mode.


@pytest.mark.parametrize('param',['SECRET KEY','EVTX:'+'a'*64+':Offset:1','response_format.SECRET','x'*1000,{},None])
def test_unknown_rejected_parameter_dropped(param):
    error=type('BadRequestError',(Exception,),{})('SECRET')
    error.status_code=400;error.param=param
    assert 'rejected_parameter' not in pd.error_metadata(error)
    assert pd.classify(error)=='request_rejected'


def test_readiness_success_does_not_claim_contract_compatibility(monkeypatch,capsys):
    config={**settings.defaults(),'provider':'deepseek','model':'deepseek-flash','cloud_acknowledged':True}
    seen=[]
    def cloud(self,messages,schema,**kw):
        seen.append((messages,schema,kw))
        return cloud_worker.generate(dict(provider='deepseek',model=self.model_name,messages=messages,schema=schema,timeout=15,handshake=kw['handshake']),SimpleNamespace(completion=lambda **args:sdk_response()))
    monkeypatch.setattr(ModelBackend,'_cloud',cloud)
    readiness.present(config,SimpleNamespace(no_color=True))
    result=readiness.status(config)
    assert result['connection_readiness']==result['model_readiness']=='ready'
    assert result['locard_compatibility']=='not_verified'
    assert len(seen)==1
    assert seen[0][0]==readiness.MESSAGES and 'SECRET' not in json.dumps(seen)
    output=capsys.readouterr().out
    assert 'Locard compatibility: not verified' in output and 'AI ready.' not in output


@pytest.mark.parametrize('text,category',[('LOCARD_OK','response_parse_failed'),('{"status":"ok","extra":1}','structured_validation_failed')])
def test_no_plaintext_or_schema_validation_downgrade(monkeypatch,text,category):
    config={**settings.defaults(),'provider':'deepseek','model':'deepseek-flash','cloud_acknowledged':True}
    monkeypatch.setattr(ModelBackend,'_cloud',lambda *a,**kw:{'text':text})
    result=readiness.check(config)
    assert result['readiness_category']==category
    assert result['connection_readiness']=='ready' and result['provider_readiness']=='unavailable'

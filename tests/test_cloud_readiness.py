"""Synthetic cloud readiness and diagnostics; no network/SDK requests."""
import json
from types import SimpleNamespace
import pytest
from forensic_assistant.ai import readiness, settings, cli, cloud_worker, diagnostics
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.ai.provider_diagnostics import ProviderFailure, classify, record, validation
from forensic_assistant.cli import build_parser


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path/'appdata'))
    for _, variable in settings.PROVIDERS.values():
        if variable:monkeypatch.delenv(variable,raising=False)
    readiness.reset()
    monkeypatch.setattr(ModelBackend,'_cloud',lambda *a,**k:pytest.fail('unexpected cloud request'))
    yield
    readiness.reset()


def config():
    return {**settings.defaults(),'provider':'deepseek','model':'synthetic-explicit-id','cloud_acknowledged':True}


def test_fixed_payload_cache_and_configuration_change(monkeypatch):
    monkeypatch.setenv('DEEPSEEK_API_KEY','test-secret')
    calls=[]
    def respond(self,messages,schema,**kwargs):
        calls.append((self.model_name,messages,schema,kwargs))
        return {'text':'{"status":"ok"}','usage':{}}
    monkeypatch.setattr(ModelBackend,'_cloud',respond)
    value=config()
    assert readiness.check(value)['provider_readiness']=='ready'
    assert readiness.check(value)['provider_readiness']=='ready'
    assert cli.status(value)['provider_readiness']=='ready'
    assert len(calls)==1
    assert calls[0][1]==[{'role':'user','content':'Return only this JSON object: {"status":"ok"}'}]
    assert calls[0][2]==readiness.SCHEMA
    assert calls[0][3]=={'timeout':15,'handshake':True}
    settings.save(value)
    args=build_parser().parse_args(['ai','configure','--model','another-explicit-id'])
    args._confirm=lambda prompt:'y'
    cli.dispatch(args)
    assert len(calls)==2 and calls[-1][0]=='another-explicit-id'
    assert settings.load()['model']=='another-explicit-id'
    readiness.reset()
    readiness.check(settings.load())
    assert len(calls)==3


def test_missing_key_and_local_never_call_cloud():
    assert readiness.check(settings.defaults())=={}
    result=readiness.check(config())
    assert result['provider_readiness']=='unavailable'
    assert result['readiness_stage']=='configuration'
    assert 'key is missing' in result['readiness_reason']


@pytest.mark.parametrize('name,code,expected',[
    ('AuthenticationError',401,'authentication_failed'),('PermissionDeniedError',403,'authorization_failed'),
    ('NotFoundError',404,'request_rejected'),('APIConnectionError',None,'network_error'),
    ('Timeout',None,'timeout'),('RateLimitError',429,'rate_limited'),
    ('UnsupportedParamsError',None,'unsupported_parameter'),('BadRequestError',400,'request_rejected'),
    ('UnexpectedError',500,'provider_server_error')])
def test_failure_categories_never_use_raw_exception(name,code,expected,monkeypatch):
    monkeypatch.setenv('DEEPSEEK_API_KEY','secret')
    error=type(name,(Exception,),{'status_code':code})('Authorization: secret EVIDENCE prompt response body')
    category=classify(error)
    assert category==expected
    def fail(*a,**kw):raise ProviderFailure(category,'timeout' if category=='timeout' else 'provider_request')
    monkeypatch.setattr(ModelBackend,'_cloud',fail)
    result=readiness.check(config())
    assert result['provider_readiness']=='unavailable'
    text=diagnostics.tail('provider.log')
    assert expected in text
    assert all(word not in text for word in ('secret','Authorization','EVIDENCE','response body'))


@pytest.mark.parametrize('text,stage',[
    ('not json','response_parse'),('{"status":"ok","status":"ok"}','response_parse'),
    ('{"status":"wrong"}','structured_validation'),('[]','structured_validation'),
    ('{"status":"ok","extra":true}','structured_validation')])
def test_response_parse_distinct_from_contract(monkeypatch,text,stage):
    monkeypatch.setenv('DEEPSEEK_API_KEY','secret')
    monkeypatch.setattr(ModelBackend,'_cloud',lambda *a,**k:{'text':text,'usage':{}})
    result=readiness.check(config())
    assert result['provider_readiness']=='unavailable' and result['readiness_stage']==stage
    assert '"operation": "handshake"' in diagnostics.tail('provider.log')


def test_handshake_sdk_low_budget_no_tools_no_retries(monkeypatch):
    monkeypatch.setenv('DEEPSEEK_API_KEY','secret')
    calls=[]
    def completion(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(finish_reason='stop',message=SimpleNamespace(content='{"status":"ok"}'))])
    request=dict(provider='deepseek',model='synthetic-explicit-id',messages=readiness.MESSAGES,schema=readiness.SCHEMA,timeout=15,handshake=True)
    assert cloud_worker.generate(request,SimpleNamespace(completion=completion))['text']=='{"status":"ok"}'
    assert calls[0]['max_tokens']==64 and calls[0]['num_retries']==0
    assert calls[0]['model']=='deepseek/synthetic-explicit-id'
    assert 'tools' not in calls[0] and 'fallbacks' not in calls[0]


def test_diagnostics_bound_and_validation_stages(monkeypatch):
    monkeypatch.setenv('DEEPSEEK_API_KEY','sensitive')
    settings.save(config())
    for _ in range(130):record('deepseek','sensitive','provider_request','authentication')
    client=SimpleNamespace(provider_name='deepseek',model_name='synthetic')
    for stage in ('response_parse','structured_validation','grounding'):validation(client,stage)
    path=settings.root()/'provider.log'
    assert path.stat().st_size<=32768
    result=cli.dispatch(build_parser().parse_args(['ai','logs']))['logs']
    assert 'sensitive' not in path.read_text()
    for stage in ('response_parse','structured_validation','grounding'):assert stage in result
    assert 'Authentication failed' in result
    assert not list(settings.root().glob('.log-*'))


@pytest.mark.parametrize('provider', ['local','deepseek'])
def test_shell_startup_nonblocking_and_once(tmp_path,monkeypatch,capsys,provider):
    from test_interactive_shell import Input, case
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from forensic_assistant.ai import runtime
    monkeypatch.setattr(runtime,'external',lambda config:None)
    calls=[]
    if provider=='deepseek':
        settings.save(config());monkeypatch.setenv('DEEPSEEK_API_KEY','secret')
        def fail(*a,**kw):calls.append(True);raise ProviderFailure('model_rejected')
        monkeypatch.setattr(ModelBackend,'_cloud',fail)
    assert Shell(State(None),Input(str(case(tmp_path)),'version','ai status','quit'),no_color=True).run()==0
    output=capsys.readouterr().out
    assert 'Database:' in output and 'Locard version' in output
    if provider=='deepseek':
        assert calls==[True]
        assert output.count('Checking AI provider...')==1
        assert 'AI provider unavailable' in output and 'Provider readiness: unavailable' in output, output
    else:assert not calls and 'Checking AI provider' not in output


def test_canonical_failure_label():
    from forensic_assistant.investigation_ai.presentation import LABELS
    assert LABELS['MODEL_FAILURE']=='AI model failure'



def test_worker_error_ipc_contains_category_only(monkeypatch,capsys):
    import io,sys,logging
    secret='never-print-key-or-evidence'
    class AuthenticationError(Exception):pass
    def completion(**kwargs):raise AuthenticationError('Authorization: '+secret+' prompt response body')
    monkeypatch.setenv('DEEPSEEK_API_KEY',secret)
    monkeypatch.setitem(sys.modules,'litellm',SimpleNamespace(completion=completion))
    request=dict(provider='deepseek',model='synthetic',messages=readiness.MESSAGES,schema=readiness.SCHEMA,timeout=15,handshake=True)
    monkeypatch.setattr(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(json.dumps(request).encode())))
    output,error=sys.stdout,sys.stderr
    disabled=logging.root.manager.disable
    try:cloud_worker.main()
    finally:
        sys.stdout,sys.stderr=output,error
        logging.disable(disabled)
    captured=capsys.readouterr()
    assert json.loads(captured.out)=={'error':'authentication_failed','stage':'provider_request','metadata':{'exception_class':'AuthenticationError','request_features':dict(structured_output='json_object',json_schema=False,tools=False,tool_choice=False,streaming=False,timeout=True,temperature=False,custom_endpoint=False,extra_headers=False,max_token_parameter='max_tokens',provider_route='deepseek',provider_prefix='deepseek')}}
    assert secret not in captured.out+captured.err


def test_diagnostic_redirection_is_rejected(tmp_path,monkeypatch):
    from forensic_assistant.investigation_ai import storage
    destination=tmp_path/'untouched';destination.write_text('original')
    real=diagnostics.local_path
    def reject(path):
        if path.name=='provider.log':raise ValueError('redirected')
        return real(path)
    monkeypatch.setattr(diagnostics,'local_path',reject)
    record('deepseek','synthetic','provider_request','authentication')
    assert destination.read_text()=='original'
    assert not (settings.root()/'provider.log').exists()


@pytest.mark.parametrize('result',[None,SimpleNamespace(choices=[]),SimpleNamespace(choices=[SimpleNamespace(message=None)])])
def test_malformed_success_is_structured_failure(monkeypatch,result):
    monkeypatch.setenv('DEEPSEEK_API_KEY','synthetic-secret')
    with pytest.raises(ProviderFailure) as exc:
        cloud_worker.generate(dict(provider='deepseek',model='synthetic',messages=readiness.MESSAGES,schema=readiness.SCHEMA,timeout=15,handshake=True),SimpleNamespace(completion=lambda **k:result))
    assert exc.value.category=='structured_validation_failed'

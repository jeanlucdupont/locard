"""Provider diagnostics contract; hostile synthetic payloads, no SDK/network use."""
import json
from types import SimpleNamespace
import pytest
from forensic_assistant.ai import provider_diagnostics as pd, settings, readiness, cli
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.cli import build_parser


@pytest.fixture(autouse=True)
def isolated(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    for _,variable in settings.PROVIDERS.values():
        if variable:monkeypatch.delenv(variable,raising=False)
    readiness.reset()
    yield
    readiness.reset()


def exception(status=None,code=None,kind=None,name='BadRequestError'):
    exc=type(name,(Exception,),{})('RAW EXCEPTION: Authorization secret prompt evidence transcript')
    exc.status_code=status
    exc.body={'error':{'code':code,'type':kind,'message':'FORBIDDEN BODY'}}
    return exc


@pytest.mark.parametrize('status,code,kind,expected',[
    (401,None,None,'authentication_failed'),(403,None,None,'authorization_failed'),
    (400,'model_not_found',None,'model_rejected'),(404,'invalid_model',None,'model_rejected'),
    (403,'model_access_denied',None,'model_rejected'),(404,None,None,'request_rejected'),
    (400,'invalid_api_key',None,'authentication_failed'),(429,None,None,'rate_limited'),
    (429,None,'invalid_request_error','rate_limited'),(429,'insufficient_quota',None,'quota_or_billing'),
    (402,'insufficient_balance',None,'quota_or_billing'),(500,None,None,'provider_server_error'),
    (503,None,None,'provider_server_error'),(418,None,None,'request_rejected'),
    (400,None,None,'request_rejected'),(400,'unsupported_parameter',None,'unsupported_parameter'),
    (400,'unsupported_response_format',None,'unsupported_schema'),
    (400,'invalid_json_schema',None,'unsupported_schema'),(400,None,'invalid_request_error','invalid_request')])
def test_status_and_structured_code_classification(status,code,kind,expected):
    exc=exception(status,code,kind)
    assert pd.classify(exc)==expected
    info=pd.error_metadata(exc)
    assert info['http_status']==status
    if code:assert info['provider_code']==code
    if kind:assert info['provider_type']==kind
    assert 'FORBIDDEN' not in json.dumps(info)


@pytest.mark.parametrize('status',[True,'401',-1,600,None])
def test_invalid_http_status_not_preserved(status):
    assert 'http_status' not in pd.error_metadata(exception(status))


def test_response_status_buffered_body_and_retry_after():
    exc=exception();exc.body=None
    exc.response=SimpleNamespace(status_code=400,content=b'{"error":{"code":"model_not_found","message":"PRIVATE EVIDENCE"}}',headers={'retry-after':'30','Authorization':'PRIVATE KEY'})
    assert pd.error_metadata(exc)==dict(http_status=400,exception_class='BadRequestError',provider_code='model_not_found',retry_after_present=True,retry_after_seconds=30)
    assert pd.classify(exc)=='model_rejected'
    for raw in ('Bearer secret','Wed, 21 Oct 2026 00:00:00 GMT','999999','-5'):
        exc.response.headers['retry-after']=raw
        info=pd.error_metadata(exc)
        assert info['retry_after_present'] and 'retry_after_seconds' not in info
    exc.response.content=b'x'*16385
    assert 'provider_code' not in pd.error_metadata(exc)


def test_unknown_code_type_and_exception_name_do_not_leak(monkeypatch):
    secret='private-key-value';monkeypatch.setenv('DEEPSEEK_API_KEY',secret)
    payloads=[secret,'Authorization: '+secret,'CASE EVIDENCE','EVTX:'+'a'*64+':Offset:1','source metadata','transcript data','prompt data','model response','{"status":"ok"}','x'*10000,'innocent_looking_but_unknown_code']
    for payload in payloads:
        exc=exception(400,payload,payload,name=payload)
        info=pd.error_metadata(exc)
        assert info=={'http_status':400}
        pd.record('deepseek','deepseek-v4-flash','provider_request',pd.classify(exc),metadata=info)
    text=(settings.root()/'provider.log').read_text()
    assert all(payload not in text for payload in payloads)
    assert 'RAW EXCEPTION' not in text and 'FORBIDDEN BODY' not in text
    # A credential that coincides with an allowlisted token still cannot be copied.
    monkeypatch.setenv('DEEPSEEK_API_KEY','model_not_found')
    assert 'provider_code' not in pd.error_metadata(exception(400,'model_not_found'))


def test_ipc_metadata_is_revalidated():
    error=pd.ProviderFailure('model_rejected',metadata={'http_status':400,'provider_code':'model_not_found','body':'SECRET','headers':{'Authorization':'SECRET'},'exception_class':'SECRET'})
    assert error.metadata=={'http_status':400,'provider_code':'model_not_found'}
    assert 'SECRET' not in str(error)


def test_handshake_single_event_and_status(monkeypatch,capsys):
    config={**settings.defaults(),'provider':'deepseek','model':'deepseek-v4-flash','cloud_acknowledged':True}
    monkeypatch.setenv('DEEPSEEK_API_KEY','synthetic-private-key')
    calls=[]
    def fail(self,*a,**kw):
        calls.append(kw)
        raise pd.ProviderFailure('model_rejected',metadata={'http_status':400,'provider_code':'model_not_found'})
    monkeypatch.setattr(ModelBackend,'_cloud_request',fail)
    readiness.present(config,SimpleNamespace(no_color=True))
    readiness.check(config)
    rows=[json.loads(line) for line in (settings.root()/'provider.log').read_text().splitlines()]
    assert len(rows)==len(calls)==1
    assert rows[0]['operation']=='handshake' and rows[0]['stage']=='provider_request'
    assert rows[0]['http_status']==400 and rows[0]['provider_code']=='model_not_found'
    output=capsys.readouterr().out
    assert 'Model: rejected' in output and 'AI provider unavailable' in output
    assert 'HTTP' not in output and 'model_not_found' not in output
    state=cli.status(config)
    assert state['provider_readiness']=='unavailable' and state['http_status']==400
    assert state['readiness_reason']==pd.REASONS['model_rejected']
    assert config['model']=='deepseek-v4-flash'
    # A separate normal request still gets its own diagnostic.
    with pytest.raises(pd.ProviderFailure):ModelBackend(config=config)._cloud([],{},handshake=False)
    rows=[json.loads(line) for line in (settings.root()/'provider.log').read_text().splitlines()]
    assert [row['operation'] for row in rows]==['handshake','request']


@pytest.mark.parametrize('category,label',[('authentication_failed','Authentication: failed'),('authorization_failed','Access: denied')])
def test_startup_specific_labels(monkeypatch,capsys,category,label):
    config={**settings.defaults(),'provider':'deepseek','model':'unchanged','cloud_acknowledged':True}
    monkeypatch.setenv('DEEPSEEK_API_KEY','synthetic-key')
    def fail(*a,**kw):raise pd.ProviderFailure(category)
    monkeypatch.setattr(ModelBackend,'_cloud',fail)
    readiness.present(config,SimpleNamespace(no_color=True))
    assert label in capsys.readouterr().out


def test_logs_human_and_json():
    settings.save({**settings.defaults(),'provider':'deepseek','model':'deepseek-v4-flash','cloud_acknowledged':True})
    pd.record('deepseek','deepseek-v4-flash','provider_request','model_rejected',operation='handshake',metadata={'http_status':400,'provider_code':'model_not_found'})
    human=cli.dispatch(build_parser().parse_args(['ai','logs']))['logs']
    assert 'HTTP status: 400' in human and 'Provider code: model_not_found' in human
    assert 'Operation: handshake' in human and 'Category: model_rejected' in human
    assert not human.startswith('{') and ' — DeepSeek' in human
    raw=cli.dispatch(build_parser().parse_args(['ai','logs','--json']))['logs']
    assert json.loads(raw)['http_status']==400
    assert json.loads((settings.root()/'provider.log').read_text())['provider_code']=='model_not_found'


def test_stopped_style_tty_and_machine(monkeypatch):
    from forensic_assistant import terminal
    monkeypatch.delenv('NO_COLOR',raising=False)
    monkeypatch.setattr(terminal,'capable',lambda stream:True)
    text=cli.render({'runtime':'stopped'},SimpleNamespace(json=False))
    assert '\x1b[2mstopped\x1b[0m' in text
    assert '\x1b[31m' not in text and '\x1b[33m' not in text
    assert '\x1b[' not in cli.render({'runtime':'stopped'},SimpleNamespace(json=True))
    monkeypatch.setattr(terminal,'capable',lambda stream:False)
    assert '\x1b[' not in cli.render({'runtime':'stopped'})


def test_worker_parent_metadata_round_trip(monkeypatch,capsys):
    import io,sys,logging,importlib.util
    from forensic_assistant.ai import cloud_worker,backend
    secret='synthetic-secret-never-forward'
    monkeypatch.setenv('DEEPSEEK_API_KEY',secret)
    exc=exception(400,'model_not_found','invalid_request_error')
    exc.response=SimpleNamespace(headers={'Retry-After':'8','Authorization':secret})
    def completion(**kw):raise exc
    monkeypatch.setitem(sys.modules,'litellm',SimpleNamespace(completion=completion))
    request=dict(provider='deepseek',model='deepseek-v4-flash',messages=readiness.MESSAGES,schema=readiness.SCHEMA,timeout=15,handshake=True)
    monkeypatch.setattr(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(json.dumps(request).encode())))
    output,error=sys.stdout,sys.stderr
    disabled=logging.root.manager.disable
    try:cloud_worker.main()
    finally:
        sys.stdout,sys.stderr=output,error
        logging.disable(disabled)
    raw=capsys.readouterr().out
    packet=json.loads(raw)
    assert packet['error']=='model_rejected'
    assert packet['metadata']==dict(http_status=400,provider_code='model_not_found',provider_type='invalid_request_error',exception_class='BadRequestError',retry_after_present=True,retry_after_seconds=8)
    assert secret not in raw and 'FORBIDDEN BODY' not in raw and 'RAW EXCEPTION' not in raw
    class Process:
        pid=12345;returncode=0
        def communicate(self,data,timeout):return raw.encode(),None
        def poll(self):return 0
        def wait(self,timeout):return 0
    monkeypatch.setattr(importlib.util,'find_spec',lambda *a:object())
    monkeypatch.setattr(backend.subprocess,'Popen',lambda *a,**kw:Process())
    monkeypatch.setattr(backend,'WorkerJob',lambda pid:SimpleNamespace(close=lambda:None))
    config={**settings.defaults(),'provider':'deepseek','model':'deepseek-v4-flash','cloud_acknowledged':True}
    result=readiness.check(config)
    assert result['readiness_category']=='model_rejected' and result['http_status']==400
    rows=(settings.root()/'provider.log').read_text().splitlines()
    assert len(rows)==1 and json.loads(rows[0])['provider_code']=='model_not_found'


def test_schema_failures_have_distinct_categories(monkeypatch):
    monkeypatch.setenv('DEEPSEEK_API_KEY','synthetic-key')
    config={**settings.defaults(),'provider':'deepseek','model':'unchanged','cloud_acknowledged':True}
    for response,category in [('not-json','response_parse_failed'),('{"status":"wrong"}','structured_validation_failed')]:
        monkeypatch.setattr(ModelBackend,'_cloud',lambda *a,**kw:{'text':response})
        result=readiness.check(config,force=True)
        assert result['readiness_category']==category
        assert 'http_status' not in result


def test_legacy_and_rotated_log_display():
    text='broken rotation fragment\n'+json.dumps(dict(utc='2026-10-19 01:36:39 UTC',provider='DeepSeek',model='unchanged',stage='provider_request',category='authentication',reason='RAW UNSAFE OLD REASON'))
    output=pd.render(text)
    assert 'Authentication failed' in output
    assert 'RAW UNSAFE OLD REASON' not in output and 'broken rotation' not in output

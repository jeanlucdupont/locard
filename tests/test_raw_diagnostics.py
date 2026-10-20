import json
from types import SimpleNamespace as NS
import pytest
from forensic_assistant.ai import raw_diagnostics as r, cloud_worker, readiness

@pytest.fixture(autouse=True)
def reset():
    r.clear()
    yield
    r.clear()


def test_optin_bounded_drain():
    r.capture({'kind':'raw_model_output','text':'not captured'})
    assert not r._entries and not r.enabled
    assert r.WARNING in r.display()
    for i in range(12):r.capture({'kind':'raw_model_output','text':str(i)+'x'*20000})
    assert len(r._entries)==10
    assert all(len(e['text'].encode())<=16384 for e in r._entries)
    text=r.display()
    assert text.index(r.WARNING)<text.index('NOT EVIDENCE')
    assert '[TRUNCATED]' in text and not r._entries
    r.clear()
    assert not r.enabled


def test_secrets(monkeypatch):
    monkeypatch.setenv('CUSTOM_SECRET','private-value')
    r.display()
    r.capture({'kind':'raw_provider_error','text':'case evidence private-value sk-ant-example\nAuthorization: Bearer password\nCookie: session=abc\nx-api-key: unknown'})
    text=r.display()
    for secret in ('private-value','sk-ant-example','password','session=abc','unknown'):assert secret not in text
    assert 'case evidence' in text

@pytest.mark.parametrize('enabled',[False,True])
def test_worker_capture_explicit(enabled,monkeypatch):
    monkeypatch.setenv('ANTHROPIC_API_KEY','synthetic-key')
    req=dict(provider='anthropic',model='synthetic',messages=[{'role':'user','content':'PRIVATE PROMPT'}],schema=readiness.SCHEMA,timeout=15,raw_diagnostics=enabled)
    sdk=NS(completion=lambda **kw:NS(choices=[NS(finish_reason='stop',message=NS(content='{"status":"ok"}'))]))
    result=cloud_worker.generate(req,sdk)
    assert ('raw_diagnostic' in result)==enabled
    assert 'PRIVATE PROMPT' not in json.dumps(result)


def test_raw_error_not_metadata(monkeypatch):
    monkeypatch.setenv('ANTHROPIC_API_KEY','synthetic-key')
    class Error(Exception):message='billing detail synthetic-key'
    def fail(**kw):raise Error()
    with pytest.raises(Exception) as e:cloud_worker.generate(dict(provider='anthropic',model='synthetic',messages=[],schema=readiness.SCHEMA,timeout=15,raw_diagnostics=True),NS(completion=fail))
    assert 'billing detail' in e.value.raw_diagnostic['text']
    assert 'synthetic-key' not in e.value.raw_diagnostic['text']
    assert 'billing detail' not in json.dumps(e.value.metadata)


def test_cli_raw_explicit_and_json_rejected(monkeypatch):
    from forensic_assistant.ai import cli, settings, diagnostics
    from forensic_assistant.cli import build_parser
    monkeypatch.setattr(settings,'load',lambda:{**settings.defaults(),'provider':'anthropic'})
    monkeypatch.setattr(diagnostics,'tail',lambda *a:'')
    parser=build_parser()
    cli.dispatch(parser.parse_args(['ai','logs']))
    assert not r.enabled
    value=cli.dispatch(parser.parse_args(['ai','logs','--raw']))
    assert r.WARNING in value['logs'] and r.enabled
    with pytest.raises(ValueError):cli.dispatch(parser.parse_args(['ai','logs','--raw','--json']))


def test_worker_relay_separate_from_evidence():
    entries=[]
    r.enabled=True
    r.sink=entries.append
    r.capture({'kind':'raw_model_output','text':'case evidence'})
    assert entries[0]['text']=='case evidence' and not r._entries
    r.clear()
    assert r.sink is None and not r.enabled

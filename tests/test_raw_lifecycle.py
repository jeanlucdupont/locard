import json
from types import SimpleNamespace as NS
import pytest
from forensic_assistant.ai import raw_diagnostics as raw, readiness, settings, cloud_worker
from forensic_assistant import cli

@pytest.fixture(autouse=True)
def clean():
    raw.clear()
    readiness.reset()
    yield
    raw.clear()
    readiness.reset()

@pytest.mark.parametrize('value,expected',[(None,False),('',False),('0',False),('invalid',False),(' true ',False),('1',True),('true',True),('yes',True),('on',True),('TRUE',True),('Yes',True),('ON',True)])
def test_environment_values(monkeypatch,value,expected):
    if value is None:monkeypatch.delenv('LOCARD_AI_RAW_DEBUG',raising=False)
    else:monkeypatch.setenv('LOCARD_AI_RAW_DEBUG',value)
    raw.initialize()
    assert raw.enabled is expected
    assert raw.source==('environment' if expected else 'disabled')


def test_entry_before_work_and_exit_cleanup(monkeypatch):
    from forensic_assistant.ai import runtime
    monkeypatch.setenv('LOCARD_AI_RAW_DEBUG','1')
    monkeypatch.setattr(runtime,'close',lambda:None)
    def work(argv):
        assert raw.enabled and raw.source=='environment'
        raw.capture({'kind':'raw_provider_error','text':'startup error'})
        text=raw.display()
        assert 'startup error' in text and 'Earlier startup' not in text
        assert 'capture enabled' not in text.lower()
        raise ValueError('synthetic')
    monkeypatch.setattr(cli,'_main',work)
    with pytest.raises(ValueError):cli.main([])
    assert not raw.enabled and not raw._entries and raw.source=='disabled'


def test_interactive_source(monkeypatch):
    monkeypatch.delenv('LOCARD_AI_RAW_DEBUG',raising=False)
    raw.initialize()
    text=raw.display()
    assert 'Earlier startup requests were not captured.' in text
    assert raw.source=='interactive'
    assert 'Earlier startup' not in raw.display()

@pytest.mark.parametrize('failure_index',[0,2])
def test_startup_stages_capture(monkeypatch,tmp_path,failure_index):
    from forensic_assistant.ai.backend import ModelBackend
    monkeypatch.setenv('LOCARD_AI_RAW_DEBUG','1')
    monkeypatch.setenv('ANTHROPIC_API_KEY','synthetic-key')
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    raw.initialize()
    expected=[{'status':'ok'}]+[p[2] for p in readiness.openai_probes()]
    calls=[]
    class Failure(Exception):message='synthetic startup rejection synthetic-key'
    def transport(self,messages,schema,**kw):
        index=len(calls);calls.append(index)
        def complete(**kwargs):
            if index==failure_index:raise Failure()
            return NS(choices=[NS(finish_reason='stop',message=NS(content=json.dumps(expected[index])))])
        request=dict(provider='anthropic',model='synthetic',messages=messages,schema=schema,timeout=15,handshake=True,raw_diagnostics=raw.enabled)
        try:result=cloud_worker.generate(request,NS(completion=complete))
        except Exception as exc:
            raw.capture(exc.raw_diagnostic)
            raise
        raw.capture(result.pop('raw_diagnostic'))
        return result
    monkeypatch.setattr(ModelBackend,'_cloud_request',transport)
    readiness.check({**settings.defaults(),'provider':'anthropic','model':'synthetic','cloud_acknowledged':True})
    assert len(calls)==failure_index+1
    text=raw.display()
    assert 'synthetic startup rejection' in text and 'synthetic-key' not in text
    if failure_index==2:assert 'Synthetic compatibility check.' in text
    for path in tmp_path.rglob('*'):
        if path.is_file():assert 'synthetic startup rejection' not in path.read_text(errors='replace')

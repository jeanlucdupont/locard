"""Synthetic clocks only: no cloud calls or sleeps."""
import json
import pytest
from forensic_assistant.ai import readiness, settings, diagnostics
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.ai.provider_diagnostics import ProviderFailure

@pytest.fixture(autouse=True)
def isolated(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    monkeypatch.setenv('OPENAI_API_KEY','SECRET')
    readiness.reset()
    yield
    readiness.reset()

def config():
    return {**settings.defaults(),'provider':'openai','model':'synthetic','cloud_acknowledged':True}

def mock(monkeypatch,durations,fail=None):
    clock=[0.0];calls=[];probes=list(readiness.openai_probes())
    monkeypatch.setattr(readiness.time,'monotonic',lambda:clock[0])
    def cloud(self,messages,schema,**kw):
        i=len(calls);calls.append(kw['timeout']);clock[0]+=durations[i]
        if fail and i==fail[0]:raise ProviderFailure(fail[1])
        return {'text':json.dumps({'status':'ok'} if i==0 else probes[i-1][2])}
    monkeypatch.setattr(ModelBackend,'_cloud',cloud)
    return calls

@pytest.mark.parametrize('seconds',[20,44])
def test_independent_startup_limits_and_cache(monkeypatch,seconds):
    calls=mock(monkeypatch,[1,seconds,seconds,seconds])
    result=readiness.check(config())
    assert calls==[15,45,45,45]
    assert result['locard_compatibility']=='ready'
    assert readiness.check(config()) is result
    assert len(calls)==4
    assert readiness.status({**config(),'model':'changed'})=={'provider_readiness':'unchecked'}

@pytest.mark.parametrize('index',[1,2,3])
def test_timeout_not_incompatible(monkeypatch,capsys,index):
    durations=[1]*4;durations[index]=46
    calls=mock(monkeypatch,durations)
    readiness.present(config())
    result=readiness.status(config())
    assert result['locard_compatibility']=='not confirmed'
    assert result['readiness_category']=='timeout'
    assert result['investigation_compatibility' if index>1 else 'advisory_compatibility']=='not confirmed'
    if index>1:assert result['advisory_compatibility']=='ready'
    text=capsys.readouterr().out
    assert 'not compatible' not in text and 'compatibility: failed' not in text
    assert 'Compatibility check timed out' in text
    raw=diagnostics.tail('provider.log')
    event=json.loads(raw)
    assert event['timeout_limit_seconds']==45
    assert event['elapsed_seconds']==46
    assert event['schema_profile']['schema_name'] in ('advisory','investigation_proposal')
    assert 'SECRET' not in raw and 'Synthetic compatibility check.' not in raw

@pytest.mark.parametrize('category',['invalid_request','structured_validation_failed'])
def test_true_failures_still_failed(monkeypatch,category):
    mock(monkeypatch,[1]*4,fail=(1,category))
    assert readiness.check(config())['locard_compatibility']=='failed'

def test_auth_unavailable(monkeypatch):
    mock(monkeypatch,[1]*4,fail=(0,'authentication_failed'))
    result=readiness.check(config())
    assert result['provider_readiness']=='unavailable'
    assert result['locard_compatibility']!='failed'

def test_lazy_request_keeps_existing_budget(monkeypatch):
    calls=mock(monkeypatch,[1,1,1,1])
    readiness.check(config(),timeout=15)
    assert calls==[15,14,13,12]

def test_timeout_gate_does_not_claim_incompatible(monkeypatch):
    mock(monkeypatch,[1,46,1,1])
    readiness.check(config())
    with pytest.raises(ProviderFailure) as caught:ModelBackend(config=config()).prepare()
    assert caught.value.category=='timeout'

def test_phase_updates_and_success_wording(monkeypatch,capsys):
    from forensic_assistant.terminal_activity import ActivityIndicator
    phases=[]
    monkeypatch.setattr(ActivityIndicator,'update',lambda self,text:phases.append(text))
    mock(monkeypatch,[1,20,20,20])
    readiness.present(config())
    output=capsys.readouterr().out
    assert 'Advisory compatibility: ready' in output
    assert 'Investigation compatibility: ready' in output
    assert 'Locard compatibility: ready' in output
    assert phases==['Checking AI provider...','Checking advisory compatibility...',
                    'Checking investigation compatibility...','Checking investigation compatibility...']

def test_cached_status_presentation(monkeypatch):
    from forensic_assistant.ai.cli import render
    from types import SimpleNamespace
    mock(monkeypatch,[1,1,46,1])
    readiness.check(config())
    rendered=render(readiness.status(config()),SimpleNamespace(no_color=True))
    assert 'Advisory compatibility: ready' in rendered
    assert 'Investigation compatibility: not confirmed' in rendered
    assert 'Locard compatibility: not confirmed' in rendered

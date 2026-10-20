"""Synthetic controller-to-worker readiness handoff and clock regressions."""
import json
import pytest
from forensic_assistant.ai import readiness, settings
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from test_readiness_timeouts import mock, config, isolated


def test_worker_reuses_parent_decision_for_continuations(monkeypatch):
    calls=mock(monkeypatch,[1,20,20,20])
    parent=ModelBackend(config=config())
    parent.prepare()
    descriptor=parent.descriptor()
    assert 'SECRET' not in json.dumps(descriptor)
    readiness.reset()  # A spawned process starts with an empty module cache.
    worker=ModelBackend.restore(json.loads(json.dumps(descriptor)))
    monkeypatch.setattr(readiness,'check',lambda *a,**k:pytest.fail('worker probed'))
    actual=[]
    def cloud(self,messages,schema,**kw):
        actual.append(kw)
        return {'text':'{"status":"ok"}','usage':{}}
    monkeypatch.setattr(ModelBackend,'_cloud',cloud)
    for _ in range(3):assert worker.complete([],readiness.SCHEMA)=='{"status":"ok"}'
    assert len(actual)==3 and len(calls)==4
    assert all(c['timeout']==120 for c in actual)


@pytest.mark.parametrize('change',['model','provider','revision','missing'])
def test_worker_rejects_stale_decision_without_probe(monkeypatch,change):
    mock(monkeypatch,[1]*4)
    parent=ModelBackend(config=config());parent.prepare();value=parent.descriptor()
    if change=='model':value['config']={**value['config'],'model':'different'}
    elif change=='provider':
        value['config']={**value['config'],'provider':'deepseek'};value['provider']='deepseek'
        monkeypatch.setenv('DEEPSEEK_API_KEY','SECRET')
    elif change=='revision':monkeypatch.setattr(readiness,'COMPATIBILITY_REVISION',999)
    else:value.pop('compatibility')
    worker=ModelBackend.restore(value)
    monkeypatch.setattr(readiness,'check',lambda *a,**k:pytest.fail('worker probed'))
    with pytest.raises(ProviderFailure):worker.prepare()


def test_direct_request_certification_has_dedicated_clock(monkeypatch):
    calls=mock(monkeypatch,[1,44,44,44])
    parent=ModelBackend(config=config(),timeout=2)
    parent.prepare()
    assert calls==[15,45,45,45]
    monkeypatch.setattr(parent,'_cloud',lambda *a,**kw:{'text':'ok','usage':{}} if kw['timeout']==2 else pytest.fail('spent request clock'))
    assert parent.complete([],readiness.SCHEMA)=='ok'
    assert readiness.status(config())['locard_compatibility']=='ready'


def test_cloud_certification_precedes_supervisor_clock(monkeypatch,tmp_path):
    from forensic_assistant.investigation_ai import supervision
    from types import SimpleNamespace
    calls=mock(monkeypatch,[1,44,44,44]);captured=[]
    class Stop(Exception):pass
    def pipe():raise Stop()
    monkeypatch.setattr(supervision.multiprocessing,'get_context',lambda *a:SimpleNamespace(Pipe=pipe))
    monkeypatch.setattr(supervision,'ExecutionClock',lambda started,deadline:captured.append((started,deadline)))
    with pytest.raises(Stop):supervision.run({},'synthetic',tmp_path,client=ModelBackend(config=config()))
    assert calls==[15,45,45,45]
    assert captured==[(133,433)]


def test_real_timeout_preserves_ready_cache(monkeypatch):
    real=ModelBackend._cloud
    mock(monkeypatch,[1]*4)
    client=ModelBackend(config=config());client.prepare()
    monkeypatch.setattr(ModelBackend,'_cloud',real)
    def fail(*a,**k):raise ProviderFailure('timeout','timeout')
    monkeypatch.setattr(client,'_cloud_request',fail)
    with pytest.raises(ProviderFailure):client.complete([],readiness.SCHEMA)
    assert readiness.status(config())['locard_compatibility']=='ready'

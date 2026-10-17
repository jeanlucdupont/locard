"""Completion hashes use the global deadline; ordinary tools retain their cap."""
import time
import pytest
from forensic_assistant.investigation_ai import controller
from forensic_assistant.investigation_ai.state import Budget
from forensic_assistant.investigation_ai.runner import WorkerError
from test_investigation_assessment import RecordingWorker, EID
from test_v4_controller import Scripted, final, tool

@pytest.mark.parametrize('dry_run',[True,False])
def test_final_check_uses_remaining_global_budget(tmp_path,dry_run):
    seen=[]
    class Measured(RecordingWorker):
        def call(self,name,*a,**kw):
            seen.append((name,kw['seconds']))
            if name=='check':
                assert kw['seconds'] > 45  # Would formerly fail even with 200s available.
            return super().call(name,*a,**kw)
    actions=[tool('show_evidence',{'evidence_id':EID}),final]
    controller.run({},'Inspect',tmp_path,budget=Budget(seconds=200),dry_run=dry_run,
                   client=Scripted(actions),worker_factory=Measured)
    assert any(name=='check' for name,_ in seen)
    assert all(45 < seconds <= 200 for name,seconds in seen if name in ('initial','check'))
    assert all(seconds<=45 for name,seconds in seen if name not in ('initial','check'))


def test_final_check_never_exceeds_global_remaining(tmp_path):
    seen=[]
    class Measured(RecordingWorker):
        def call(self,name,*a,**kw):
            seen.append((name,kw['seconds']))
            return super().call(name,*a,**kw)
    controller.run({'_deadline':time.monotonic()+10},'Inspect',tmp_path,
                   client=Scripted([final]),worker_factory=Measured)
    assert any(name=='check' for name,_ in seen)
    assert all(0 < seconds <= 10 for _,seconds in seen)


def test_expired_global_deadline_never_starts_worker(tmp_path):
    result=controller.run({'_deadline':time.monotonic()-1},'Inspect',tmp_path,
        client=Scripted([]),worker_factory=lambda _:pytest.fail('worker started'))
    assert result['termination']=='STARTUP_TIMEOUT'

from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import time
import pytest
from forensic_assistant.investigation_ai.controller import run
from forensic_assistant.investigation_ai.runner import ForensicWorker, WorkerError
from forensic_assistant.investigation_ai.state import Budget, State
from forensic_assistant.investigation_ai.transcript import Transcript
from forensic_assistant.llm.client import LLMError
from test_v4_worker import make_case, config
from test_v4_controller import Scripted, final, tool

@pytest.mark.parametrize('wal',[True,False])
def test_two_workers_release_locks_between_operations(tmp_path,wal):
    path=tmp_path/'case.db';make_case(path,wal=wal)
    with ForensicWorker(config(path)) as one, ForensicWorker(config(path)) as two:
        with ThreadPoolExecutor(2) as pool:
            results=list(pool.map(lambda w:w.call('check'),[one,two]))
        assert results[0]['fingerprint']==results[1]['fingerprint']
        writer=sqlite3.connect(path,timeout=.2)
        writer.execute("UPDATE events SET command_line='writer proceeds'");writer.commit()
        if wal:assert writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()==(0,0,0)
        writer.close()
        for worker in (one,two):
            with pytest.raises(WorkerError,match='EVIDENCE_STATE_CHANGED'):
                worker.call('check',fingerprint=results[0]['fingerprint'])

def test_deadline_during_large_fingerprint_releases_locks(tmp_path):
    path=tmp_path/'case.db';make_case(path)
    writer=sqlite3.connect(path)
    writer.execute('CREATE TABLE synthetic_pressure(value BLOB)')
    writer.executemany('INSERT INTO synthetic_pressure VALUES (?)',[(bytes(1024*1024),)]*32)
    writer.commit()
    with ForensicWorker(config(path)) as worker:
        with pytest.raises(WorkerError):worker.call('check',seconds=.02)
    writer.execute('INSERT INTO synthetic_pressure VALUES (?)',(b'after timeout',));writer.commit()
    assert writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()==(0,0,0)
    writer.close()

def test_wal_pressure_watchdog_kills_worker(tmp_path,monkeypatch):
    path=tmp_path/'case.db';make_case(path)
    with ForensicWorker(config(path)) as worker:
        sizes=iter([0,65*1024*1024])
        monkeypatch.setattr(worker,'_wal_size',lambda:next(sizes))
        with pytest.raises(WorkerError,match='WAL_PRESSURE'):worker.call('check')
        assert worker.process.poll() is not None

def test_concurrent_investigations_are_isolated(tmp_path):
    path=tmp_path/'case.db';make_case(path)
    def investigate(_):return run(config(path),'PowerShell',tmp_path/'runs',client=Scripted([final]))
    with ThreadPoolExecutor(2) as pool:results=list(pool.map(investigate,range(2)))
    assert results[0]['investigation_id']!=results[1]['investigation_id']
    assert all(r['termination']=='ANSWER_SUPPORTED' for r in results)

def test_steps_calls_model_failure_and_approval(tmp_path):
    path=tmp_path/'case.db';event=make_case(path)
    call=tool('show_evidence',{'evidence_id':event['id']})
    result=run(config(path),'PowerShell',tmp_path/'runs',budget=Budget(steps=1),client=Scripted([call]))
    assert result['termination']=='BUDGET_EXHAUSTED'
    result=run(config(path),'PowerShell',tmp_path/'runs',budget=Budget(calls=1),client=Scripted([call,tool('process_tree',{'evidence_id':event['id']})]))
    assert result['termination']=='BUDGET_EXHAUSTED' and result['state']['accepted_calls']==1
    result=run(config(path),'PowerShell',tmp_path/'runs',client=Scripted([call]),approval=lambda p,t:False)
    assert result['termination']=='USER_SCOPE_REACHED' and result['state']['accepted_calls']==0
    class Failed:
        def complete(self,*args):raise LLMError('unavailable')
    result=run(config(path),'PowerShell',tmp_path/'runs',client=Failed())
    assert result['termination']=='MODEL_FAILURE' and result['findings']['observed']

def test_transcript_growth_fails_before_terminal_reserve(tmp_path):
    transcript=Transcript(tmp_path,{})
    with pytest.raises(ValueError,match='TRANSCRIPT_BUDGET'):
        for _ in range(10):transcript.append('synthetic',{'value':'x'*(500*1024)})
    transcript.finish({'termination':'BUDGET_EXHAUSTED'})
    assert transcript.size<4*1024*1024

def test_transient_windows_manifest_sharing_failure_retries_atomically(tmp_path,monkeypatch):
    import forensic_assistant.investigation_ai.transcript as module
    original=module.os.replace;attempts=[]
    def transient(source,destination):
        attempts.append(1)
        if len(attempts)<3:raise PermissionError('Synthetic sharing violation')
        original(source,destination)
    monkeypatch.setattr(module.os,'replace',transient)
    transcript=module.Transcript(tmp_path,{})
    assert len(attempts)==3
    transcript.finish({'termination':'USER_SCOPE_REACHED'})
    manifest,_=module.load(tmp_path,transcript.id)
    assert manifest['status']=='USER_SCOPE_REACHED'

def test_omitted_context_cannot_be_cited_and_retention_is_bounded():
    state=State(Budget(records=2))
    records=[{'id':'EVTX:'+'a'*64+':Offset:'+str(i),'command_line':'x'*3000} for i in range(3)]
    state.ingest({'records':records,'relationships':[],'detections':[]})
    assert len(state.records)==2
    _,data,size=state.prompt('Inspect',[],[]);state.disclose(data)
    assert size<=5600 and len(state.exposed)==1
    absent=next(eid for eid in state.records if eid not in state.exposed)
    with pytest.raises(ValueError,match='unexposed'):
        state.render(dict(observed=[dict(evidence_id=absent,field='/command_line')],relationships=[],detections=[],hypotheses=[],unknowns=[]))

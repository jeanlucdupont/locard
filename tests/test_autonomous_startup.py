"""No provider requests: real supervised processes with synthetic blocked phases."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from dataclasses import asdict

import pytest

from forensic_assistant.investigation_ai import autonomous, supervision
from forensic_assistant.investigation_ai.state import Budget
from forensic_assistant.llm.client import LocalClient
from test_autonomous_stage_a import grant
from test_v4_worker import make_case
from test_compact_disclosure import records, envelope


def blocked_phase_child(connection,gate,request):
    """Exercise the real child entrypoint; substitute only the blocking dependency."""
    from forensic_assistant.investigation_ai import controller
    from forensic_assistant import assessment_handoff
    phase=request['config']['_test_phase']
    row=records()[0];row['source_context']={'source_ids':['source-test']}
    def block():
        time.sleep(30)
    class Client:
        provider_name='openai';model_name='synthetic'
        def complete(self,*args):
            assert phase=='model'
            block()
    if phase=='provider_init':supervision.LocalClient=lambda *a: block()
    else:supervision.LocalClient=lambda *a: Client()
    if phase=='handoff_validation':assessment_handoff.validate=lambda *a: block()
    if phase=='transcript_init':
        class BadJournal:
            def __init__(self,*a,**kw):raise PermissionError('synthetic journal failure')
        autonomous.Transcript=BadJournal
    class Worker:
        def __init__(self,config):
            if phase=='worker_start':
                child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                Path(config['_test_pid']).write_text(str(child.pid))
                block()
        def call(self,name,*a,**kw):
            if (phase=='read_transaction' and name=='initial') or (phase=='operation' and name=='show_evidence'):
                block()
            return dict(result=envelope([] if name in ('initial','check') else [row]),
                evidence_state={'contract':'sqlite-read-view-v1','view_id':'a'*32,'file_identity':{'device':1,'inode':1}},
                fingerprint=None,database_changes=0,schema=5)
        def close(self):pass
    controller.run=lambda c,q,r,**kw:autonomous.run(c,q,r,**{**kw,'budget':Budget(),'worker_factory':Worker})
    supervision._child(connection,gate,request)


def configured(tmp_path,phase):
    path=tmp_path/'case.db';make_case(path)
    g=grant(path,records()[:1])
    c=dict(case_path=str(path),_stage_a=g,_test_phase=phase,_test_pid=str(tmp_path/'child.pid'))
    if phase=='handoff_validation':c['_stage_a_handoff']={'synthetic':True}
    return c


def alive(pid):
    if os.name=='nt':
        import ctypes
        from ctypes import wintypes
        dll=ctypes.WinDLL('kernel32',use_last_error=True)
        dll.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
        dll.OpenProcess.restype=wintypes.HANDLE
        dll.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
        dll.CloseHandle.argtypes=[wintypes.HANDLE]
        h=dll.OpenProcess(0x100000,False,pid)
        if not h:return False
        try:return dll.WaitForSingleObject(h,0)==258
        finally:dll.CloseHandle(h)
    try:os.kill(pid,0);return True
    except ProcessLookupError:return False


@pytest.mark.parametrize('phase',['handoff_validation','provider_init','worker_start','read_transaction','operation','model'])
def test_startup_and_operation_hangs_are_contained(tmp_path,monkeypatch,phase):
    config=configured(tmp_path,phase);before=Path(config['case_path']).read_bytes()
    monkeypatch.setattr(supervision,'_child',blocked_phase_child)
    phases=[];start=time.monotonic()
    result=supervision.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=LocalClient(),
                           budget=Budget(seconds=3),status=phases.append)
    assert time.monotonic()-start<3+supervision.CLEANUP_SECONDS+2
    assert phase in phases
    assert result['startup_diagnostic']['last_phase']==phase
    assert result['startup_diagnostic']['cleanup_confirmed']
    established=phase in ('operation','model')
    assert result['startup_diagnostic']['read_view_established']==established
    assert result['termination']==('MAX_SECONDS' if established else 'STARTUP_TIMEOUT')
    assert not result['findings']
    assert Path(config['case_path']).read_bytes()==before
    if phase=='worker_start':
        assert not alive(int(Path(config['_test_pid']).read_text()))


def test_journal_creation_failure_is_actionable(tmp_path,monkeypatch):
    config=configured(tmp_path,'transcript_init')
    monkeypatch.setattr(supervision,'_child',blocked_phase_child)
    result=supervision.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=LocalClient(),budget=Budget(seconds=3))
    assert result['termination']=='TRANSCRIPT_FAILURE'
    assert result['startup_diagnostic']['last_phase']=='transcript_init'
    assert not result['startup_diagnostic']['read_view_established']
    assert result['startup_diagnostic']['cleanup_confirmed']


def test_cancellation_during_preparation_cleans_descendants(tmp_path,monkeypatch):
    config=configured(tmp_path,'worker_start')
    monkeypatch.setattr(supervision,'_child',blocked_phase_child)
    def cancel(phase):
        if phase=='worker_start':
            # Let the synthetic constructor create its descendant, then interrupt.
            end=time.monotonic()+1
            while not Path(config['_test_pid']).exists() and time.monotonic()<end:time.sleep(.01)
            raise KeyboardInterrupt()
    result=supervision.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=LocalClient(),budget=Budget(seconds=4),status=cancel)
    assert result['termination']=='ANALYST_CANCELLED'
    assert result['startup_diagnostic']['cleanup_confirmed']
    assert not alive(int(Path(config['_test_pid']).read_text()))


def test_grant_expired_before_worker_never_retrieves(tmp_path):
    config=configured(tmp_path,'unused');config['_stage_a']['issued']-=301;config['_stage_a']['expires']-=301
    with pytest.raises(ValueError,match='AUTHORIZATION_EXPIRED'):
        autonomous.run(config,config['_stage_a']['objective'],tmp_path/'runs',
                       worker_factory=lambda _:pytest.fail('worker started'))
    assert not (tmp_path/'runs').exists()


def test_expired_grant_reports_safe_reason_through_supervisor(tmp_path,monkeypatch):
    config=configured(tmp_path,'unused')
    config['_stage_a']['issued']-=301;config['_stage_a']['expires']-=301
    monkeypatch.setattr(supervision,'_child',blocked_phase_child)
    result=supervision.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=LocalClient(),budget=Budget(seconds=3))
    assert result['termination']=='AUTHORIZATION_EXPIRED'
    assert result['startup_diagnostic']['last_phase']=='authorization_validation'
    assert not result['startup_diagnostic']['read_view_established'] and not result['findings']
    from forensic_assistant.investigation_ai.presentation import render
    assert 'Last phase: authorization_validation' in render(result)


def test_launch_wait_is_bounded_and_late_child_gate_expires():
    release=threading.Event()
    class Process:
        def start(self):release.wait(2)
    launch=supervision.Launch(Process());launch.thread.start()
    try:
        with pytest.raises(TimeoutError):launch.wait(time.monotonic()+.02)
    finally:release.set();launch.thread.join(1)
    assert launch.done.is_set()
    class Connection:
        def send_bytes(self,*a):pytest.fail('late child ran')
    # Expired, unopened gate must return before audit, journal or provider setup.
    supervision._child(Connection(),threading.Event(),{'config':{'_stage_a':True,'_deadline':time.monotonic()-1}})
    gate=threading.Event();gate.set()
    cancelled=threading.Event();cancelled.set()
    supervision._child(Connection(),gate,{'_startup_cancelled':cancelled,
        'config':{'_stage_a':True,'_deadline':time.monotonic()+300}})


def test_approval_clock_starts_before_revalidation(tmp_path,monkeypatch):
    from forensic_assistant import assessment_handoff
    from forensic_assistant.ai import readiness
    from test_autonomous_stage_a import setup
    config,worker,client,_,_=setup(tmp_path)
    client.config={'cloud_acknowledged':True}
    monkeypatch.setattr(readiness,'status',lambda _: {'investigation_compatibility':'ready'})
    monkeypatch.setattr(assessment_handoff,'validate',lambda *a:pytest.fail('unsupervised validation'))
    handoff={'case':{'path':config['case_path']},'question':'Inspect','assessment_id':'a','assessment_digest':'b',
        'hints':[{'id':eid} for eid in config['_stage_a']['evidence_ids']],
        'scope':{'start':config['_stage_a']['start'],'end':config['_stage_a']['end']}}
    assessment={'records':{eid:{'source_context':{'source_ids':['source-test']}} for eid in config['_stage_a']['evidence_ids']}}
    def supervised(c,*a,**kw):
        assert c['_stage_a_deadline']-c['_stage_a_started']==300
        assert c['_stage_a_started']<=time.monotonic()
        assert c['_stage_a_handoff']['authorization']
        return 'supervised'
    monkeypatch.setattr(supervision,'run',supervised)
    assert autonomous.start(handoff,assessment,client,lambda _:True)=='supervised'


def test_unknown_launch_cleanup_cannot_return_to_prompt(tmp_path,monkeypatch):
    from forensic_assistant.investigation_ai.lifecycle import CleanupError
    from types import SimpleNamespace
    config=configured(tmp_path,'unused')
    class StuckLaunch:
        def __init__(self,process):
            self.done=threading.Event();self.thread=SimpleNamespace(start=lambda:None)
        def wait(self,deadline):raise TimeoutError('synthetic startup timeout')
    monkeypatch.setattr(supervision,'Launch',StuckLaunch)
    monkeypatch.setattr(supervision,'CLEANUP_SECONDS',.02)
    with pytest.raises(CleanupError) as failure:
        supervision.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=LocalClient(),budget=Budget(seconds=1))
    assert failure.value.result['startup_diagnostic']['cleanup_confirmed'] is False
    assert failure.value.result['termination']=='STARTUP_TIMEOUT'


def test_real_worker_ipc_silence_times_out_and_cleans(tmp_path,monkeypatch):
    from forensic_assistant.investigation_ai.runner import ForensicWorker,WorkerError
    path=tmp_path/'case.db';make_case(path)
    script=tmp_path/'silent_worker.py'
    script.write_text('import json,sys,time,os\n'
                      'sys.stdin.readline()\n'
                      'print(json.dumps({"ready":True,"worker_pid":os.getpid()}),flush=True)\n'
                      'sys.stdin.readline()\ntime.sleep(30)\n',encoding='utf-8')
    monkeypatch.setattr(ForensicWorker,'worker_script',script)
    with ForensicWorker({'case_path':str(path),'semantic_enabled':False}) as worker:
        pid=worker.worker_pid
        with pytest.raises(WorkerError,match='TOOL_TIMEOUT'):
            worker.call('initial',question='Synthetic',seconds=.1)
    # Job active-count reaches zero just before Windows signals the process object.
    # Bound that kernel-exit observation; a still-running process must fail.
    deadline=time.monotonic()+1
    while alive(pid) and time.monotonic()<deadline:time.sleep(.01)
    assert not alive(pid)

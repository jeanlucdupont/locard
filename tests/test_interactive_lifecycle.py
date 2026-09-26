from contextlib import closing
import io
import json
import os
from pathlib import Path
import sys
import threading
import time
import pytest
from forensic_assistant.database.db import connect
from forensic_assistant.ingest.evtx import ingest_file, ParsedRecord
from forensic_assistant.artifacts.ingest import ingest_artifact
from test_ingest import xml
from v2_fixtures import mft_file


@pytest.mark.skipif(sys.platform!='win32',reason='Windows console gate')
def test_approval_timeout_and_cancel_have_no_surviving_reader(monkeypatch):
    from contextlib import nullcontext
    from forensic_assistant.interactive.console import timed_line
    from forensic_assistant.investigation_ai.cli import approve
    class Terminal:
        def isatty(self):return True
        def readline(self):raise AssertionError('Blocking reader used')
    monkeypatch.setattr(sys,'stdin',Terminal())
    monkeypatch.setattr('forensic_assistant.interactive.console.windows_input',nullcontext)
    keys=list('partial')
    class Keys:
        def poll(self):return keys.pop(0) if keys else None
        def flush(self):keys.clear()
    monkeypatch.setattr('forensic_assistant.interactive.console.WindowsKeys',Keys)
    before={t.ident for t in threading.enumerate()}
    assert approve({},.03) is False
    keys.extend('status\r')
    assert timed_line('',1)=='status'
    keys.extend('\x03')
    with pytest.raises(KeyboardInterrupt):approve({},1)
    keys.extend('exit\r')
    assert timed_line('',1)=='exit'
    keys.extend('\u00e0\ud83d\udd0e\r')
    assert timed_line('',1)=='\u00e0\U0001f50e'
    assert {t.ident for t in threading.enumerate()}==before


@pytest.mark.parametrize('wal',[False,True])
def test_interrupted_evtx_keeps_earlier_completed_files(tmp_path,wal):
    path=tmp_path/'case.db';source=tmp_path/'synthetic.evtx';source.write_bytes(b'synthetic')
    with closing(connect(path)) as db:
        if wal:db.execute('PRAGMA journal_mode=WAL')
        ingest_file(db,source,reader=lambda p:iter([ParsedRecord(512,xml=xml())]))
        def cancel(p):
            yield ParsedRecord(1024,xml=xml())
            raise KeyboardInterrupt
        with pytest.raises(KeyboardInterrupt):ingest_file(db,source,reader=cancel,batch_size=1)
        runs=list(db.execute('SELECT status,inserted_count,finished_utc FROM ingestion_runs ORDER BY id'))
        assert runs[0]['status']=='complete' and runs[0]['inserted_count']==1
        assert runs[1]['status']=='interrupted' and runs[1]['inserted_count']==0 and runs[1]['finished_utc']
        assert db.execute('SELECT count(*) FROM events').fetchone()[0]==1
        assert not db.in_transaction
        if wal:assert db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]==0


@pytest.mark.parametrize('artifact',[False,True])
def test_interrupt_after_publication_records_committed_counts(tmp_path,monkeypatch,artifact):
    import tempfile
    original=tempfile.TemporaryDirectory
    class InterruptAfterCleanup:
        def __init__(self,*args,**kwargs):self.context=original(*args,**kwargs)
        def __enter__(self):return self.context.__enter__()
        def __exit__(self,*exc):
            result=self.context.__exit__(*exc)
            if exc[0] is None:raise KeyboardInterrupt
            return result
    monkeypatch.setattr(tempfile,'TemporaryDirectory',InterruptAfterCleanup)
    with closing(connect(tmp_path/'case.db')) as db:
        with pytest.raises(KeyboardInterrupt):
            if artifact:ingest_artifact(db,mft_file(tmp_path/'mft'),'mft')
            else:
                source=tmp_path/'synthetic.evtx';source.write_bytes(b'synthetic')
                ingest_file(db,source,reader=lambda p:iter([ParsedRecord(512,xml=xml())]))
        row=db.execute('SELECT * FROM ingestion_runs').fetchone()
        assert row['status']=='interrupted' and row['inserted_count']>0 and row['file_sha256']
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]==row['inserted_count']
        assert not db.in_transaction
        assert {r[1] for r in db.execute('PRAGMA database_list')} <= {'main','temp'}


def test_artifact_cancel_before_publication(tmp_path):
    def cancel(*args):raise KeyboardInterrupt
    with closing(connect(tmp_path/'case.db')) as db:
        with pytest.raises(KeyboardInterrupt):ingest_artifact(db,mft_file(tmp_path/'mft'),'mft',runner=cancel)
        row=db.execute('SELECT * FROM ingestion_runs').fetchone()
        assert row['status']=='interrupted' and row['inserted_count']==0 and row['finished_utc']
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]==0


def process_handle(pid):
    import ctypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.restype=ctypes.c_void_p
    kernel.OpenProcess.argtypes=[ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong]
    kernel.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_ulong]
    kernel.CloseHandle.argtypes=[ctypes.c_void_p]
    handle=kernel.OpenProcess(0x100000|0x1000,False,pid)
    assert handle
    return kernel,handle


@pytest.mark.skipif(sys.platform!='win32',reason='Windows process containment gate')
@pytest.mark.parametrize('termination',['interrupt','timeout'])
def test_real_parser_and_descendant_terminated(tmp_path,monkeypatch,termination):
    import forensic_assistant.artifacts.ingest as module
    script=tmp_path/'synthetic_worker.py'
    script.write_text('''import os,sys,json,subprocess,time
from pathlib import Path
stage=Path(sys.argv[1])
Path(str(stage)+'.ready').write_text(json.dumps({'worker_pid':os.getpid()}))
if sys.stdin.buffer.readline(16)!=b'go\\n':sys.exit(2)
child_code="import os,time; from pathlib import Path; Path("+repr(str(stage)+'.child')+").write_text(str(os.getpid())); time.sleep(60)"
child=subprocess.Popen([sys.executable,'-c',child_code])
while not Path(str(stage)+'.child').exists():time.sleep(.01)
Path(str(stage)+'.pids').write_text(json.dumps([os.getpid(),int(Path(str(stage)+'.child').read_text())]))
time.sleep(60)
''')
    stage=tmp_path/'stage.db';original_popen=module.subprocess.Popen
    def launch(args,**kwargs):return original_popen([sys.executable,str(script),str(stage)],**kwargs)
    monkeypatch.setattr(module.subprocess,'Popen',launch)
    original_sleep=time.sleep;handles=[]
    def poll(seconds):
        pids=Path(str(stage)+'.pids')
        if pids.exists() and not handles:
            try:ids=json.loads(pids.read_text())
            except json.JSONDecodeError:return original_sleep(.02)
            handles.extend(process_handle(pid) for pid in ids)
            if termination=='interrupt':raise KeyboardInterrupt
        original_sleep(.02)
    monkeypatch.setattr(module.time,'sleep',poll)
    try:
        with pytest.raises(KeyboardInterrupt if termination=='interrupt' else ValueError):
            module.worker('mft','unused','a'*64,stage,{},2)
        assert len(handles)==2
        for kernel,handle in handles:assert kernel.WaitForSingleObject(handle,5000)==0
    finally:
        for kernel,handle in handles:kernel.CloseHandle(handle)


def test_cleanup_failure_is_fatal_to_shell(tmp_path,monkeypatch):
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from forensic_assistant.investigation_ai.lifecycle import CleanupError
    from test_interactive_shell import Input
    path=tmp_path/'case.db';connect(path).close()
    def fail(*args,**kwargs):raise CleanupError('Cannot confirm cleanup')
    monkeypatch.setattr('forensic_assistant.cli.dispatch',fail)
    with pytest.raises(CleanupError):Shell(State(None),Input(str(path),'status')).run()


@pytest.mark.skipif(sys.platform!='win32',reason='Windows abnormal parent termination gate')
def test_parser_job_dies_with_parent(tmp_path):
    import subprocess
    import ctypes
    script=tmp_path/'parent.py'
    marker=tmp_path/'pids.json'
    script.write_text('''import os,sys,time,json,subprocess
from pathlib import Path
from forensic_assistant.artifacts.ingest import worker
from forensic_assistant.investigation_ai.lifecycle import WorkerJob
import forensic_assistant.artifacts.ingest as ingestion
original=ingestion.WorkerJob
class Observed(original):
    def __init__(self,pid):
        super().__init__(pid)
        Path(sys.argv[1]).write_text(json.dumps([os.getpid(),pid]))
        time.sleep(60)
ingestion.WorkerJob=Observed
worker('mft','unused','a'*64,Path(sys.argv[1]+'.stage'),{},60)
''')
    # The parent is an actual Python process; terminate its reported PID, not
    # the Windows venv launcher. Parsing is still blocked at the handshake.
    env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    parent=subprocess.Popen([sys.executable,str(script),str(marker)],env=env,
                            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    handles=[]
    try:
        deadline=time.monotonic()+10
        while not marker.exists() and time.monotonic()<deadline:time.sleep(.02)
        assert marker.exists()
        ids=json.loads(marker.read_text())
        handles=[process_handle(pid) for pid in ids]
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.OpenProcess.restype=ctypes.c_void_p
        kernel.OpenProcess.argtypes=[ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong]
        kernel.TerminateProcess.argtypes=[ctypes.c_void_p,ctypes.c_uint]
        kernel.CloseHandle.argtypes=[ctypes.c_void_p]
        handle=kernel.OpenProcess(1,False,ids[0])
        try:assert kernel.TerminateProcess(handle,1)
        finally:kernel.CloseHandle(handle)
        for api,handle in handles:assert api.WaitForSingleObject(handle,5000)==0
        parent.wait(timeout=5)
    finally:
        if parent.poll() is None:parent.kill();parent.wait(timeout=5)
        for api,handle in handles:api.CloseHandle(handle)

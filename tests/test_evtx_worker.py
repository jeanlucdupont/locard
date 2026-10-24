"""Timeout semantics and actual hung-XML worker termination, using synthetic data."""
import ctypes
import io
import json
import os
from pathlib import Path
import sys
import struct
import time

import pytest
from forensic_assistant.ingest import evtx_worker as worker
from forensic_assistant.ingest.evtx import ingest_file
from forensic_assistant.database.db import connect
from test_evtx_recovery import chunk, file_bytes
from test_ingest import xml


def test_progress_timer():
    now = [0]
    timer = worker.ProgressDeadline(300, 21600, lambda: now[0])
    for i in range(1, 101):
        now[0] += 200
        assert timer.check() is None
        timer.advance(i)
    assert now[0] > 300 and timer.check() is None
    now[0] += 299
    timer.advance(100)  # Same position/liveness is not progress.
    assert timer.check() is None
    now[0] += 1
    assert 'stalled' in timer.check()


def test_resumption_and_hard_ceiling():
    now = [0]
    timer = worker.ProgressDeadline(300, 21600, lambda: now[0])
    now[0] = 299; timer.advance(1)
    now[0] = 598; assert timer.check() is None
    timer.advance(2)
    for i in range(3, 100):
        now[0] += 200
        timer.advance(i)
    now[0] = 21600
    assert 'hard ceiling' in timer.check()


@pytest.mark.parametrize('advance,hard,expected', [(True, 21600, None),
                                                  (False, 21600, 'stalled'),
                                                  (True, 500, 'hard ceiling')])
def test_supervisor_mocked_clock_and_cleanup(tmp_path, monkeypatch, advance, hard, expected):
    path=tmp_path/'source';path.write_bytes(bytes(10000))
    directory=tmp_path/'ipc';directory.mkdir()
    (directory/'ready').write_text(json.dumps({'worker_pid': 12345}))
    now=[0]; closed=[]
    class Process:
        pid=12345
        returncode=None
        stdin=io.BytesIO()
        def poll(self):
            if now[0] >= 1000:self.returncode=0
            return self.returncode
        def kill(self):self.returncode=-1
        def wait(self, timeout):return self.returncode
    proc=Process()
    monkeypatch.setattr(worker.subprocess,'Popen',lambda *a,**k:proc)
    class Job:
        def __init__(self,pid):pass
        def close(self):closed.append(True);proc.returncode=-1
    monkeypatch.setattr(worker,'WorkerJob',Job)
    if sys.platform!='win32':monkeypatch.setattr(worker.os,'killpg',lambda *a:None)
    def tick(_):
        now[0]+=100
        with (directory/'progress').open('ab') as stream:
            stream.write(struct.pack('<Q', now[0] if advance else 0))
    result=worker.supervise(path,directory,300,hard,clock=lambda:now[0],sleep=tick)
    assert result is None if expected is None else expected in result
    assert closed == [True] and proc.returncode is not None


def assert_gone(pid):
    if os.name=='nt':
        from ctypes import wintypes
        k=ctypes.WinDLL('kernel32',use_last_error=True)
        k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
        k.OpenProcess.restype=wintypes.HANDLE
        k.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
        k.CloseHandle.argtypes=[wintypes.HANDLE]
        handle=k.OpenProcess(0x100000,False,pid)
        if not handle:
            assert ctypes.get_last_error()==87  # PID no longer exists, not access denied.
        if handle:
            try:assert k.WaitForSingleObject(handle,0)==0
            finally:k.CloseHandle(handle)
    else:
        with pytest.raises(ProcessLookupError):os.kill(pid,0)


def install_worker(monkeypatch, hang, cancel=False):
    original=worker.supervise
    seen=[]
    code='''import sys,time,subprocess
from pathlib import Path
from forensic_assistant.ingest import evtx_recovery
from forensic_assistant.ingest.evtx_worker import run
def decode(r):
    if HANG and r.record_num()==2:
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'], creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        Path(sys.argv[2],'descendant').write_text(str(child.pid))
        time.sleep(60)
    return XML.replace('<EventRecordID>7</EventRecordID>', '<EventRecordID>'+str(r.record_num())+'</EventRecordID>')
evtx_recovery.Record.xml=decode
run(sys.argv[1],sys.argv[2])
'''.replace('HANG',repr(hang)).replace('XML',repr(xml()))
    def supervise(path,directory,timeout,hard_timeout):
        def sleep(seconds):
            spool=directory/'records.jsonl'
            if cancel and (directory/'descendant').exists() and spool.exists() and spool.stat().st_size:
                raise KeyboardInterrupt
            time.sleep(seconds)
        try:
            return original(path,directory,timeout,hard_timeout,sleep=sleep,
                            command=[sys.executable,'-c',code,str(path),str(directory)])
        finally:
            ready=directory/'ready'
            if ready.exists():seen.append((directory,json.loads(ready.read_text())['worker_pid']))
            descendant=directory/'descendant'
            if descendant.exists():seen.append((directory,int(descendant.read_text())))
    monkeypatch.setattr(worker,'supervise',supervise)
    return seen


@pytest.mark.parametrize('hang',[False,True])
def test_real_worker_xml_hang_partial_and_cleanup(tmp_path,monkeypatch,hang):
    path=tmp_path/'generated.evtx';path.write_bytes(file_bytes([chunk([1,2])]))
    seen=install_worker(monkeypatch,hang)
    db=connect(':memory:')
    try:
        result=ingest_file(db,path,timeout=2)
        assert result['inserted']==(1 if hang else 2)
        assert result['status']==('partial' if hang else 'complete')
        assert result['errors']==(1 if hang else 0)
        if not hang:
            from forensic_assistant.ingest import evtx_recovery
            monkeypatch.setattr(evtx_recovery.Record, 'xml', lambda r: xml().replace(
                '<EventRecordID>7</EventRecordID>', '<EventRecordID>'+str(r.record_num())+'</EventRecordID>'))
            reference=connect(':memory:')
            try:
                ingest_file(reference,path,reader=evtx_recovery.read_records)
                assert [tuple(r) for r in db.execute('select * from events order by record_offset')]==[
                    tuple(r) for r in reference.execute('select * from events order by record_offset')]
            finally:reference.close()
        if hang:
            assert 'stalled' in db.execute('select message from ingestion_errors').fetchone()[0]
        assert len(seen)==(2 if hang else 1)
        for directory,pid in seen:
            assert not directory.exists()
            assert_gone(pid)
    finally:db.close()


def test_replay_partial_frame_and_diagnostics(tmp_path):
    from dataclasses import asdict
    from forensic_assistant.ingest.evtx import ParsedRecord
    p=tmp_path/'spool'
    err=ParsedRecord(1,error='bad XML',diagnostics={'resume_offset':None,'parsed_records_after_error':0})
    valid=ParsedRecord(2,xml='<Event/>')
    p.write_text(json.dumps({'record':asdict(err),'recoverable':True})+'\n'+
                 json.dumps({'record':asdict(valid),'recoverable':False})+'\n'+ '{"record":')
    found=list(worker.replay(p,'EVTX parser stalled'))
    assert found[0].diagnostics=={'resume_offset':2,'parsed_records_after_error':1}
    assert found[1].xml=='<Event/>' and 'stalled' in found[-1].error


def test_cli_separates_evtx_hard_ceiling():
    from forensic_assistant.cli import build_parser
    args=build_parser().parse_args(['ingest-evtx','sample.evtx','--parser-timeout','30','--evtx-hard-timeout','7200'])
    assert args.parser_timeout==30 and args.evtx_hard_timeout==7200


def test_cancel_reaps_worker_and_descendant_and_removes_spool(tmp_path,monkeypatch):
    path=tmp_path/'generated.evtx';path.write_bytes(file_bytes([chunk([1,2])]))
    seen=install_worker(monkeypatch,True,cancel=True)
    created=[]
    original_temp=worker.tempfile.TemporaryDirectory
    def temporary(*args,**kwargs):
        result=original_temp(*args,**kwargs)
        created.append(Path(result.name))
        return result
    monkeypatch.setattr(worker.tempfile,'TemporaryDirectory',temporary)
    db=connect(':memory:')
    try:
        with pytest.raises(KeyboardInterrupt):
            ingest_file(db,path,timeout=5)
        assert db.execute('select status from ingestion_runs').fetchone()[0]!='complete'
    finally:db.close()
    assert created and all(not p.exists() for p in created)
    assert len(seen)==2
    for directory,pid in seen:
        assert not directory.exists()
        assert_gone(pid)


def test_cleanup_failure_cannot_be_reported_as_complete(tmp_path,monkeypatch):
    from forensic_assistant.investigation_ai.lifecycle import CleanupError
    path=tmp_path/'generated.evtx';path.write_bytes(file_bytes([chunk([1])]))
    def fail(*a,**k):raise CleanupError('synthetic unconfirmed cleanup')
    monkeypatch.setattr(worker,'supervise',fail)
    db=connect(':memory:')
    try:
        with pytest.raises(CleanupError):ingest_file(db,path)
        assert db.execute('select status from ingestion_runs').fetchone()[0]!='complete'
    finally:db.close()

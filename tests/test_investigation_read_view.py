"""Disposable SQLite cases: persistent read views and fail-closed lifecycle."""
import sqlite3
import time
import pytest
from forensic_assistant.investigation_ai.case import ReadView, ReadViewFingerprint, open_readonly, read_transaction
from forensic_assistant.semantic.documents import fingerprint
from forensic_assistant.investigation_ai.runner import ForensicWorker, WorkerError
from forensic_assistant.investigation_ai.lifecycle import CleanupError, cleanup_message
from test_v4_worker import make_case, config


def test_wal_view_and_live_fingerprint(tmp_path):
    path = tmp_path / 'case.db'
    make_case(path)
    writer = sqlite3.connect(path, timeout=.05)
    writer.execute('PRAGMA wal_autocheckpoint=0')
    writer.execute("UPDATE events SET process_name='before.exe'")
    writer.commit()
    view = ReadView(path, time.monotonic()+20)
    try:
        view.fingerprint = fingerprint(view.db)
        proof = ReadViewFingerprint(view)
        writer.execute("UPDATE events SET process_name='after.exe'")
        writer.commit()
        assert view.db.execute('SELECT process_name FROM events').fetchone()[0] == 'before.exe'
        assert fingerprint(view.db) == proof.value(view.db)
        live = open_readonly(path)
        try:
            with read_transaction(live):
                assert fingerprint(live) != proof.value(view.db)
            with pytest.raises(ValueError):
                proof.value(live)
        finally:
            live.close()
        assert writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] == 1
    finally:
        view.close()
    with pytest.raises(ValueError):
        proof.value(view.db)
    assert writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone() == (0,0,0)
    writer.close()


def test_rollback_writer_blocked_until_close(tmp_path):
    path = tmp_path / 'case.db'
    make_case(path, wal=False)
    writer = sqlite3.connect(path, timeout=.05)
    writer.execute('PRAGMA journal_mode=DELETE')
    view = ReadView(path, time.monotonic()+20)
    try:
        writer.execute("UPDATE events SET process_name='after.exe'")
        with pytest.raises(sqlite3.OperationalError, match='locked'):
            writer.commit()
        assert view.db.execute('SELECT process_name FROM events').fetchone()[0] == 'powershell.exe'
    finally:
        view.close()
    writer.commit()
    writer.close()


@pytest.mark.parametrize('sql', ["UPDATE events SET process_name='x'", 'COMMIT', 'ROLLBACK',
    'ATTACH DATABASE ":memory:" AS other', 'PRAGMA query_only=OFF', 'SELECT load_extension("x")',
    'CREATE TABLE forbidden(x)'])
def test_read_view_authorizer(tmp_path, sql):
    path = tmp_path / 'case.db'
    make_case(path)
    view = ReadView(path, time.monotonic()+20)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            view.db.execute(sql)
        assert view.db.in_transaction and view.db.total_changes == 0
    finally:
        view.close()


def test_identity_change_fails_closed(tmp_path):
    path = tmp_path / 'case.db'
    make_case(path)
    view = ReadView(path, time.monotonic()+20)
    try:
        view.identity = (-1, -1)  # portable simulation of replaced inode/file ID
        with pytest.raises(ValueError, match='EVIDENCE_STATE_CHANGED'):
            view.check_identity()
    finally:
        view.close()


def test_worker_timeout_releases_transaction(tmp_path):
    path = tmp_path / 'case.db'
    make_case(path)
    worker = ForensicWorker({**config(path), '_transaction_view': True})
    worker.call('initial', question='PowerShell')
    with pytest.raises(WorkerError, match='TIMEOUT'):
        worker.call('check', seconds=0)
    assert worker.process.poll() is not None
    worker.close()
    with sqlite3.connect(path, timeout=.05) as writer:
        assert writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone() == (0,0,0)


def test_shell_cleanup_failure_exits_without_traceback(monkeypatch, capsys):
    from forensic_assistant.interactive.shell import Shell
    error = CleanupError('secret exception text')
    error.result = {'termination': 'STARTUP_TIMEOUT'}
    def failed(self):
        raise error
    monkeypatch.setattr(Shell, '_run_session', failed)
    shell = object.__new__(Shell)
    assert shell.run() == 1
    out = capsys.readouterr().out
    assert 'startup timed out' in out and 'CLEANUP_LIMITATION' in out
    assert 'secret' not in out and 'session ended' not in out


def test_transaction_semantic_proof_and_stale_index(tmp_path, monkeypatch):
    from forensic_assistant.semantic import index
    from test_v3_index import FakeModel
    path = tmp_path / 'case.db'
    make_case(path)
    source = open_readonly(path)
    try:
        index.build(source, tmp_path/'index', FakeModel())
    finally:
        source.close()
    view = ReadView(path, time.monotonic()+20)
    try:
        view.fingerprint = fingerprint(view.db)
        proof = ReadViewFingerprint(view)
        monkeypatch.setattr(index, 'fingerprint', lambda _: pytest.fail('Redundant fingerprint'))
        found = index.search(view.db, tmp_path/'index', FakeModel(), 'execution', _read_view_proof=proof)
        assert found['results'] and view.db.in_transaction
        with pytest.raises(ValueError, match='Invalid investigation read view proof'):
            index.search(view.db, tmp_path/'index', FakeModel(), 'execution', _read_view_proof='forged')
        original = index._manifest
        def stale(root):
            path, manifest = original(root)
            return path, {**manifest, 'database_fingerprint':'0'*64}
        monkeypatch.setattr(index, '_manifest', stale)
        with pytest.raises(ValueError, match='stale'):
            index.search(view.db, tmp_path/'index', FakeModel(), 'execution', _read_view_proof=proof)
    finally:
        view.close()


def test_cleanup_failure_preserves_primary_in_transcript(tmp_path):
    from forensic_assistant.investigation_ai import controller
    from forensic_assistant.investigation_ai.transcript import load
    from test_investigation_assessment import RecordingWorker
    from test_v4_controller import Scripted
    class Worker(RecordingWorker):
        def call(self, name, *args, **kwargs):
            raise WorkerError('TOOL_TIMEOUT', stage='fingerprint', timed_out=True)
        def close(self):
            raise CleanupError('private exception text')
    with pytest.raises(CleanupError) as caught:
        controller.run({}, 'Inspect', tmp_path/'runs', client=Scripted([]), worker_factory=Worker)
    result = caught.value.result
    assert result['termination'] == 'STARTUP_TIMEOUT'
    assert result['cleanup'] == {'status':'CLEANUP_LIMITATION','stage':'forensic_worker'}
    manifest, events = load(tmp_path/'runs', result['investigation_id'])
    assert 'private exception text' not in str(events)
    assert any(e['kind']=='terminal' and e['data']['termination']=='STARTUP_TIMEOUT' for e in events)


def test_cli_fatal_cleanup_is_nonzero(monkeypatch, capsys):
    from forensic_assistant import cli
    def fail(*args):
        raise CleanupError('secret')
    monkeypatch.setattr(cli, '_main', fail)
    assert cli.main(['status']) == 1
    assert 'CLEANUP_LIMITATION' in capsys.readouterr().err


def test_worker_abnormal_exit_not_success(tmp_path):
    path = tmp_path/'case.db'
    make_case(path)
    worker = ForensicWorker({**config(path), '_transaction_view':True})
    worker.call('initial', question='PowerShell')
    worker.job.close_confirmed()
    worker.process.wait(timeout=2)
    with pytest.raises(WorkerError):
        worker.call('check')
    worker.close()
    with sqlite3.connect(path, timeout=.05) as db:
        assert db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone() == (0,0,0)


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows job containment')
def test_confirmed_job_cleanup_includes_descendant():
    import ctypes
    from ctypes import wintypes as w
    import subprocess
    import sys
    from forensic_assistant.investigation_ai.lifecycle import WorkerJob
    code = ("import os,sys,subprocess,time; print(os.getpid(),flush=True); "
            "sys.stdin.readline(); child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
            "print(child.pid,flush=True); time.sleep(60)")
    process = subprocess.Popen([sys.executable, '-I', '-c', code], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, text=True)
    job = None
    handle = None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD,w.BOOL,w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.WaitForSingleObject.argtypes = [w.HANDLE,w.DWORD]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    try:
        actual_pid = int(process.stdout.readline())
        job = WorkerJob(actual_pid)
        process.stdin.write('go\n'); process.stdin.flush()
        descendant = int(process.stdout.readline())
        handle = kernel.OpenProcess(0x00100000, False, descendant)
        assert handle
        job.close_confirmed(seconds=2)
        process.wait(timeout=2)
        assert kernel.WaitForSingleObject(handle, 0) == 0
    finally:
        if job:
            job.close()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        process.stdin.close(); process.stdout.close()
        if handle:
            kernel.CloseHandle(handle)


def test_transaction_does_not_invoke_backup(tmp_path, monkeypatch):
    from forensic_assistant.investigation_ai import snapshot, controller
    from test_v4_controller import Scripted, final
    path = tmp_path/'case.db'
    make_case(path)
    monkeypatch.setattr(snapshot, 'SnapshotDirectory', lambda: pytest.fail('physical copy directory'))
    monkeypatch.setattr(snapshot, 'create', lambda *a, **kw: pytest.fail('physical copy'))
    result = controller.run(config(path), 'PowerShell', tmp_path/'runs', client=Scripted([final]), dry_run=True)
    assert result['metrics']['integrity']['live_case_matches'] is True

"""Disposable progress snapshots only; Windows sharing and fail-closed transport."""
import ctypes
import json
import os
import threading
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from forensic_assistant.artifacts import progress as p


@pytest.mark.skipif(os.name != 'nt', reason='Windows sharing regression')
def test_original_collision_and_corrected_final_completion(tmp_path):
    path = tmp_path / 'progress'
    reporter = p.Reporter(path)
    temporary = tmp_path / 'old-writer.tmp'
    temporary.write_bytes(b'new')
    with path.open('rb'):
        with pytest.raises(OSError) as caught:
            os.replace(temporary, path)
    assert caught.value.winerror in (5, 32, 33)
    with p.snapshot_reader(path) as reader:
        fd = reader.fileno()
        original = reader.read()
        for phase in p.PHASES[1:]:
            reporter.update(phase=phase, force=True)
        reader.seek(0)
        assert reader.read() == original  # Pinned old snapshot, never a torn new frame.
        assert p.read_snapshot(path)['phase'] == 'complete'
    with pytest.raises(OSError):
        os.fstat(fd)


def test_concurrent_replacements_are_complete_and_monotonic(tmp_path):
    path = tmp_path / 'progress'
    reporter = p.Reporter(path)
    ready = threading.Barrier(2)
    def read():
        deadline = p.Deadline(p.policy(), 10**9)
        ready.wait(timeout=5)
        for _ in range(1000):
            deadline.observe(p.read_snapshot(path))
    def write():
        ready.wait(timeout=5)
        for count in range(1, 501):
            reporter.update(phase='parsing', records=count, bytes_read=count * 1024, force=True)
        for phase in ('staging', 'reconstruction', 'finalizing', 'complete'):
            reporter.update(phase=phase, force=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(read), pool.submit(write)]
        for future in futures:
            future.result(timeout=30)
    assert p.read_snapshot(path)['phase'] == 'complete'
    assert path.stat().st_size <= p.MAX_FRAME


def test_parent_reads_separate_publisher_process(tmp_path):
    import subprocess
    import sys
    import time
    path = tmp_path / 'progress'
    p.Reporter(path)
    code = '''import sys
from pathlib import Path
from forensic_assistant.artifacts import progress as p
r = p.Reporter.__new__(p.Reporter)
r.path = Path(sys.argv[1]); r.clock = __import__('time').monotonic
r.last_write = 0; r.value = p.read_snapshot(r.path)
for n in range(1, 501): r.update(phase='parsing', records=n, force=True)
for phase in p.PHASES[2:]: r.update(phase=phase, force=True)
'''
    proc = subprocess.Popen([sys.executable, '-c', code, str(path)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    deadline = p.Deadline(p.policy(), 10**9)
    end = time.monotonic() + 30
    reads = 0
    try:
        while proc.poll() is None and time.monotonic() < end:
            deadline.observe(p.read_snapshot(path)); reads += 1
        assert proc.wait(timeout=2) == 0, proc.stderr.read(4096)
        deadline.observe(p.read_snapshot(path))
        assert deadline.phase == 'complete' and reads > 0
    finally:
        if proc.poll() is None: proc.kill()
        proc.wait(timeout=5); proc.stderr.close()


def test_hardlink_and_directory_refused(tmp_path):
    original = tmp_path / 'original'
    p.Reporter(original)
    link = tmp_path / 'link'
    os.link(original, link)
    with pytest.raises(p.ProgressError) as caught:
        p.read_snapshot(link)
    assert caught.value.diagnostics['progress_failure'] == 'unsafe_file'
    with pytest.raises(p.ProgressError):
        p.read_snapshot(tmp_path)


def test_missing_file_is_bounded_open_diagnostic(tmp_path):
    with pytest.raises(p.ProgressError) as caught:
        p.read_snapshot(tmp_path / 'private-name')
    details = caught.value.diagnostics
    assert details['progress_operation'] == 'open'
    assert details['progress_failure'] == 'io_error'
    assert 'private-name' not in str(details)


@pytest.mark.parametrize('raw,reason', [(b'{secret', 'invalid_json'), (b'x' * 1025, 'frame_limit'),
                                      (b'{"records":1,"records":2}', 'duplicate_field')])
def test_invalid_frames_keep_bounded_reason(tmp_path, raw, reason):
    path = tmp_path / 'progress'; path.write_bytes(raw)
    with pytest.raises(p.ProgressError) as caught:
        p.read_snapshot(path)
    assert caught.value.diagnostics['progress_failure'] == reason
    assert 'secret' not in str(caught.value.diagnostics)


def test_counter_and_phase_regression_distinct(tmp_path):
    path = tmp_path / 'progress'; reporter = p.Reporter(path)
    deadline = p.Deadline(p.policy(), 10000)
    reporter.update(phase='parsing', records=2, force=True)
    deadline.observe(p.read_snapshot(path))
    reporter.update(records=1, force=True)
    with pytest.raises(p.ProgressError) as caught:
        deadline.observe(p.read_snapshot(path))
    assert caught.value.diagnostics['progress_failure'] == 'counter_regression'
    reporter.update(phase='initialization', records=2, force=True)
    with pytest.raises(p.ProgressError) as caught:
        deadline.observe(p.read_snapshot(path))
    assert caught.value.diagnostics['progress_failure'] == 'phase_regression'


def test_replacement_failure_not_retried_or_disclosed(tmp_path, monkeypatch):
    path = tmp_path / 'progress'; reporter = p.Reporter(path)
    before = path.read_bytes(); calls = []
    def fail(*args):
        calls.append(args)
        raise PermissionError(13, 'secret error contents')
    monkeypatch.setattr(p, 'replace_snapshot', fail)
    with pytest.raises(p.ProgressError) as caught:
        reporter.update(phase='complete', force=True)
    assert len(calls) == 1 and path.read_bytes() == before
    assert caught.value.diagnostics == dict(progress_operation='replace', progress_failure='io_error', errno=13)
    assert 'secret' not in str(caught.value)


def test_worker_diagnostics_are_allowlisted():
    assert p.safe_diagnostics(dict(progress_operation='replace', progress_failure='io_error', winerror=32,
                                  errno=True, phase='complete', staged_output='accepted', private='secret')) == dict(
                                      progress_operation='replace', progress_failure='io_error', winerror=32)
    assert p.safe_diagnostics(dict(progress_operation='secret', progress_failure='private', errno=2**100)) == {}


def test_read_error_distinct_from_open_error(tmp_path, monkeypatch):
    @contextmanager
    def reader(path):
        def fail(count):
            assert count == p.MAX_FRAME + 1
            raise OSError(5, 'private contents')
        yield SimpleNamespace(read=fail)
    monkeypatch.setattr(p, 'snapshot_reader', reader)
    with pytest.raises(p.ProgressError) as caught:
        p.read_snapshot(tmp_path / 'progress')
    assert caught.value.diagnostics == dict(progress_operation='read', progress_failure='io_error', errno=5)


def test_portable_reader_and_publication_branch(tmp_path, monkeypatch):
    # Exercise the portable branch without changing pathlib's host platform.
    portable = SimpleNamespace(**{k: getattr(os, k) for k in
        ('open', 'close', 'fstat', 'fdopen', 'replace', 'O_RDONLY')})
    portable.name = 'posix'
    monkeypatch.setattr(p, 'os', portable)
    path = tmp_path / 'progress'
    reporter = p.Reporter(path)
    reporter.update(phase='complete', force=True)
    assert p.read_snapshot(path)['phase'] == 'complete'


@pytest.mark.skipif(os.name != 'nt', reason='Windows atomic rename API')
def test_native_rename_failure_is_single_attempt_and_closes_handle(tmp_path, monkeypatch):
    path = tmp_path / 'progress'; reporter = p.Reporter(path)
    original = path.read_bytes()
    real_kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    calls = []
    def fail(*args):
        calls.append(args[1])
        ctypes.set_last_error(87)  # Unsupported flags/filesystem must fail closed, no fallback.
        return 0
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **k: SimpleNamespace(
        CreateFileW=real_kernel.CreateFileW, CloseHandle=real_kernel.CloseHandle,
        GetFileInformationByHandleEx=real_kernel.GetFileInformationByHandleEx,
        SetFileInformationByHandle=fail))
    descriptors = []
    real_open = p._windows_fd
    def opened(*a, **kw):
        fd = real_open(*a, **kw); descriptors.append(fd); return fd
    monkeypatch.setattr(p, '_windows_fd', opened)
    with pytest.raises(p.ProgressError) as caught:
        reporter.update(phase='complete', force=True)
    assert caught.value.diagnostics['winerror'] == 87
    assert caught.value.diagnostics['progress_operation'] == 'replace'
    assert calls == [22] and path.read_bytes() == original
    for fd in descriptors:
        with pytest.raises(OSError): os.fstat(fd)


@pytest.mark.skipif(os.name != 'nt', reason='Windows reparse check after precheck')
def test_reparse_substitution_is_not_followed(tmp_path, monkeypatch):
    path = tmp_path / 'progress'; other = tmp_path / 'other'
    p.Reporter(path); p.Reporter(other)
    before = other.read_bytes()
    real_open = p._windows_fd
    def substitute(target):
        path.unlink()
        try: path.symlink_to(other)
        except OSError as exc: pytest.skip('Synthetic symlink creation unavailable: ' + str(exc.winerror))
        return real_open(target)
    monkeypatch.setattr(p, '_windows_fd', substitute)
    with pytest.raises(p.ProgressError) as caught:
        p.read_snapshot(path)
    assert caught.value.diagnostics['progress_failure'] == 'unsafe_file'
    assert other.read_bytes() == before


def test_final_publication_failure_reaps_worker_and_rejects_committed_stage(tmp_path, monkeypatch):
    from pathlib import Path
    from forensic_assistant.artifacts import ingest
    from forensic_assistant.database.db import connect
    from v2_fixtures import mft_file
    from test_evtx_worker import assert_gone
    source = mft_file(tmp_path / 'MFT'); before = source.read_bytes()
    real_launch = ingest.subprocess.Popen
    processes, stages = [], []
    code = '''import runpy
from forensic_assistant.artifacts import progress as p
original = p.Reporter.update
def update(self, **kw):
    if kw.get('phase') == 'complete':
        raise p.ProgressError('synthetic failure', operation='replace', failure='io_error', cause=PermissionError(13, 'private'))
    return original(self, **kw)
p.Reporter.update = update
runpy.run_module('forensic_assistant.artifacts.worker', run_name='__main__')
'''
    def launch(args, **kwargs):
        stages.append(Path(args[6]))
        proc = real_launch([args[0], '-c', code, *args[3:]], **kwargs)
        processes.append(proc)
        return proc
    monkeypatch.setattr(ingest.subprocess, 'Popen', launch)
    db = connect(':memory:')
    result = ingest.ingest_artifact(db, source, 'mft')
    assert result['status'] == 'failed' and result['inserted'] == 0
    assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 0
    detail = json.loads(db.execute('SELECT locator_json FROM artifact_errors').fetchone()[0])
    assert detail['category'] == 'progress_communication'
    assert detail['progress_operation'] == 'replace' and detail['errno'] == 13
    assert detail['cleanup'] == 'confirmed' and detail['staged_output'] == 'rejected'
    assert detail['worker_exit_code_before_cleanup'] != 0
    assert processes and all(proc.poll() is not None for proc in processes)
    for proc in processes: assert_gone(proc.pid)
    assert all(not stage.parent.exists() for stage in stages)
    assert source.read_bytes() == before


@pytest.mark.skipif(os.name != 'nt', reason='Windows handle API')
@pytest.mark.parametrize('mode', ['open_failure', 'reparse', 'information_failure', 'fd_failure'])
def test_windows_api_failures_close_owned_handles(tmp_path, monkeypatch, mode):
    from ctypes import wintypes as w
    import msvcrt
    closed = []
    def create(*args):
        assert args[2] == 7 and args[5] == 0x00200000
        ctypes.set_last_error(5)
        return w.HANDLE(-1).value if mode == 'open_failure' else 123
    def info(handle, kind, pointer, size):
        if mode == 'information_failure':
            ctypes.set_last_error(5)
            return 0
        ctypes.cast(pointer, ctypes.POINTER(w.DWORD))[0] = 0x400 if mode == 'reparse' else 0
        return 1
    def close(handle):
        closed.append(handle)
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **k: SimpleNamespace(
        CreateFileW=create, GetFileInformationByHandleEx=info, CloseHandle=close))
    monkeypatch.setattr(msvcrt, 'open_osfhandle', lambda *a: (_ for _ in ()).throw(OSError('fd allocation failed')))
    with pytest.raises((OSError, p.ProgressError)):
        p._windows_fd(tmp_path / 'progress')
    assert closed == ([] if mode == 'open_failure' else [123])


@pytest.mark.skipif(os.name != 'nt', reason='Windows no-follow race')
def test_hardlink_substitution_after_path_check_rejected(tmp_path, monkeypatch):
    path = tmp_path / 'progress'; other = tmp_path / 'other'
    p.Reporter(path); p.Reporter(other)
    original = p._windows_fd
    def substitute(target):
        path.unlink()
        os.link(other, path)
        return original(target)
    monkeypatch.setattr(p, '_windows_fd', substitute)
    with pytest.raises(p.ProgressError) as caught:
        p.read_snapshot(path)
    assert caught.value.diagnostics['progress_failure'] == 'unsafe_file'

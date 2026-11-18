"""Synthetic MFT progress, deadline, publication and presentation controls."""
import io
import json
import sys
from pathlib import Path

import pytest

from forensic_assistant.artifacts import progress as p, ingest
from forensic_assistant.database.db import connect
from v2_fixtures import mft_file


def frame(phase='parsing', records=1, paths=0):
    return dict(contract='mft-progress-v1', phase=phase, records=records,
                bytes_read=records * 1024, paths=paths)


def test_real_advancement_and_reconstruction_only_extend_idle_deadline():
    clock = [0]
    d = p.Deadline(p.policy(), 10**9, lambda: clock[0])
    d.ready = True
    for i in range(1, 20):
        clock[0] += 800
        assert d.check() is None
        d.observe(frame(records=i))
    d.observe(frame('reconstruction', records=19))
    for i in range(1, 4):
        clock[0] += 800
        d.observe(frame('reconstruction', records=19, paths=i))
        assert d.check() is None
    clock[0] += 899
    d.observe(frame('reconstruction', records=19, paths=3))
    assert d.check() is None
    clock[0] += 1
    assert d.check() == 'progress_inactivity'


def test_startup_and_hard_ceiling_independent():
    clock = [0]
    d = p.Deadline(p.policy(), 10000, lambda: clock[0])
    clock[0] = 60
    assert d.check() == 'startup_timeout'
    d.ready = True
    d.observe(frame())
    clock[0] = 21600
    d.observe(frame(records=2))
    assert d.check() == 'emergency_ceiling'


@pytest.mark.parametrize('value', [frame(records=-1), frame(records=True), frame(phase='heartbeat'),
                                  dict(frame(), extra=1), frame(records=100), frame(phase='parsing', paths=1)])
def test_invalid_frames(value):
    d = p.Deadline(p.policy(), 8192)
    with pytest.raises(p.ProgressError):
        d.observe(value)


def test_monotonic_and_fixed_phase_counts():
    d = p.Deadline(p.policy(), 8192)
    d.observe(frame(records=2))
    with pytest.raises(p.ProgressError): d.observe(frame(records=1))
    d.observe(frame('staging', records=2))
    with pytest.raises(p.ProgressError): d.observe(frame('parsing', records=2))
    with pytest.raises(p.ProgressError): d.observe(frame('staging', records=3))


def test_bounded_coalescing_and_bad_transport(tmp_path):
    clock = [0]
    path = tmp_path / 'progress'
    r = p.Reporter(path, lambda: clock[0])
    original = path.read_bytes()
    for i in range(10000): r.update(records=i)
    assert path.read_bytes() == original
    clock[0] = 1
    r.update(phase='parsing', records=10000)
    assert p.read_snapshot(path)['records'] == 10000
    assert path.stat().st_size < p.MAX_FRAME
    for content in (b'x'*1025, b'{"phase":1,"phase":2}', b'invalid'):
        path.write_bytes(content)
        with pytest.raises(p.ProgressError): p.read_snapshot(path)


@pytest.mark.parametrize('mode,category', [('healthy', None), ('idle', 'progress_inactivity'),
    ('startup', 'startup_timeout'), ('hard', 'emergency_ceiling'), ('crash', 'worker_crash'),
    ('bad', 'progress_communication'), ('cancel', 'cancelled'), ('incomplete', 'incomplete_progress')])
def test_supervisor_deadlines_and_cleanup(tmp_path, monkeypatch, mode, category):
    source = tmp_path/'source'; source.write_bytes(bytes(100000))
    stage = tmp_path/'stage.db'
    if mode != 'startup': Path(str(stage)+'.ready').write_text('{"worker_pid":12345}')
    clock = [0]; closed = []
    class Process:
        pid = 12345
        returncode = None
        stdin = io.BytesIO()
        def poll(self): return self.returncode
        def kill(self): self.returncode = -1
        def wait(self, **kwargs): self.returncode = -1; return -1
    proc = Process()
    def launch(*args, **kwargs):
        kwargs['stdout'].write(b'{"records":1,"errors":0}')
        return proc
    monkeypatch.setattr(ingest.subprocess, 'Popen', launch)
    class Job:
        def __init__(self, pid): assert pid == proc.pid
        def close(self): closed.append(True); proc.kill()
    monkeypatch.setattr(ingest, 'WorkerJob', Job)
    if sys.platform != 'win32': monkeypatch.setattr(ingest.os, 'killpg', lambda *a: None)
    monkeypatch.setattr(ingest.time, 'monotonic', lambda: clock[0])
    def tick(_):
        clock[0] += 100
        if mode == 'cancel': raise KeyboardInterrupt
        if mode == 'bad': p.snapshot_path(stage).write_text('bad'); return
        if mode == 'crash': proc.returncode = 2; return
        if mode == 'startup': return
        value = frame(records=1 if mode == 'idle' else clock[0]//100)
        if clock[0] >= 1000 and mode in ('healthy', 'incomplete'):
            proc.returncode = 0
            if mode == 'healthy': value['phase'] = 'complete'
        p.snapshot_path(stage).write_text(json.dumps(value))
    monkeypatch.setattr(ingest.time, 'sleep', tick)
    limits = p.policy(300, 300, 500 if mode == 'hard' else 21600)
    if category:
        with pytest.raises(KeyboardInterrupt if mode == 'cancel' else p.WorkerFailure) as caught:
            ingest.worker('mft', str(source), 'a'*64, stage, {'_supervision':limits}, 300)
        assert caught.value.diagnostics['category'] == category
        assert caught.value.diagnostics['cleanup'] == 'confirmed'
    else:
        assert ingest.worker('mft', str(source), 'a'*64, stage, {'_supervision':limits}, 300)['records'] == 1
        assert clock[0] > 300
    assert proc.poll() is not None and proc.stdin.closed
    assert closed == ([] if mode == 'startup' else [True])


def test_incomplete_reconstruction_is_never_published(tmp_path):
    from forensic_assistant.artifacts.worker import run
    source = mft_file(tmp_path/'MFT'); original = source.read_bytes()
    db = connect(':memory:'); stages = []
    def failed(kind, path, sha, stage, options, timeout):
        stages.append(stage.parent)
        run(kind, path, sha, stage, options)
        raise p.WorkerFailure('progress_inactivity', dict(phase='reconstruction', cleanup='confirmed'))
    result = ingest.ingest_artifact(db, source, 'mft', runner=failed)
    assert result['status'] == 'failed' and result['inserted'] == 0
    assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 0
    detail = json.loads(db.execute('SELECT locator_json FROM artifact_errors').fetchone()[0])
    assert detail['phase'] == 'reconstruction' and detail['staged_output'] == 'rejected'
    assert all(not stage.exists() for stage in stages)
    assert source.read_bytes() == original


def test_progress_presentation_and_redirected_output():
    from forensic_assistant.interactive.setup_display import FileProgress
    from forensic_assistant.terminal import Palette
    stream = io.StringIO()
    meter = FileProgress('mft', 1, Palette(), stream=stream)
    meter.observe(dict(parser_stage='reconstruction', paths_processed=27))
    meter.update(0, 0); meter.close()
    assert 'reconstruction: 27 paths processed' in stream.getvalue()
    assert '\x1b' not in stream.getvalue()
    assert '0 records stored' in stream.getvalue()


@pytest.mark.parametrize('cancel', [False, True])
def test_actual_hung_reconstruction_is_reaped(tmp_path, monkeypatch, cancel):
    from test_evtx_worker import assert_gone
    source = mft_file(tmp_path/'MFT')
    before = source.read_bytes()
    original = ingest.subprocess.Popen
    seen = []
    code = """import runpy,time,sys,os
from pathlib import Path
from forensic_assistant.artifacts import mft
def hang(*args):
    Path(sys.argv[4]+'.hung').write_text(str(os.getpid()))
    time.sleep(60)
mft.reconstruct_paths=hang
runpy.run_module('forensic_assistant.artifacts.worker',run_name='__main__')
"""
    def launch(args, **kwargs):
        stage = Path(args[6])
        seen.append(stage)
        return original([args[0], '-c', code, *args[3:]], **kwargs)
    monkeypatch.setattr(ingest.subprocess, 'Popen', launch)
    sleep = ingest.time.sleep
    def wait(seconds):
        if cancel and seen and Path(str(seen[0])+'.hung').exists():
            raise KeyboardInterrupt
        sleep(seconds)
    monkeypatch.setattr(ingest.time, 'sleep', wait)
    db = connect(':memory:')
    # Capture the real child PID before TemporaryDirectory removes its marker.
    ids = []
    def runner(*args):
        try: return ingest.worker(*args)
        finally:
            marker = Path(str(args[3])+'.hung')
            if marker.exists(): ids.append(int(marker.read_text()))
    if cancel:
        with pytest.raises(KeyboardInterrupt):
            ingest.ingest_artifact(db, source, 'mft', timeout=2, runner=runner)
    else:
        result = ingest.ingest_artifact(db, source, 'mft', timeout=2, runner=runner)
        assert result['status'] == 'failed' and result['inserted'] == 0
    assert ids
    for pid in ids: assert_gone(pid)
    assert all(not stage.parent.exists() for stage in seen)
    assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 0
    diagnostic = json.loads(db.execute('SELECT locator_json FROM artifact_errors').fetchone()[0])
    assert diagnostic['category'] == ('cancelled' if cancel else 'progress_inactivity')
    assert diagnostic['phase'] == 'reconstruction'
    assert diagnostic['cleanup'] == 'confirmed'
    assert source.read_bytes() == before


def test_mft_cli_policy_defaults_and_overrides():
    from forensic_assistant.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(['evidence', 'ingest', 'mft', 'synthetic'])
    assert args.parser_timeout is None
    assert args.mft_startup_timeout == 60 and args.mft_hard_timeout == 21600
    args = parser.parse_args(['evidence', 'ingest', 'mft', 'synthetic', '--parser-timeout', '1200',
                             '--mft-startup-timeout', '90', '--mft-hard-timeout', '43200'])
    assert (args.parser_timeout, args.mft_startup_timeout, args.mft_hard_timeout) == (1200, 90, 43200)


def test_launch_failure_is_sanitized(tmp_path, monkeypatch):
    source = tmp_path/'source'; source.write_bytes(b'')
    def fail(*a, **k): raise OSError('private path or parser data')
    monkeypatch.setattr(ingest.subprocess, 'Popen', fail)
    with pytest.raises(p.WorkerFailure) as caught:
        ingest.worker('mft', str(source), 'a'*64, tmp_path/'stage', {}, 900)
    assert caught.value.diagnostics['category'] == 'startup_failure'
    assert 'private' not in str(caught.value.diagnostics)


def test_cleanup_failure_remains_fatal_and_recorded(tmp_path):
    from forensic_assistant.investigation_ai.lifecycle import CleanupError
    source = mft_file(tmp_path/'MFT')
    def fail(*a): raise CleanupError('Unconfirmed cleanup')
    db = connect(':memory:')
    with pytest.raises(CleanupError): ingest.ingest_artifact(db, source, 'mft', runner=fail)
    assert db.execute('SELECT status FROM ingestion_runs').fetchone()[0] == 'failed'
    assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 0
    diagnostic = json.loads(db.execute('SELECT locator_json FROM artifact_errors').fetchone()[0])
    assert diagnostic['category'] == 'cleanup_failure' and diagnostic['cleanup'] == 'unconfirmed'


def test_scripted_json_has_no_progress_frames(tmp_path, capsys):
    from forensic_assistant.cli import main
    source = mft_file(tmp_path/'MFT')
    target = tmp_path/'case.db'; connect(target).close()
    assert main(['--db', str(target), 'evidence', 'ingest', 'mft', str(source), '--json']) == 0
    text = capsys.readouterr().out
    value = json.loads(text)
    assert value['results'][0]['inserted'] == 3
    assert '\x1b' not in text and 'record slots processed' not in text

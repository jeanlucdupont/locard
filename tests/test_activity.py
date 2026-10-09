"""Synthetic audit integrity, privacy, lifecycle, and fail-safe mutations."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from forensic_assistant import activity
from forensic_assistant.cli import main
from forensic_assistant.database import sources
from forensic_assistant.database.db import connect
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from test_interactive_shell import Input
from test_output_ux import case


def records(path):
    result = activity.inspect(activity.sidecar(path), 1000)
    assert result['valid'], result
    return result['records']


def test_chain_sequence_utc_and_canonical_bytes(tmp_path):
    path = tmp_path / 'test.audit.jsonl'
    previous = None
    for i in range(3):
        entry = activity.append(path, 'session-one', 'SEARCH', 'success', argv=['search', '--title', 'café'])
        assert entry['sequence'] == i + 1 and entry['previous_entry_hash'] == previous
        assert datetime.fromisoformat(entry['timestamp_utc']).utcoffset().total_seconds() == 0
        assert entry['timestamp_utc'].endswith('Z')
        body = {k: v for k, v in entry.items() if k != 'entry_hash'}
        assert entry['entry_hash'] == hashlib.sha256(activity.canonical(body)).hexdigest()
        previous = entry['entry_hash']
    before = path.read_bytes()
    result = activity.inspect(path, 2)
    assert result['entries'] == 3 and len(result['records']) == 2 and result['head_hash'] == previous
    assert path.read_bytes() == before


@pytest.mark.parametrize('damage', ['modify', 'remove', 'reorder', 'partial', 'malformed', 'duplicate_key'])
def test_verify_detects_historical_or_trailing_damage(tmp_path, damage):
    path = tmp_path / 'audit'
    for _ in range(4):
        activity.append(path, 'session', 'COMMAND', 'success')
    lines = path.read_bytes().splitlines(keepends=True)
    if damage == 'modify':
        lines[1] = lines[1].replace(b'COMMAND', b'TAMPERED')
    elif damage == 'remove':
        del lines[1]
    elif damage == 'reorder':
        lines[1], lines[2] = lines[2], lines[1]
    elif damage == 'partial':
        lines[-1] = lines[-1][:-10]
    elif damage == 'malformed':
        lines.append(b'{broken}\n')
    else:
        lines[-1] = lines[-1].replace(b'{', b'{"action":"extra",', 1)
    path.write_bytes(b''.join(lines))
    original = path.read_bytes()
    result = activity.inspect(path)
    assert not result['valid'] and result['first_invalid_entry'] >= 2
    assert path.read_bytes() == original


def test_partial_tail_blocks_append_and_fsync_failure_preserves_prefix(tmp_path, monkeypatch):
    path = tmp_path / 'audit'
    activity.append(path, 'session', 'COMMAND', 'success')
    original = path.read_bytes()
    path.write_bytes(original + b'{partial')
    with pytest.raises(activity.AuditError):
        activity.append(path, 'session', 'COMMAND', 'success')
    assert path.read_bytes() == original + b'{partial'
    path.write_bytes(original)
    def denied(*args):
        raise OSError('synthetic flush failure')
    monkeypatch.setattr(activity.os, 'fsync', denied)
    with pytest.raises(OSError):
        activity.append(path, 'session', 'COMMAND', 'success')
    assert path.read_bytes() == original and activity.inspect(path)['valid']


def test_append_tail_work_is_bounded(tmp_path):
    path = tmp_path / 'audit'
    for _ in range(12):
        activity.append(path, 'session', 'COMMAND', 'success', padding='x' * 8000)
    class Counting(io.BytesIO):
        count = 0
        def read(self, n=-1):
            result = super().read(n)
            self.count += len(result)
            return result
    stream = Counting(path.read_bytes())
    assert activity.tail(stream)['sequence'] == 12
    assert stream.count < 16384 < len(path.read_bytes())


def test_threads_and_processes_share_monotonic_sequence(tmp_path):
    path = tmp_path / 'audit'
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda i: activity.append(path, str(i), 'COMMAND', 'success'), range(20)))
    script = "from forensic_assistant.activity import append; import sys; [append(sys.argv[1],sys.argv[2],'COMMAND','success') for _ in range(10)]"
    processes = [subprocess.Popen([sys.executable, '-B', '-c', script, str(path), str(i)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE) for i in range(2)]
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr
    result = activity.inspect(path, 100)
    assert result['valid'] and result['entries'] == 40


def test_hardlink_audit_alias_is_refused(tmp_path):
    path, original = tmp_path / 'audit', tmp_path / 'original'
    original.write_bytes(b'private data')
    os.link(original, path)
    with pytest.raises(activity.AuditError):
        activity.append(path, 'session', 'COMMAND', 'success')
    assert original.read_bytes() == b'private data'


@pytest.mark.parametrize('option', ['password', 'passwd', 'api-key', 'api_token', 'access-token', 'refresh-token',
                                    'secret', 'client-secret', 'credentials', 'authorization', 'bearer-token'])
def test_deterministic_secret_option_redaction(option):
    raw = ['future', '--' + option, 'private-value', '--' + option + '=private-inline', '--title', 'analyst query']
    assert activity.redact_argv(raw) == ['future', '--' + option, '<redacted>', '--' + option + '=<redacted>', '--title', 'analyst query']
    assert activity.clean({option: 'private', 'query': 'public'}) == {option: '<redacted>', 'query': 'public'}


def test_interactive_lifecycle_commands_and_evidence_privacy(case, capsys):
    path, eid, _ = case
    before = path.read_bytes()
    shell = Shell(State(None), Input(str(path), 'search --artifact prefetch --limit 1', f'show {eid}',
                                     f'around {eid} --timestamp-slot run:1 --seconds 20',
                                     f'investigate {eid} --timestamp-slot run:1', 'show missing', 'exit'))
    assert shell.run() == 0
    entries = records(path)
    assert entries[0]['action'] == 'SESSION_START' and entries[-1]['action'] == 'SESSION_END'
    assert len({e['session_id'] for e in entries}) == 1
    searches = [e for e in entries if e['action'] == 'COMMAND' and e.get('command') == 'search' and e['outcome'] == 'success']
    assert searches[0]['parameters']['limit'] == 1 and searches[0]['result_count'] == 1
    assert any(e['action'] == 'SHOW' and e.get('evidence_id') == eid for e in entries)
    assert any(e['action'] == 'AROUND' and e.get('seconds') == 20 and e.get('timestamp_slot') == 'run:1' for e in entries)
    assert any(e['action'] == 'INVESTIGATE' and e.get('evidence_id') == eid for e in entries)
    assert any(e['action'] == 'COMMAND' and e['outcome'] == 'failure' and e.get('error_category') for e in entries)
    assert 'REFERENCE_ONLY' not in activity.sidecar(path).read_text() and path.read_bytes() == before


def test_fatal_session_has_no_fake_end(case, monkeypatch):
    path, _, _ = case
    def fatal(*args, **kwargs):
        raise RuntimeError('synthetic fatal worker failure')
    monkeypatch.setattr('forensic_assistant.cli.dispatch', fatal)
    with pytest.raises(RuntimeError):
        Shell(State(None), Input(str(path), 'status')).run()
    assert not any(e['action'] == 'SESSION_END' for e in records(path))


def test_case_switch_has_separate_session_identity(case, tmp_path):
    path, _, _ = case
    other = tmp_path / 'other.db'
    connect(other).close()
    Shell(State(None), Input(str(path), f'case "{other}"', 'status', 'exit')).run()
    a, b = records(path), records(other)
    assert a[-1]['action'] == b[-1]['action'] == 'SESSION_END'
    assert {e['session_id'] for e in a}.isdisjoint({e['session_id'] for e in b})


def test_activity_snapshot_precedes_own_command(case, capsys):
    path, _, _ = case
    assert main(['--db', str(path), 'status']) == 0
    capsys.readouterr()
    assert main(['--db', str(path), 'activity', '--json', '--limit', '1000']) == 0
    snapshot = json.loads(capsys.readouterr().out)
    assert not any(e.get('command') == 'activity' for e in snapshot['records'])
    assert any(e.get('command') == 'activity' for e in records(path))
    assert main(['--db', str(path), 'activity', '--verify']) == 0
    assert 'Chain: valid' in capsys.readouterr().out


def test_read_warns_but_source_mutation_fails_before_change(case, monkeypatch, capsys):
    path, _, _ = case
    with closing(connect(path)) as db, db:
        sid = sources.create(db, name='Original')
    before = path.read_bytes()
    def denied(*args, **kwargs):
        raise PermissionError('synthetic audit denial')
    monkeypatch.setattr(activity, 'append', denied)
    assert main(['--db', str(path), 'status']) == 0
    assert 'Warning: Activity log unavailable' in capsys.readouterr().err
    assert main(['--db', str(path), 'source', 'update', sid, '--name', 'Forbidden', '--yes']) == 2
    assert path.read_bytes() == before


def test_source_update_actual_values_and_declined_change(case, capsys):
    path, _, _ = case
    with closing(connect(path)) as db, db:
        sid = sources.create(db, name='Original')
    assert main(['--db', str(path), 'source', 'update', sid, '--hostname', 'HOST-A', '--name', 'Renamed', '--yes']) == 0
    output = capsys.readouterr().out
    assert 'Previous assertion retained.' not in output and 'Name: Original -> Renamed' in output
    changes = [e['changes'] for e in records(path) if e['action'] == 'SOURCE_UPDATE' and e['outcome'] == 'success'][0]
    assert changes['hostname'] == dict(previous_value=None, new_value='host-a')
    Shell(State(None), Input(str(path), f'source update {sid} --name Declined', 'n', 'exit')).run()
    assert any(e['action'] == 'SOURCE_UPDATE' and e['outcome'] == 'cancelled' for e in records(path))
    with closing(connect(path)) as db:
        assert sources.current(db, sid)['display_name'] == 'Renamed'
        assert db.execute('SELECT count(*) FROM source_assertions WHERE source_id=?', (sid,)).fetchone()[0] == 2


def test_postcommit_audit_failure_is_explicit_and_intent_survives(case, monkeypatch, capsys):
    path, _, _ = case
    with closing(connect(path)) as db, db:
        sid = sources.create(db, name='Original')
    append = activity.append
    def fail_completion(log_path, session_id, action, outcome, **fields):
        if action == 'SOURCE_UPDATE' and fields.get('phase') == 'complete':
            raise OSError('completion unavailable')
        return append(log_path, session_id, action, outcome, **fields)
    monkeypatch.setattr(activity, 'append', fail_completion)
    assert main(['--db', str(path), 'source', 'update', sid, '--name', 'Committed', '--yes']) == 2
    assert 'Action completed but its audit completion failed' in capsys.readouterr().err
    assert any(e['action'] == 'SOURCE_UPDATE' and e['phase'] == 'intent' for e in records(path))
    with closing(connect(path)) as db:
        assert sources.current(db, sid)['display_name'] == 'Committed'


def test_audit_not_evidence_or_discovery(case, capsys):
    from forensic_assistant.artifacts.ingest import discover
    path, _, source = case
    before = path.read_bytes()
    main(['--db', str(path), 'status'])
    audit = activity.sidecar(path)
    assert audit.exists()
    assert all(p != audit for p, _ in discover(path.parent, include_browser=True))
    # Even a misleading signature must not turn an audit sidecar into evidence.
    audit.write_bytes(b'ElfFile\x00' + bytes(100))
    assert all(p != audit for p, _ in discover(path.parent, include_browser=True))
    assert path.read_bytes() == before


def test_ingestion_audits_summary_not_browser_payload(tmp_path, capsys):
    from test_browser_parser import history
    original = tmp_path / 'History'
    history(original).close()
    target = tmp_path / 'case.db'
    assert main(['--db', str(target), 'ingest-browser', str(original), '--browser', 'chrome', '--profile', 'Default']) == 0
    entries = records(target)
    result = next(e for e in entries if e['action'] == 'INGEST' and e['outcome'] == 'success')
    assert result['inserted'] == 2 and result['errors'] == 0 and result['artifact_type'] == 'browser'
    assert result['source_id'] and result['batch_id']
    assert 'example.com' not in activity.sidecar(target).read_text()


def test_ingestion_finalizes_batch_when_source_audit_fails(case, tmp_path, monkeypatch):
    from test_browser_parser import history
    path, _, _ = case
    original = tmp_path / 'History'
    history(original).close()
    append = activity.append
    def denied(log_path, session_id, action, outcome, **fields):
        if action == 'SOURCE_CREATE':
            raise OSError('synthetic audit completion failure')
        return append(log_path, session_id, action, outcome, **fields)
    monkeypatch.setattr(activity, 'append', denied)
    assert main(['--db', str(path), 'ingest-browser', str(original), '--browser', 'chrome', '--profile', 'Default']) == 2
    with closing(connect(path)) as db:
        batch = db.execute('SELECT status,finished_utc FROM ingestion_batches').fetchone()
        assert batch['status'] == 'failed' and batch['finished_utc']
        assert db.execute('SELECT count(*) FROM browser_record_occurrences').fetchone()[0] == 0
    assert any(e['action'] == 'INGEST_BATCH' and e['outcome'] == 'failure' for e in records(path))


def test_preparation_failure_has_one_failed_command(case, monkeypatch):
    path, _, _ = case
    def denied(*args):
        raise ValueError('synthetic preparation error')
    monkeypatch.setattr('forensic_assistant.interactive.sources.prepare', denied)
    Shell(State(None), Input(str(path), 'status', 'exit')).run()
    commands = [e for e in records(path) if e['action'] == 'COMMAND']
    assert len(commands) == 1 and commands[0]['outcome'] == 'failure'
    assert commands[0]['error_category'] == 'ValueError'


def test_interrupted_command_entry_restores_context(case, monkeypatch):
    from forensic_assistant.cli import build_parser
    path, _, _ = case
    def cancel(*args):
        raise KeyboardInterrupt
    monkeypatch.setattr('forensic_assistant.interactive.case.validate', cancel)
    args = build_parser().parse_args(['--db', str(path), 'status'])
    with pytest.raises(KeyboardInterrupt):
        with activity.Command(args):
            pytest.fail('must not enter interrupted command')
    assert activity.CURRENT.get() is None and activity.COMMAND.get() is None


def test_error_message_redacts_recognized_secret_values():
    from types import SimpleNamespace
    command = SimpleNamespace(argv=['future', '--api-key=private-value', '--password', 'hidden'])
    token = activity.COMMAND.set(command)
    try:
        error = activity.error_data(ValueError('private-value and hidden unavailable'))
        assert error['message'] == '<redacted> and <redacted> unavailable'
    finally:
        activity.COMMAND.reset(token)

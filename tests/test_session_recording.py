"""Disposable process records only. No providers or real forensic cases."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from types import SimpleNamespace
import hashlib
import io
import json
import logging
import os
import sys
import pytest

from forensic_assistant import activity, session_recording as sr
from forensic_assistant.database.db import connect
from forensic_assistant.cli import main, build_parser


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'app'))
    monkeypatch.setenv('USERPROFILE', str(tmp_path / 'user'))
    monkeypatch.setattr('forensic_assistant.ai.backend.ModelBackend.complete', lambda *a, **k: pytest.fail('provider called'))


def case(tmp_path, name='one'):
    path = tmp_path / name / 'case.db'
    path.parent.mkdir()
    with closing(connect(path)):
        pass
    return path


def entries(path):
    return [activity.decode(line) for line in path.read_bytes().splitlines(keepends=True)]


def test_lifecycle_input_output_diagnostics_and_defaults(tmp_path):
    with sr.execution([]) as rec:
        path = rec.path
        sr.read_response(lambda p: 'y', 'Authorize? [y/N]: ')
        sr.read_response(lambda p: 'n', 'Authorize? [y/N]: ')
        sr.read_response(lambda p: '', 'Use default? [Y/n]: ')
        sr.read_response(lambda p: 'evidence search --process café', '> ', command=True)
        print('\x1b[31mUnicode café ─\x1b[0m')
        print('handled failure', file=sys.stderr)
        logging.getLogger('forensic_assistant.synthetic').info('parser finished')
    rows = entries(path)
    assert [e['sequence'] for e in rows] == list(range(1, len(rows)+1))
    assert rows[-1]['action'] == 'session_end'
    assert '\x1b' not in path.read_text(encoding='utf-8')
    inputs = [e['data'] for e in rows if e['action'] == 'input']
    assert [x['value'] for x in inputs[:3]] == ['y', 'n', '']
    assert inputs[2]['default_resolution'] == 'application-owned'
    assert inputs[3]['provenance'] == 'shell_command'
    assert any(e['data'].get('channel') == 'stderr' for e in rows)
    assert any(e['action'] == 'diagnostic' for e in rows)
    assert sr.verify()['sessions'][0]['integrity'] == 'verified'


def test_case_switch_and_database_unchanged(tmp_path):
    a, b = case(tmp_path), case(tmp_path, 'two')
    original = {p: p.read_bytes() for p in (a,b)}
    with sr.execution([]) as rec:
        rec.open(a)
        pa = rec.path
        print('only first case')
        rec.open(b)
        pb = rec.path
        print('only second case')
    assert 'only second case' not in pa.read_text()
    assert 'only first case' not in pb.read_text()
    assert all(p.read_bytes() == raw for p, raw in original.items())
    assert sr.verify(a)['sessions'][0]['integrity'] == 'verified'
    assert sr.verify(b)['sessions'][0]['integrity'] == 'verified'


@pytest.mark.parametrize('damage', ['modify', 'delete', 'reorder', 'partial', 'missing', 'truncate_tail'])
def test_anchored_tampering(tmp_path, damage):
    with sr.execution([]) as rec:
        path = rec.path
        rec.emit('one');rec.emit('two')
    lines = path.read_bytes().splitlines(keepends=True)
    if damage == 'modify':lines[1] = lines[1].replace(b'application_start', b'false_start')
    if damage == 'delete':del lines[1]
    if damage == 'reorder':lines[1],lines[2] = lines[2],lines[1]
    if damage == 'partial':lines[-1] = lines[-1][:-5]
    if damage == 'truncate_tail':lines.pop()
    if damage == 'missing':path.unlink()
    else:path.write_bytes(b''.join(lines))
    result = sr.verify()
    assert not result['valid']
    assert result['sessions'][0]['integrity'] == ('missing' if damage == 'missing' else 'corrupt')


def test_incomplete_and_unanchored_are_not_complete(tmp_path):
    rec = sr.Recorder(io.StringIO());rec.open();rec.emit('unfinished')
    assert sr.verify()['sessions'][0]['integrity'] == 'incomplete'
    rec.authority.unlink()
    assert sr.verify()['sessions'][0]['integrity'] == 'unverifiable'


def test_abnormal_exit_records_reason_restores_streams(tmp_path):
    stdout, stderr = sys.stdout, sys.stderr
    with pytest.raises(RuntimeError):
        with sr.execution([]) as rec:
            path = rec.path
            raise RuntimeError('synthetic worker failure')
    assert sys.stdout is stdout and sys.stderr is stderr and sr.ACTIVE.get() is None
    assert entries(path)[-1]['data']['reason'] == 'abnormal'
    assert any(e['action'] == 'exception' and e['data']['frames'] for e in entries(path))


def test_secrets_redacted_before_all_persistence(tmp_path, monkeypatch):
    secrets = ['example-env-secret', 'example-argv-secret', 'example-prompt-secret', 'example-field-secret']
    monkeypatch.setenv('OPENAI_API_KEY', secrets[0])
    with sr.execution(['--password', secrets[1]]) as rec:
        path = rec.path
        sr.read_response(lambda p: secrets[2], 'API key: ')
        rec.emit('structured', {'password':secrets[3], 'message':secrets[3]})
        print(' '.join(secrets))
        logging.getLogger('forensic_assistant.synthetic').warning('Authorization: Bearer synthetic-bearer')
        activity.append(rec.authority, 'synthetic', 'TEST', 'success', credentials={'key':secrets[0]}, message=secrets[1])
    for file in sr.app_root().rglob('*'):
        if file.is_file():
            raw = file.read_text(encoding='utf-8')
            assert all(secret not in raw for secret in secrets)
            assert 'synthetic-bearer' not in raw
    assert '<redacted>' in path.read_text()


def test_large_output_and_large_event_explicit_limits(tmp_path):
    with sr.execution([]) as rec:
        path = rec.path
        rec.output('é' * 100000)
        rec.emit('large', {'field': 'a' * 50000})
    rows = entries(path)
    gap = next(e['data'] for e in rows if e['action'] == 'capture_gap')
    assert gap['omitted_utf8_bytes'] == 200000 - sr.OUTPUT_BYTES
    assert any(e['data'].get('capture_gap') == 'event_payload_limit' for e in rows)
    assert path.stat().st_size < sr.SESSION_BYTES


@pytest.mark.parametrize('error', [PermissionError('denied'), OSError(28, 'full'), activity.AuditError('corrupt')])
def test_required_failure_before_action(tmp_path, monkeypatch, error):
    with sr.execution([]) as rec:
        def broken(*a, **k):raise error
        monkeypatch.setattr(activity, 'append', broken)
        changed = []
        with pytest.raises(activity.AuditError):
            sr.read_response(lambda p: 'y', 'Publish? [y/N]: ')
            changed.append(True)
        assert changed == [] and rec.broken


def test_ordinary_read_and_review_survive_capture_failure(tmp_path, monkeypatch):
    with sr.execution([]) as rec:
        rec.broken = True
        with sr.operation(SimpleNamespace(command='status')):
            print('read-only answer')
        with sr.operation(SimpleNamespace(command='workflow', workflow='audit-verify')):
            pass
        with pytest.raises(activity.AuditError):
            with sr.operation(SimpleNamespace(command='source')):
                pytest.fail('mutation admitted')


def test_replaced_case_and_invalid_copy_block(tmp_path):
    path = case(tmp_path)
    with sr.execution([]) as rec:
        rec.open(path)
        path.rename(path.with_suffix('.old'))
        path.write_bytes(b'not a database')
        with pytest.raises(activity.AuditError):rec.require()
        assert rec.broken


def test_threaded_capture_serialized(tmp_path):
    with sr.execution([]) as rec:
        path = rec.path
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda i: rec.emit('thread', {'number': i}), range(30)))
    assert sorted(e['data']['number'] for e in entries(path) if e['action']=='thread') == list(range(30))
    assert sr.verify()['valid']


def test_logical_output_pager_and_editor_boundaries(tmp_path, monkeypatch):
    from forensic_assistant.output import Output
    args = SimpleNamespace(command='status', page=True, no_color=True)
    monkeypatch.setattr('forensic_assistant.output.page', lambda *a: print('pager redraw excluded'))
    with sr.execution([]) as rec:
        path = rec.path
        out = Output(args)
        out.write('page content')
        out.finish();out.close()
        sr.imported('synthetic-editor.txt', b'edited document', external_editor=True)
    raw = path.read_text()
    assert raw.count('page content') == 1 and 'pager redraw excluded' not in raw
    row = next(e['data'] for e in entries(path) if e['action']=='document_import')
    assert row['sha256'] == hashlib.sha256(b'edited document').hexdigest()
    assert row['external_editor_keystrokes_captured'] is False


def test_raw_ai_review_excluded(tmp_path):
    with sr.execution([]) as rec:
        path = rec.path
        with sr.operation(SimpleNamespace(command='ai', raw=True)):
            print('raw-private-response')
    assert 'raw-private-response' not in path.read_text()
    assert 'raw_ai_debug_excluded' in path.read_text()


def test_cli_review_and_status_do_not_change_evidence(tmp_path, capsys):
    path = case(tmp_path)
    original = path.read_bytes()
    assert main(['--db', str(path), 'case', 'status']) == 0
    capsys.readouterr()
    assert main(['--db', str(path), 'audit', 'sessions', '--json']) == 0
    value = json.loads(capsys.readouterr().out)
    assert value['sessions'][0]['integrity'] == 'verified'
    assert main(['--db', str(path), 'audit', 'session', 'show', 'latest', '--json']) == 0
    assert json.loads(capsys.readouterr().out)['records']
    assert main(['--db', str(path), 'audit', 'verify']) == 0
    assert 'Activity chain: verified' in capsys.readouterr().out
    assert path.read_bytes() == original


def test_filters_and_parser(tmp_path):
    with sr.execution([]) as rec:
        rec.operation_id = 'synthetic-operation'
        rec.emit('diagnostic', dict(severity='ERROR', message='failure'))
        rec.emit('diagnostic', dict(severity='INFO', message='success'))
    result = sr.review(diagnostics=True, severity='ERROR', operation_id='synthetic-operation', since='2000-01-01T00:00:00Z')
    assert len(result['records']) == 1
    args = build_parser().parse_args(['audit','diagnostics','latest','--severity','ERROR','--limit','5'])
    assert args.workflow == 'audit-diagnostics' and args.limit == 5


def test_old_activity_bytes_untouched(tmp_path):
    path = case(tmp_path)
    activity.append(activity.sidecar(path), 'old', 'HISTORICAL', 'success')
    prefix = activity.sidecar(path).read_bytes()
    with sr.execution([]) as rec:rec.open(path)
    assert activity.sidecar(path).read_bytes().startswith(prefix)
    assert sr.verify(path)['valid']


def test_input_cancel_and_external_stream_boundary(tmp_path):
    with sr.execution([]) as rec:
        path = rec.path
        def cancel(p):raise KeyboardInterrupt
        with pytest.raises(KeyboardInterrupt):sr.read_response(cancel,'Question: ')
        rec.stream('password=', 'stdout')
        rec.stream('synthetic-password\n', 'stdout')
    assert any(e['action']=='input_cancelled' for e in entries(path))
    assert 'synthetic-password' not in path.read_text()


def test_copied_session_binding_never_extended(tmp_path):
    import shutil
    a, b = case(tmp_path), case(tmp_path, 'copied')
    with sr.execution([]) as rec:rec.open(a)
    shutil.copyfile(activity.sidecar(a), activity.sidecar(b))
    before = activity.sidecar(b).read_bytes()
    with sr.execution([]) as rec:
        rec.open(b)
        assert rec.broken and rec.path is None
        with pytest.raises(activity.AuditError):rec.require()
    assert activity.sidecar(b).read_bytes() == before


def test_capacity_failure_and_required_action(tmp_path, monkeypatch):
    with sr.execution([]) as rec:
        rec.size = sr.SESSION_BYTES
        rec.emit('synthetic')
        assert rec.broken
        with pytest.raises(activity.AuditError):rec.require()
    assert any(e['action']=='SESSION_CAPTURE_FAILURE' for e in entries(sr.locations()[1]))


def test_directory_quota_before_creation(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, 'MAX_FILES', 1)
    with sr.execution([]):pass
    count = len(list(sr.locations()[0].iterdir()))
    with sr.execution([]) as rec:
        assert rec.broken
        with pytest.raises(activity.AuditError):rec.require()
    assert len(list(sr.locations()[0].iterdir())) == count


def test_read_only_capture_failure_after_action_is_not_rollback(tmp_path, monkeypatch):
    with sr.execution([]) as rec:
        completed = []
        with sr.operation(SimpleNamespace(command='status')):
            completed.append(True)
            rec.broken = True
        assert completed == [True]
        assert sr.verify()['sessions'][0]['integrity'] == 'incomplete'


def test_invalid_case_does_not_attach_to_previous_case(tmp_path):
    valid = case(tmp_path)
    invalid = tmp_path / 'invalid.db'
    invalid.write_bytes(b'bad database')
    with sr.execution([]) as rec:
        rec.open(valid)
        rec.open(invalid)
        before = activity.sidecar(valid).read_bytes()
        assert rec.broken
        rec.emit('must not enter previous case')
        assert activity.sidecar(valid).read_bytes() == before


def test_verbose_diagnostics_and_worker_boundary(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCARD_AUDIT_LEVEL', 'DEBUG')
    from forensic_assistant.ai import provider_diagnostics
    monkeypatch.setattr(provider_diagnostics.diagnostics, 'append', lambda *a: None)
    with sr.execution([]) as rec:
        path = rec.path
        logging.getLogger('forensic_assistant.synthetic').debug('verbose detail')
        provider_diagnostics.record('openai', 'synthetic-model', 'provider_request', 'request_rejected')
    rows = entries(path)
    assert any(e['data'].get('severity')=='DEBUG' for e in rows)
    assert any(e['data'].get('component')=='ai.provider' for e in rows)
    assert any('parent-visible worker' in str(e['data']) for e in rows)


def test_parent_provider_boundary_fails_closed_without_request(tmp_path):
    from forensic_assistant.ai.backend import ModelBackend
    backend = object.__new__(ModelBackend)
    with sr.execution([]) as rec:
        rec.broken = True
        with pytest.raises(activity.AuditError):backend.prepare()
        with pytest.raises(activity.AuditError):backend._cloud_request([], {})


def test_credentials_at_output_limit_and_split_writes(tmp_path):
    secret = 'SYNTHETIC-CREDENTIAL'
    with sr.execution(['--token', secret]) as rec:
        path = rec.path
        rec.output('x' * (sr.OUTPUT_BYTES - 5) + secret)
    assert secret[:5] not in path.read_text()


def test_path_redirection_rejected(tmp_path):
    path = case(tmp_path)
    root, _ = sr.locations(path)
    root.parent.mkdir(parents=True)
    root.write_text('not a directory')
    with sr.execution([]) as rec:
        rec.open(path)
        assert rec.broken and rec.path is None


def test_session_review_does_not_recursively_capture(tmp_path):
    with sr.execution([]) as rec:
        path = rec.path
        with sr.operation(SimpleNamespace(command='workflow', workflow='audit-session')):
            print('previous transcript output')
    assert 'previous transcript output' not in path.read_text()
    assert 'audit_review_not_recursively_recorded' in path.read_text()

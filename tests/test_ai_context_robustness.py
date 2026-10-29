"""Deterministic context failures use disposable SQLite cases, never real evidence."""
from contextlib import closing
import json
import logging
import sqlite3
import time

import pytest

from forensic_assistant.interactive import ai_context as ctx
from forensic_assistant.interactive.advisory import AdvisoryError, SYSTEM
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from test_interactive_shell import case, Input
from test_ai_shell import model
from v2_fixtures import evtx_process


def sql_error(code):
    error = sqlite3.OperationalError('SECRET path/metadata')
    error.sqlite_errorcode = code
    return error


def test_real_lock_failure_retries_silently(tmp_path, monkeypatch, model, caplog, capsys):
    path = case(tmp_path)
    shell = Shell(State(None), Input(), no_color=True)
    shell.activate(path)
    before = path.read_bytes()
    lock = sqlite3.connect(path)
    lock.execute('BEGIN EXCLUSIVE')
    original = ctx.open_readonly
    attempts = []
    def open_case(*args, **kwargs):
        attempts.append(kwargs['deadline'])
        try:
            return original(*args, **kwargs)
        finally:
            if len(attempts) == 1:
                lock.rollback()
                lock.close()
    monkeypatch.setattr(ctx, 'open_readonly', open_case)
    capsys.readouterr()
    with caplog.at_level(logging.DEBUG, logger=ctx.__name__):
        shell.request_advice('inventory')
    assert len(attempts) == 2 and attempts[1] > attempts[0]
    assert len(model) == 1 and path.read_bytes() == before
    assert 'database_busy' in caplog.text and 'retry succeeded' in caplog.text
    assert 'retry' not in capsys.readouterr().out.lower()
    assert str(path) not in caplog.text
    shell.audit.end('test')


@pytest.mark.parametrize('code', [sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_BUSY | (2 << 8)])
def test_retry_at_most_once_then_fail_closed(tmp_path, monkeypatch, model, caplog, code):
    path = case(tmp_path)
    shell = Shell(State(None), Input(), no_color=True)
    shell.activate(path)
    before = path.read_bytes()
    attempts = []
    def fail(*args, **kwargs):
        attempts.append(1)
        raise sql_error(code)
    monkeypatch.setattr(ctx, 'open_readonly', fail)
    with caplog.at_level(logging.DEBUG, logger=ctx.__name__), pytest.raises(AdvisoryError) as failure:
        shell.request_advice('private request')
    assert len(attempts) == 2 and not model
    assert str(failure.value) == 'AI case context unavailable (database busy). No action was taken.'
    assert 'attempt=2 retry=False' in caplog.text
    assert all(secret not in caplog.text for secret in ('SECRET', str(path), 'private request'))
    assert path.read_bytes() == before
    shell.audit.end('test')


@pytest.mark.parametrize('target,error,reason', [
    ('check_structure', ValueError('SECRET'), 'case_validation'),
    ('investigation_capabilities', KeyError('SECRET'), 'command_catalog'),
    ('open_readonly', sqlite3.ProgrammingError('closed SECRET connection'), 'connection_or_programming'),
    ('open_readonly', sql_error(sqlite3.SQLITE_IOERR), 'database_read'),
    ('check_structure', sql_error(sqlite3.SQLITE_ERROR), 'query_failure'),
    ('check_structure', RuntimeError('SECRET'), 'unexpected_exception'),
    ('open_readonly', OSError('SECRET'), 'filesystem_read'),
])
def test_deterministic_failures_never_retry(tmp_path, monkeypatch, model, caplog, target, error, reason):
    path = case(tmp_path)
    shell = Shell(State(None), Input(), no_color=True)
    shell.activate(path)
    before = path.read_bytes()
    calls = []
    def fail(*args, **kwargs):
        calls.append(1)
        raise error
    monkeypatch.setattr(ctx, target, fail)
    with caplog.at_level(logging.DEBUG, logger=ctx.__name__), pytest.raises(AdvisoryError):
        shell.request_advice('question')
    assert len(calls) == 1 and not model and path.read_bytes() == before
    assert reason in caplog.text and 'retry=False' in caplog.text and 'SECRET' not in caplog.text
    shell.audit.end('test')


def test_query_retry_closes_first_connection_and_reads_new_snapshot(tmp_path, monkeypatch):
    path = case(tmp_path)
    original_open, original_check = ctx.open_readonly, ctx.check_structure
    connections = []
    def open_case(*args, **kwargs):
        if connections:
            with pytest.raises(sqlite3.ProgrammingError):
                connections[0].execute('SELECT 1')
            with closing(connect(path, existing_only=True)) as db:
                evtx_process(db)
        db = original_open(*args, **kwargs)
        connections.append(db)
        return db
    def check(db):
        original_check(db)
        if len(connections) == 1:
            raise sql_error(sqlite3.SQLITE_BUSY)
    monkeypatch.setattr(ctx, 'open_readonly', open_case)
    monkeypatch.setattr(ctx, 'check_structure', check)
    assert ctx.build_ai_case_context(path, 'Test')['artifact_inventory']['evtx'] == 1
    assert len(connections) == 2
    with pytest.raises(sqlite3.ProgrammingError):
        connections[1].execute('SELECT 1')


def test_real_read_deadline_and_unrelated_interrupt_classification(tmp_path, monkeypatch, caplog):
    path = case(tmp_path)
    original = ctx.open_readonly
    calls = []
    def open_case(path, deadline):
        calls.append(1)
        return original(path, deadline=time.monotonic() - 1)
    # Force the actual SQLite progress handler to interrupt a read at its deadline.
    monkeypatch.setattr(ctx, 'open_readonly', open_case)
    monkeypatch.setattr(ctx, 'BUILD_SECONDS', -1)
    with caplog.at_level(logging.DEBUG, logger=ctx.__name__), pytest.raises(ctx.ContextBuildError) as error:
        ctx.build_ai_case_context(path, 'Test')
    assert len(calls) == 2 and error.value.reason == 'read_deadline'
    unrelated = ctx._failure(sql_error(sqlite3.SQLITE_INTERRUPT), 'inventory', time.monotonic() + 100)
    assert not unrelated.retryable and unrelated.reason == 'query_failure'


def test_malformed_source_and_size_failure_are_private_and_not_retried(tmp_path, monkeypatch, caplog):
    path = case(tmp_path)
    with closing(connect(path, existing_only=True)) as db, db:
        sources.create(db, name='Private name')
    calls = []
    def malformed(*args):
        calls.append(1)
        return {'display_name': b'PRIVATE', 'hostname': None, 'username': None, 'volume_root': None}
    monkeypatch.setattr(ctx, 'current', malformed)
    with caplog.at_level(logging.DEBUG, logger=ctx.__name__), pytest.raises(ctx.ContextBuildError) as error:
        ctx.build_ai_case_context(path, 'Test')
    assert error.value.reason == 'source_metadata' and len(calls) == 1
    assert 'PRIVATE' not in caplog.text and 'Private name' not in caplog.text
    monkeypatch.undo()
    monkeypatch.setattr(ctx, 'MAX_CONTEXT_BYTES', 1)
    with pytest.raises(ctx.ContextBuildError) as error:
        ctx.build_ai_case_context(path, 'Test')
    assert error.value.reason == 'context_size' and not error.value.retryable


def test_concrete_guidance_keeps_unknown_ids_and_timestamps_as_placeholders():
    assert 'prefer the exact catalog usage with that value' in SYSTEM
    assert 'Use placeholders when IDs or timestamps are unknown; never fabricate them' in SYSTEM
    assert 'examiner must run recommendations manually' in SYSTEM

@pytest.mark.parametrize('reason,label', [
    ('read_deadline', 'context timeout'),
    ('case_validation', 'context validation failure'),
    ('source_metadata', 'source metadata validation failure'),
    ('context_size', 'context size limit'),
    ('query_failure', 'database query failure'),
    ('filesystem_read', 'database access failure'),
    ('unexpected_exception', 'controlled internal failure'),
])
def test_shell_preserves_only_safe_context_category(tmp_path, monkeypatch, model, reason, label):
    path = case(tmp_path)
    shell = Shell(State(None), Input(), no_color=True)
    shell.activate(path)
    def fail(*args):
        raise ctx.ContextBuildError(reason, 'inventory')
    monkeypatch.setattr(ctx, 'build_ai_case_context', fail)
    with pytest.raises(AdvisoryError) as error:
        shell.request_advice('Explain Windows Prefetch files.')
    assert str(error.value) == f'AI case context unavailable ({label}). No action was taken.'
    assert not model
    shell.audit.end('test')


def test_large_metadata_inventory_is_independent_of_run_history(tmp_path, monkeypatch, caplog, model):
    path = case(tmp_path)
    with closing(connect(path, existing_only=True)) as db, db:
        sid = sources.create(db, name='Synthetic source', hostname=None)
        for i in range(614):
            db.execute('INSERT INTO evidence_files VALUES (?,?,?)', (f'{i:064x}', 1, '2026-01-01'))
        for i in range(682):
            bid = f'batch-{i}'
            status = ('complete', 'partial', 'failed', 'unsupported')[i % 4]
            db.execute('INSERT INTO ingestion_batches VALUES (?,?,?,?,?,?,?)',
                       (bid, sid, '2026-01-01', '2026-01-01', 'SECRET_PATH', 'test', status))
            db.execute('INSERT INTO ingestion_runs(source_file,file_sha256,started_utc,status,batch_id) VALUES (?,?,?,?,?)',
                       ('SECRET_PATH', f'{i % 614:064x}', '2026-01-01', status, bid))
        db.execute("""WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10000)
            INSERT INTO evidence_records SELECT printf('SYNTHETIC:%d',x),
            CASE x%5 WHEN 0 THEN 'evtx' WHEN 1 THEN 'mft' WHEN 2 THEN 'prefetch' WHEN 3 THEN 'registry' ELSE 'browser' END,
            'synthetic',printf('%064x',x%614),'SECRET_PATH','{}',
            CASE x%2 WHEN 0 THEN 'HOST_CONFLICT_A' ELSE 'HOST_CONFLICT_B' END,
            NULL,'synthetic','1','1','[]','SECRET_RAW' FROM n""")
    before = path.read_bytes()
    queries = []
    original = ctx.open_readonly
    def traced(*args, **kwargs):
        db = original(*args, **kwargs)
        db.set_trace_callback(queries.append)
        return db
    monkeypatch.setattr(ctx, 'open_readonly', traced)
    # Context must not accidentally introduce expensive source summaries/fingerprints.
    def forbidden(*args, **kwargs):
        pytest.fail('Context attempted unrelated evidence aggregation')
    monkeypatch.setattr(sources, 'summary', forbidden)
    monkeypatch.setattr('forensic_assistant.semantic.documents.fingerprint', forbidden)
    with caplog.at_level(logging.DEBUG, logger=ctx.__name__):
        context = ctx.build_ai_case_context(path, 'Synthetic')
    assert context['artifact_inventory'] == dict.fromkeys(('evtx', 'mft', 'prefetch', 'registry', 'browser'), 2000)
    assert context['sources']['items'][0]['hostname'] is None
    encoded = json.dumps(context)
    assert len(encoded.encode()) < ctx.MAX_CONTEXT_BYTES
    assert not any(s in encoded + caplog.text for s in ('SECRET', 'HOST_CONFLICT', str(path)))
    reads = [q for q in queries if 'FROM evidence_records' in q]
    assert len(reads) == 5 and all(q.startswith('SELECT count(*)') for q in reads)
    assert not any('JOIN' in q.upper() and 'EVIDENCE_RECORDS' in q.upper() for q in queries)
    for stage in ('catalog', 'metadata', 'open', 'validation', 'inventory', 'sources', 'serialization', 'total'):
        assert f'AI context timing stage={stage} seconds=' in caplog.text
    from forensic_assistant.interactive import advisory
    assert advisory.advise(context, 'What forensic artifact categories are available in this case?') is advisory.INVENTORY_ADVICE
    assert not model
    advisory.advise(context, 'Explain the forensic significance of Windows Prefetch files.')
    assert len(model) == 1
    assert json.loads(model[0][0][1]['content'])['case_context'] == context
    assert path.read_bytes() == before


def test_reported_inventory_phrase_keeps_conservative_routing():
    from forensic_assistant.interactive.advisory import is_inventory_question
    from forensic_assistant.interactive.ai_routing import needs_investigation
    request = 'What forensic artifact categories are available in this case?'
    assert is_inventory_question(request)
    assert not needs_investigation(request)
    assert not is_inventory_question(request + ' Explain suspicious activity.')
    assert not needs_investigation('Explain the forensic significance of Windows Prefetch files.')
    assert needs_investigation('Did coreupdater.exe execute after loot.zip was downloaded?')

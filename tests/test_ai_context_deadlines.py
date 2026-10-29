"""Synthetic deadline/path checks; no provider network or protected cases."""
from contextlib import closing
import io
import json
import logging
import sqlite3
import threading
import time

import pytest
from forensic_assistant.database.db import connect
from forensic_assistant.interactive import ai_context as ctx
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant import terminal_activity
from test_interactive_shell import case, Input
from test_ai_shell import model


@pytest.fixture
def populated(tmp_path):
    path = case(tmp_path)
    with closing(connect(path)) as db, db:
        db.execute("INSERT INTO evidence_files VALUES (?,1,'synthetic')", ('a'*64,))
        db.execute("""WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100000)
            INSERT INTO evidence_records SELECT printf('SYNTHETIC:%d',x),'mft','synthetic',
            ?, 'synthetic','{}',NULL,NULL,'synthetic','1','1','[]','{}' FROM n""", ('a'*64,))
    return path


@pytest.mark.parametrize('where', ['catalog', 'open', 'inventory'])
@pytest.mark.parametrize('recover', [False, True])
def test_real_sqlite_interrupt_fresh_retry_and_closed_connections(populated, monkeypatch, caplog, where, recover):
    before = populated.read_bytes()
    now = [100.0]
    monkeypatch.setattr(ctx.time, 'monotonic', lambda: now[0])
    original_open, original_catalog = ctx.open_readonly, ctx.investigation_capabilities
    attempts, connections = [], []
    catalog_calls = []
    def catalog():
        catalog_calls.append(1)
        if where == 'catalog' and (not recover or len(catalog_calls) == 1):
            now[0] += 4
        return original_catalog()
    def opened(path, deadline):
        attempts.append(deadline)
        slow = not recover or len(attempts) == 1
        if where == 'open' and slow:
            now[0] += 4
        db = original_open(path, deadline=deadline)
        connections.append(db)
        delayed = False
        def trace(sql):
            nonlocal delayed
            if where == 'inventory' and slow and not delayed and sql.startswith('SELECT count(*) FROM evidence_records'):
                delayed = True
                now[0] += 4
        db.set_trace_callback(trace)
        return db
    monkeypatch.setattr(ctx, 'investigation_capabilities', catalog)
    monkeypatch.setattr(ctx, 'open_readonly', opened)
    with caplog.at_level(logging.DEBUG, logger=ctx.__name__):
        if recover:
            assert ctx.build_ai_case_context(populated, 'Synthetic')['artifact_inventory']['mft'] == 100000
        else:
            with pytest.raises(ctx.ContextBuildError) as error:
                ctx.build_ai_case_context(populated, 'Synthetic')
            assert error.value.reason == 'read_deadline'
            assert error.value.sqlite_code == sqlite3.SQLITE_INTERRUPT
    assert attempts == [103.0, 107.0]
    assert len(connections) == 2
    for db in connections:
        with pytest.raises(sqlite3.ProgrammingError):
            db.execute('SELECT 1')
    assert 'deadline_exceeded=True' in caplog.text
    assert ('retry succeeded' in caplog.text) is recover
    assert ('attempt=2 retry=False' in caplog.text) is not recover
    if where == 'catalog':
        assert 'phase_start stage=open remaining_seconds=0.000000 deadline_exceeded=True' in caplog.text
    assert populated.read_bytes() == before


def test_completed_small_operations_do_not_invent_interrupts(populated, monkeypatch, caplog):
    # There is no unconditional post-query deadline exception. A genuine SQLite
    # interruption is required; expiration after the final read is not relabeled.
    original = ctx.json.dumps
    now = [100.0]
    monkeypatch.setattr(ctx.time, 'monotonic', lambda: now[0])
    def serialized(*args, **kwargs):
        now[0] += 4
        return original(*args, **kwargs)
    monkeypatch.setattr(ctx.json, 'dumps', serialized)
    with caplog.at_level(logging.DEBUG, logger=ctx.__name__):
        assert ctx.build_ai_case_context(populated, 'Synthetic')['artifact_inventory']['mft'] == 100000
    assert 'deadline_exceeded=True' in caplog.text
    assert 'AI context failure' not in caplog.text


def test_direct_and_shell_equivalence_with_active_indicator(populated, monkeypatch, model, caplog):
    shell = Shell(State(None), Input(), no_color=True)
    shell.activate(populated, announce=False)
    before = populated.read_bytes()
    calls, threads, indicators = [], [], []
    original = ctx.build_ai_case_context
    def build(path, label):
        calls.append((path, label, threading.get_ident()))
        return original(path, label)
    monkeypatch.setattr(ctx, 'build_ai_case_context', build)
    class Indicator(terminal_activity.ActivityIndicator):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs, stream=io.StringIO(), delay=0)
            self.active = True
            indicators.append(self)
        def _animate(self):
            threads.append(threading.get_ident())
            super()._animate()
    monkeypatch.setattr(terminal_activity, 'ActivityIndicator', Indicator)
    measurements = {}
    with caplog.at_level(logging.DEBUG, logger=ctx.__name__):
        for route in ('direct', 'interactive'):
            caplog.clear()
            if route == 'direct':
                direct = ctx.build_ai_case_context(shell.active, shell.case_label)
            else:
                shell.request_advice('Explain the forensic significance of Windows Prefetch files.')
            timings = {}
            for record in caplog.records:
                message = record.getMessage()
                if message.startswith('AI context timing stage='):
                    stage, seconds = message.split('stage=')[1].split(' seconds=')
                    timings[stage] = float(seconds)
            measurements[route] = timings
            assert sum('AI context attempt=' in r.getMessage() for r in caplog.records) == 1
    assert calls[0] == calls[1]
    assert calls[0][2] == threading.get_ident()
    assert threads and all(t != threading.get_ident() for t in threads)
    assert all(i._thread is None for i in indicators)
    assert len(model) == 1
    assert json.loads(model[0][0][1]['content'])['case_context'] == direct
    shell.request_advice('What forensic artifact categories are available in this case?')
    assert len(model) == 1
    assert populated.read_bytes() == before
    shell.audit.end('test')
    print('SYNTHETIC_CONTEXT_TIMINGS ' + json.dumps(measurements))

@pytest.mark.parametrize('cancel', [False, True])
def test_source_boundary_timeout_or_cancellation_closes_case(populated, monkeypatch, caplog, cancel):
    from forensic_assistant.database import sources
    with closing(connect(populated)) as db, db:
        sources.create(db, name='Synthetic')
    before = populated.read_bytes()
    now = [100.0]
    monkeypatch.setattr(ctx.time, 'monotonic', lambda: now[0])
    original_open = ctx.open_readonly
    connections = []
    def opened(*args, **kwargs):
        db = original_open(*args, **kwargs)
        connections.append(db)
        return db
    def current(db, sid):
        if cancel:
            raise KeyboardInterrupt()
        now[0] += 4
        # Actual SQLite progress-handler cancellation within source processing.
        db.execute('WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10000) SELECT sum(x) FROM n').fetchone()
        pytest.fail('Expired SQLite query was not interrupted')
    monkeypatch.setattr(ctx, 'open_readonly', opened)
    monkeypatch.setattr(ctx, 'current', current)
    with caplog.at_level(logging.DEBUG, logger=ctx.__name__):
        with pytest.raises(KeyboardInterrupt if cancel else ctx.ContextBuildError) as error:
            ctx.build_ai_case_context(populated, 'Synthetic')
    if not cancel:
        assert error.value.reason == 'read_deadline'
        assert error.value.stage == 'sources'
    assert len(connections) == (1 if cancel else 2)
    for db in connections:
        with pytest.raises(sqlite3.ProgrammingError):
            db.execute('SELECT 1')
    assert populated.read_bytes() == before

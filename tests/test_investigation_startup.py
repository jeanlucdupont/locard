"""Startup diagnostics, budgets and byte-exact fingerprint equivalence."""
import logging
import sqlite3
import time

import pytest

from forensic_assistant.investigation_ai import controller
from forensic_assistant.investigation_ai.diagnostics import Profile, record
from forensic_assistant.investigation_ai.runner import WorkerError
from forensic_assistant.investigation_ai.state import Budget
from forensic_assistant.semantic.documents import fingerprint
from fingerprint_reference import fingerprint as original
from test_investigation_assessment import RecordingWorker
from test_v4_controller import Scripted, final
from test_v4_worker import make_case, config


@pytest.mark.parametrize('version', [3, 4, 5])
def test_fingerprint_exact_framing_types_chunks_and_mutation(version):
    db = sqlite3.connect(':memory:')
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA user_version=' + str(version))
    db.execute('CREATE TABLE "odd""table"(a,b,c,d,e,f)')
    for n in (0, 1, 65535, 65536, 65537, 131073):
        db.execute('INSERT INTO "odd""table" VALUES(?,?,?,?,?,?)',
                   (None, -(2**63), 1.23456789012345, '漢\x00é' * n, b'\x00\xff' * n, ''))
    before = fingerprint(db)
    assert before == original(db) == fingerprint(db)
    db.execute('UPDATE "odd""table" SET a=? WHERE rowid=1', ('changed',))
    assert fingerprint(db) == original(db) != before
    db.close()


def test_fingerprint_streams_rows_not_whole_case():
    class Rows:
        def __init__(self, cursor, table_scan=False):
            self.cursor, self.table_scan = cursor, table_scan
        def __iter__(self): return iter(self.cursor)
        def fetchone(self): return self.cursor.fetchone()
        def fetchall(self):
            assert not self.table_scan, 'evidence materialized globally'
            return self.cursor.fetchall()
    class Connection:
        def __init__(self, db): self.db = db
        def execute(self, sql, args=()):
            return Rows(self.db.execute(sql, args), sql.startswith('SELECT rowid,'))
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE records(a,b)')
    db.executemany('INSERT INTO records VALUES(?,?)', ((i, 'synthetic') for i in range(10000)))
    assert fingerprint(Connection(db)) == original(db)
    other = sqlite3.connect(':memory:')
    assert fingerprint(other) != fingerprint(db)  # no cross-case digest caching
    db.close(); other.close()


@pytest.mark.parametrize('stage,timeout,expected', [
    ('fingerprint', True, 'STARTUP_TIMEOUT'),
    ('fingerprint', False, 'FINGERPRINT_FAILURE'),
    ('initial_retrieval', False, 'INITIAL_RETRIEVAL_FAILURE'),
    ('worker_start', False, 'WORKER_START_FAILURE'),
])
def test_startup_failure_never_invokes_model(tmp_path, stage, timeout, expected):
    class Failed(RecordingWorker):
        def __init__(self, cfg):
            if stage == 'worker_start': raise WorkerError('synthetic', stage=stage)
            super().__init__(cfg)
        def call(self, *a, **kw):
            raise WorkerError('synthetic', stage=stage, timed_out=timeout)
    client = Scripted([])
    result = controller.run({}, 'Inspect', tmp_path / 'runs', worker_factory=Failed, client=client)
    assert result['termination'] == expected
    assert result['evidence_fingerprint'] is None
    assert not client.calls
    assert result['state']['accepted_calls'] == result['state']['requested_calls'] == 0


def test_initial_request_uses_overall_remaining_time(tmp_path):
    seen = []
    class Measured(RecordingWorker):
        def call(self, name, *a, **kw):
            seen.append((name, kw['seconds']))
            return super().call(name, *a, **kw)
    result = controller.run({}, 'Inspect', tmp_path / 'runs', worker_factory=Measured,
                            budget=Budget(seconds=200), client=Scripted([final]), dry_run=True)
    assert 45 < seen[0][1] <= 200
    assert all(45 < seconds <= 200 for name, seconds in seen if name == 'check')
    assert all(seconds <= 45 for name, seconds in seen if name not in ('initial', 'check'))
    assert result['state']['accepted_calls'] == 0


def test_real_startup_diagnostics_are_content_free(tmp_path, caplog):
    path = tmp_path / 'private-case.db'
    make_case(path)
    with caplog.at_level(logging.DEBUG, logger='forensic_assistant.investigation_ai'):
        result = controller.run(config(path), 'PowerShell confidential question', tmp_path / 'runs',
                                client=Scripted([final]), dry_run=True)
    assert result['evidence_fingerprint'] and result['state']['accepted_calls'] == 0
    for phase in ('audit_init','transcript_init','worker_start','database_open','schema_validation',
                  'fingerprint','initial_retrieval','inventory','source_hydration','exposure','pre_model'):
        assert 'stage='+phase in caplog.text
    for secret in ('private-case', 'confidential question', 'powershell.exe', 'EVTX:'):
        assert secret not in caplog.text
    assert 'remaining=' in caplog.text and 'elapsed=' in caplog.text


def test_diagnostics_validate_frames_and_report_deadline():
    messages=[]
    profile=Profile(time.monotonic()-1, messages.append)
    with pytest.raises(ValueError), profile.phase('fingerprint'):
        raise ValueError('sensitive evidence')
    assert messages[-1]['event']=='timeout'
    assert messages[-1]['remaining']==0
    assert 'sensitive' not in str(messages)
    for bad in ({'stage':'evidence secret'}, dict(messages[-1], seconds=float('nan'))):
        with pytest.raises(ValueError): record(bad)

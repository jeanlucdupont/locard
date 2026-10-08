"""Schema 5 is explicit, additive, and separates browser record provenance."""
from contextlib import closing
import sqlite3
import pytest
from forensic_assistant.database import browser, migrations, sources
from forensic_assistant.database.db import connect, now, register_source
from forensic_assistant.artifacts.context import effective_context
from forensic_assistant.artifacts.storage import base_record
from forensic_assistant.database.artifacts import register
from forensic_assistant.interactive.case import validate
from forensic_assistant.semantic.documents import fingerprint


def schema4(path):
    from test_sources_model import connect as legacy
    with closing(legacy(path)) as db:
        with db:
            sources.upgrade4(db)
            register_source(db, 'a' * 64, 10, 'synthetic.pf')
            register(db, dict(base_record('PF:old', 'prefetch', 'prefetch', {}),
                              file_sha256='a' * 64, source_file='synthetic.pf'))


def test_explicit_upgrade_preserves_old_rows_and_backup(tmp_path):
    path = tmp_path / 'case.db'
    schema4(path)
    with closing(connect(path)) as db:
        before = fingerprint(db)
        record = tuple(db.execute('SELECT * FROM evidence_records').fetchone())
        assert db.execute('PRAGMA user_version').fetchone()[0] == 4
        with pytest.raises(ValueError, match='explicitly'):
            browser.require5(db)
        assert fingerprint(db) == before
    result = migrations.migrate(path)
    with closing(connect(result['backup'])) as backup:
        assert fingerprint(backup) == before
    with closing(connect(path)) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 5
        assert tuple(db.execute('SELECT * FROM evidence_records').fetchone()) == record
        assert not db.execute('SELECT * FROM browser_record_occurrences').fetchone()
        assert not db.execute('PRAGMA foreign_key_check').fetchone()
    assert validate(path) == path
    assert migrations.migrate(path)['status'] == 'current'


def test_schema5_upgrade_failure_is_atomic(tmp_path, monkeypatch):
    path = tmp_path / 'case.db'
    schema4(path)
    with closing(connect(path)) as db:
        before = fingerprint(db)
    def fail(db):
        db.execute(browser.DDL[0])
        raise ValueError('injected migration failure')
    monkeypatch.setattr(browser, 'upgrade5', fail)
    with pytest.raises(ValueError, match='rolled back'):
        migrations.migrate(path)
    with closing(connect(path)) as db:
        assert fingerprint(db) == before


def test_browser_occurrences_do_not_inherit_file_membership():
    with closing(connect(':memory:')) as db:
        sha = 'a' * 64
        with db:
            register_source(db, sha, 10, 'History')
            pairs = [('chrome', 'Default', 'chrome-host'), ('edge', 'Profile 1', 'edge-host')]
            for product, profile, host in pairs:
                sid = sources.create(db, hostname=host, username=product + '-user')
                batch = sources.identifier('batch')
                db.execute('INSERT INTO ingestion_batches VALUES (?,?,?,?,?,?,?)',
                           (batch, sid, now(), now(), 'History', 'ingest-browser', 'complete'))
                run = db.execute('INSERT INTO ingestion_runs(source_file,file_sha256,started_utc,status,batch_id) VALUES (?,?,?,?,?)',
                                 ('History', sha, now(), 'complete', batch)).lastrowid
                ctx = browser.context_id(sha, product, profile)
                eid = 'BROWSER:' + product
                db.execute('INSERT INTO browser_contexts VALUES (?,?,?,?,?,?)', (ctx, sha, product, profile, sha, '{}'))
                record = dict(base_record(eid, 'browser', 'browser_visit', {}), file_sha256=sha, source_file='History')
                register(db, record)
                db.execute('INSERT INTO browser_record_occurrences VALUES (?,?,?)', (eid, ctx, run))
                context = effective_context(db, record)
                assert context['hostname'] == host
                assert context['source_ids'] == [sid]
            for product, profile, host in pairs:
                record = dict(db.execute('SELECT * FROM evidence_records WHERE evidence_id=?', ('BROWSER:' + product,)).fetchone())
                assert effective_context(db, record)['hostname'] == host
        assert not db.execute('PRAGMA foreign_key_check').fetchone()

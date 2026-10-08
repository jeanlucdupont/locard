"""Schema 5 is explicit, additive, and separates browser record provenance."""
from contextlib import closing
import pytest
from forensic_assistant.database import browser, sources
from forensic_assistant.database.db import connect, now, register_source
from forensic_assistant.artifacts.context import effective_context
from forensic_assistant.artifacts.storage import base_record
from forensic_assistant.database.artifacts import register
from forensic_assistant.interactive.case import validate
from forensic_assistant.semantic.documents import fingerprint


def schema4(path):
    from schema_fixtures import legacy
    with closing(legacy(path, version=4)) as db:
        with db:
            register_source(db, 'a' * 64, 10, 'synthetic.pf')
            register(db, dict(base_record('PF:old', 'prefetch', 'prefetch', {}),
                              file_sha256='a' * 64, source_file='synthetic.pf'))


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


def test_schema4_read_does_not_change_evidence_or_schema(tmp_path):
    path = tmp_path / 'case.db'
    schema4(path)
    with closing(connect(path)) as db:
        before = fingerprint(db)
        with pytest.raises(ValueError, match='requires schema 5'):
            browser.require5(db)
    assert validate(path) == path
    with closing(connect(path)) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 4
        assert fingerprint(db) == before
        assert db.execute('SELECT evidence_id FROM evidence_records').fetchone()[0] == 'PF:old'

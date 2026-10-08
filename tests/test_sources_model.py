"""Source revisions and retrospective membership preserve evidence identity."""
from contextlib import closing
from forensic_assistant.database.db import connect, register_source
from forensic_assistant.database import sources
from forensic_assistant.semantic.documents import fingerprint


def test_revision_history_and_unassigned_runs():
    with closing(connect(':memory:')) as db:
        with db:
            register_source(db, 'a' * 64, 1, 'synthetic.pf')
            db.execute("INSERT INTO ingestion_runs(source_file,started_utc,status) VALUES ('synthetic.pf','2020','complete')")
        before = [tuple(r) for r in db.execute('SELECT * FROM evidence_files')]
        assert db.execute('SELECT batch_id FROM ingestion_runs').fetchone()[0] is None
        assert db.execute('SELECT count(*) FROM sources').fetchone()[0] == 0
        with db:
            sid = sources.create(db, automatic=True)
        first = sources.current(db, sid)
        assert first['hostname'] is None and first['creation_basis'] == 'automatic'
        digest = fingerprint(db)
        with db:
            sources.update(db, sid, hostname='PC01')
        with db:
            sources.update(db, sid, hostname='WS01', username='analyst', volume_root='c:', display_name='Workstation')
        assert sources.current(db, sid)['hostname'] == 'ws01'
        history = list(db.execute('SELECT * FROM source_assertions ORDER BY assertion_id'))
        assert len(history) == 3 and history[2]['supersedes'] == history[1]['assertion_id']
        assert history[1]['hostname'] == 'pc01' and fingerprint(db) != digest
        with db:
            sources.assign(db, sid, ['a' * 64], reason='Explicit synthetic selection')
        assert before == [tuple(r) for r in db.execute('SELECT * FROM evidence_files')]
        assert sources.memberships(db, 'a' * 64)[0]['source_id'] == sid
        assert db.execute('SELECT count(*) FROM ingestion_batches').fetchone()[0] == 0


def test_multiple_sources_keep_file_identity():
    with closing(connect(':memory:')) as db:
        with db:
            register_source(db, 'b' * 64, 1, 'synthetic.pf')
            a = sources.create(db, name='Same label', hostname='host-a')
            b = sources.create(db, name='Same label', hostname='host-b')
            sources.assign(db, a, ['b' * 64], reason='Selection A')
            sources.assign(db, b, ['b' * 64], reason='Selection B')
        assert a != b and len(sources.memberships(db, 'b' * 64)) == 2
        assert db.execute('SELECT count(*) FROM evidence_files').fetchone()[0] == 1

"""Integrity, failure and provenance boundary regression tests for browsers."""
from contextlib import closing
from pathlib import Path
import sqlite3
import pytest
from forensic_assistant.artifacts import browser
from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.artifacts.worker import run
from forensic_assistant.database.db import connect, now
from forensic_assistant.database import sources
from forensic_assistant.retrieval.evidence import EvidenceQueries
from test_browser_parser import history
from test_browser_integration import ingest


def batch(db):
    with db:
        sid = sources.create(db, hostname='host-a')
        bid = sources.identifier('batch')
        db.execute('INSERT INTO ingestion_batches VALUES (?,?,?,?,?,?,?)', (bid, sid, now(), None, 'History', 'ingest-browser', 'running'))
    return bid


def local_runner(kind, path, sha, stage, options, timeout):
    return run(kind, path, sha, stage, options)


def test_legacy_download_epoch_refused(tmp_path):
    path = tmp_path / 'History'
    with closing(history(path)) as db:
        db.executescript('DROP TABLE downloads; CREATE TABLE downloads(id INTEGER PRIMARY KEY,full_path TEXT,start_time INTEGER); INSERT INTO downloads VALUES(1,\'C:\\example.exe\',1577836800);')
    with closing(connect(':memory:')) as db:
        result = ingest_artifact(db, path, 'browser', browser_product='chrome', profile='Default', batch_id=batch(db), runner=local_runner)
        assert result['status'] == 'failed' and result['inserted'] == 0
        assert 'epoch' in db.execute('SELECT message FROM ingestion_errors').fetchone()[0]


@pytest.mark.parametrize('kind', ['corrupt', 'missing-schema', 'rollback-journal'])
def test_bad_input_records_failed_run_without_evidence(tmp_path, kind):
    path = tmp_path / 'History'
    if kind == 'corrupt':
        path.write_bytes(b'not sqlite')
    elif kind == 'missing-schema':
        with closing(sqlite3.connect(path)) as db:
            db.execute('CREATE TABLE unrelated(id INTEGER PRIMARY KEY)')
    else:
        history(path).close()
        Path(str(path)+'-journal').write_bytes(b'synthetic unfinished journal')
    before = path.read_bytes()
    with closing(connect(':memory:')) as db:
        result = ingest_artifact(db, path, 'browser', browser_product='edge', profile='Profile 1', batch_id=batch(db), runner=local_runner)
        assert result['status'] == 'failed' and result['inserted'] == 0
        assert db.execute('SELECT status FROM ingestion_runs').fetchone()[0] == 'failed'
        assert db.execute('SELECT count(*) FROM browser_record_occurrences').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 0
    assert path.read_bytes() == before


def test_changed_source_rejects_all_staged_records(tmp_path):
    path = tmp_path / 'History'
    history(path).close()
    def changed(*args):
        result = local_runner(*args)
        # Deliberate mutation of a disposable synthetic fixture only.
        with path.open('ab') as output:
            output.write(b'changed')
        return result
    with closing(connect(':memory:')) as db:
        result = ingest_artifact(db, path, 'browser', browser_product='chrome', profile='Default', batch_id=batch(db), runner=changed)
        assert result['status'] == 'changed' and result['inserted'] == 0
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM browser_record_occurrences').fetchone()[0] == 0


def test_cancelled_browser_run_keeps_previous_committed_evidence(tmp_path):
    path = tmp_path / 'History'
    history(path).close()
    with closing(connect(':memory:')) as db:
        assert ingest(db, path)['inserted'] == 2
        def cancel(*args):
            raise KeyboardInterrupt
        with pytest.raises(KeyboardInterrupt):
            ingest_artifact(db, path, 'browser', browser_product='edge', profile='Profile 1', batch_id=batch(db), runner=cancel)
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 2
        assert db.execute('SELECT status FROM ingestion_runs ORDER BY id DESC LIMIT 1').fetchone()[0] == 'interrupted'


def test_file_assignment_cannot_reassign_browser_context(tmp_path):
    path = tmp_path / 'History'
    history(path).close()
    with closing(connect(':memory:')) as db:
        ingest(db, path)
        records = EvidenceQueries(db).search(artifact='browser').records
        sid = records[0]['context']['source_ids'][0]
        with db:
            other = sources.create(db, hostname='other-host')
            sources.assign(db, other, [records[0]['file_sha256']], reason='Synthetic file-level assignment')
        assert EvidenceQueries(db).search(source_id=other).total == 0
        assert sources.summary(db, other)['evidence_count'] == 0
        assert EvidenceQueries(db).search(hostname='other-host').total == 0
        with db:
            sources.update(db, sid, hostname='updated-host')
        assert EvidenceQueries(db).search(hostname='updated-host', strict_host=True).total == 2
        # A new invocation without --source must not silently reuse this source.
        ingest(db, path, host='host-b')
        record = EvidenceQueries(db).search(artifact='browser', limit=1).records[0]
        assert record['host_key'] is None and len(record['context']['source_ids']) == 2


def test_browser_query_does_not_query_each_url_or_run(tmp_path):
    path = tmp_path / 'History'
    history(path).close()
    with closing(connect(':memory:')) as db:
        ingest(db, path)
        first = EvidenceQueries(db).search(artifact='browser', evidence_kind='browser_download').records[0]
        sid = first['context']['source_ids'][0]
        statements = []
        db.set_trace_callback(statements.append)
        EvidenceQueries(db).search(artifact='browser', evidence_kind='browser_download')
        count = len(statements)
        db.set_trace_callback(None)
        ingest(db, path, source=sid)
        statements.clear()
        db.set_trace_callback(statements.append)
        found = EvidenceQueries(db).search(artifact='browser', evidence_kind='browser_download').records[0]
        assert len(found['context']['browser_occurrences']) == 2
        assert len(statements) == count  # More runs/chain entries add no query loop.
        assert not any('downloads_url_chains' in statement for statement in statements)


def test_browser_states_and_url_case_are_not_inferred(tmp_path):
    path = tmp_path / 'History'
    with closing(history(path)) as db:
        with db:
            db.execute('UPDATE downloads SET state=99,danger_type=123,end_time=0')
            db.execute('UPDATE urls SET url=?', ('https://example.com/Case',))
    with closing(connect(':memory:')) as db:
        ingest(db, path)
        query = EvidenceQueries(db)
        record = query.search(artifact='browser', evidence_kind='browser_download').records[0]
        assert record['detail']['state'] == 99 and record['detail']['state_name'] == 'unknown'
        assert record['detail']['danger_type'] == 123
        assert next(t for t in record['timestamps'] if t['slot'] == 'Browser.DownloadEnd')['timestamp_utc'] is None
        assert query.search(url='https://example.com/Case').total == 1
        assert query.search(url='https://example.com/case').total == 0
        assert query.search(profile='default').total == 0


def test_wal_change_creates_distinct_snapshot_and_records(tmp_path):
    path = tmp_path / 'History'
    with closing(history(path, wal=True)) as original, closing(connect(':memory:')) as db:
        first = ingest(db, path)
        record = EvidenceQueries(db).search(artifact='browser', limit=1).records[0]
        sid = record['context']['source_ids'][0]
        first_context = record['detail']['context_id']
        first_main_hash = record['file_sha256']
        with original:
            original.execute('UPDATE urls SET title=?', ('Updated synthetic title',))
        second = ingest(db, path, source=sid)
        assert first['inserted'] == second['inserted'] == 2
        contexts = list(db.execute('SELECT context_id,main_file_sha256 FROM browser_contexts'))
        assert len(contexts) == 2
        assert {r['main_file_sha256'] for r in contexts} == {first_main_hash}
        assert len({r['context_id'] for r in contexts}) == 2


def test_parser_primary_key_is_not_composite(tmp_path):
    path = tmp_path / 'History'
    with closing(history(path)) as db:
        db.executescript('DROP TABLE visits; CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER,PRIMARY KEY(id,url)); INSERT INTO visits VALUES(1,1,1); INSERT INTO visits VALUES(1,2,2);')
    options = browser.snapshot(path, tmp_path / 'copy', 'chrome', 'Default')
    with pytest.raises(ValueError, match='primary row identity'):
        list(browser.parse(tmp_path / 'copy', options['manifest']['']['sha256'], **options))


def test_same_context_new_path_preserves_first_record_path_and_all_occurrences(tmp_path):
    import shutil
    path = tmp_path / 'History'
    other = tmp_path / 'History-copy'
    history(path).close()
    shutil.copyfile(path, other)
    with closing(connect(':memory:')) as db:
        ingest(db, path)
        first = EvidenceQueries(db).search(artifact='browser', limit=1).records[0]
        sid = first['context']['source_ids'][0]
        result = ingest(db, other, source=sid)
        assert result['inserted'] == 0 and result['duplicates'] == 2
        record = EvidenceQueries(db).search(artifact='browser', limit=1).records[0]
        assert record['source_file'] == str(path.resolve())
        assert set(record['source_locations']) == {str(path.resolve()), str(other.resolve())}
        assert {o['source_file'] for o in record['context']['browser_occurrences']} == set(record['source_locations'])
        assert {o['run_id'] for o in record['context']['browser_occurrences']} == {1, 2}


def test_file_assignment_preview_excludes_browser_records(tmp_path):
    from forensic_assistant.database.source_selection import preview
    path = tmp_path / 'History'
    history(path).close()
    with closing(connect(':memory:')) as db:
        ingest(db, path)
        record = EvidenceQueries(db).search(artifact='browser', limit=1).records[0]
        with db:
            sid = sources.create(db, hostname='unrelated')
        selection = dict(file_hashes=[record['file_sha256']], paths=[], explicit_hashes=[record['file_sha256']], matched_locations=[])
        shown = preview(db, sid, selection, 'Synthetic preview')
        assert shown['evidence_records'] == 0
        assert shown['browser_records_excluded'] == 2
        assert shown['artifact_types'] == {}
        assert any('browser records excluded' in message for message in shown['limitations'])

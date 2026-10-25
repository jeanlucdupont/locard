"""Private index reduction must not change evidence or published case schemas."""
import hashlib
import sqlite3

import pytest

from forensic_assistant.artifacts import worker
from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.database import db as database
from forensic_assistant.database.artifacts import MFT_STAGE_QUERY_INDEXES
from forensic_assistant.retrieval.evidence import EvidenceQueries, get_evidence
from v2_fixtures import mft_file, mft_record


def indexes(db):
    return dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='index'"))


def contents(db):
    tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    return {t: sorted([tuple(r) for r in db.execute(f'SELECT * FROM "{t}"')], key=repr) for t in tables}


def test_only_reviewed_secondary_indexes_omitted(tmp_path):
    normal = database.connect(tmp_path / 'case.db')
    stage = database.connect(tmp_path / 'stage.db', _mft_stage=True)
    assert MFT_STAGE_QUERY_INDEXES == {
        'artifact_time', 'evidence_source', 'evidence_type',
        'mft_parent', 'object_path', 'object_basename',
    }
    omitted = MFT_STAGE_QUERY_INDEXES | {'sqlite_autoindex_evidence_timestamps_1'}
    assert indexes(stage) == {n: sql for n, sql in indexes(normal).items() if n not in omitted}
    normal_tables = dict(normal.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"))
    stage_tables = dict(stage.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"))
    normal_tables['evidence_timestamps'] += ' WITHOUT ROWID'
    assert stage_tables == normal_tables
    assert list(normal.execute('PRAGMA table_info(evidence_timestamps)')) == list(stage.execute('PRAGMA table_info(evidence_timestamps)'))
    assert list(normal.execute('PRAGMA foreign_key_list(evidence_timestamps)')) == list(stage.execute('PRAGMA foreign_key_list(evidence_timestamps)'))
    assert stage.execute('PRAGMA foreign_keys').fetchone()[0] == 1
    assert stage.execute('PRAGMA user_version').fetchone()[0] == normal.execute('PRAGMA user_version').fetchone()[0]
    for name in MFT_STAGE_QUERY_INDEXES:
        table = normal.execute('SELECT tbl_name FROM sqlite_master WHERE name=?', (name,)).fetchone()[0]
        row = next(r for r in normal.execute(f'PRAGMA index_list({table})') if r[1] == name)
        assert row[2:4] == (0, 'c')  # Not a UNIQUE/PRIMARY KEY index.
    normal.close()
    stage.close()


@pytest.mark.parametrize('existing_only', [False, True])
def test_private_mode_cannot_modify_existing_case(tmp_path, existing_only):
    path = tmp_path / 'case.db'
    db = database.connect(path)
    original = indexes(db)
    db.close()
    before = path.read_bytes()
    with pytest.raises(ValueError, match='requires a new database'):
        database.connect(path, existing_only=existing_only, _mft_stage=True)
    assert path.read_bytes() == before
    db = database.connect(path)
    assert indexes(db) == original
    db.close()


def test_reduced_stage_retains_foreign_keys_and_uniqueness(tmp_path):
    db = database.connect(tmp_path / 'stage.db', _mft_stage=True)
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO mft_names VALUES ('missing','slot','name',1,5,1,NULL,'unresolved')")
    db.execute("INSERT INTO evidence_files VALUES ('hash',1,'time')")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO evidence_files VALUES ('hash',2,'time')")
    db.close()


def test_private_mode_rejects_unversioned_nonempty_database(tmp_path):
    path = tmp_path / 'unversioned.db'
    db = sqlite3.connect(path)
    db.execute('CREATE TABLE analyst_data (value TEXT)')
    db.close()
    before = path.read_bytes()
    with pytest.raises(ValueError, match='Unversioned nonempty'):
        database.connect(path, _mft_stage=True)
    assert path.read_bytes() == before


def test_complete_staged_content_matches_full_index_model(tmp_path, monkeypatch):
    source = mft_file(tmp_path / '$MFT', names=('long-file.exe', 'LONGFI~1.EXE'))
    source.write_bytes(source.read_bytes()
                      + mft_record(7, names=('LongDirectory', 'LONGDI~1'), directory=True)
                      + mft_record(8, parent=7, names=('child.exe', 'CHILD~1.EXE'))
                      + mft_record(9, parent=7, parent_sequence=99)
                      + b'BAD!' + bytes(1020) + bytes(1024) + b'FILEtruncated')
    raw = source.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(database, 'now', lambda: '2000-01-01T00:00:00+00:00')
    monkeypatch.setattr(worker, 'now', database.now)
    reduced = tmp_path / 'reduced.db'
    full = tmp_path / 'full.db'
    options = {'record_size': None, '_source_path': 'E:\\$MFT'}
    actual = worker.run('mft', str(source), sha, reduced, options)
    with monkeypatch.context() as patch:
        patch.setattr(worker, 'connect', lambda path, **kw: database.connect(path))
        expected = worker.run('mft', str(source), sha, full, options)
    assert actual == expected
    assert actual['records'] == 6 and actual['errors'] == 2
    a = sqlite3.connect(reduced)
    b = sqlite3.connect(full)
    assert contents(a) == contents(b)
    assert a.execute('SELECT count(*) FROM evidence_objects').fetchone()[0] > a.execute('SELECT count(*) FROM mft_names').fetchone()[0]
    assert a.execute('PRAGMA foreign_key_check').fetchall() == []
    a.close()
    b.close()
    assert source.read_bytes() == raw


def test_publication_keeps_full_indexes_and_queries(tmp_path):
    source = mft_file(tmp_path / '$MFT', names=('payload.exe', 'PAYLOA~1.EXE'))
    case = database.connect(tmp_path / 'case.db')
    original_indexes = indexes(case)
    def runner(kind, path, sha, stage, options, timeout):
        result = worker.run(kind, path, sha, stage, options)
        private = sqlite3.connect(stage)
        assert not MFT_STAGE_QUERY_INDEXES.intersection(indexes(private))
        private.close()
        return result
    result = ingest_artifact(case, source, 'mft', runner=runner)
    assert result['status'] == 'complete' and result['inserted'] == 3
    assert indexes(case) == original_indexes
    eid = case.execute("SELECT evidence_id FROM evidence_objects WHERE basename='payload.exe'").fetchone()[0]
    assert get_evidence(case, eid)['detail']['record_number'] == 6
    assert EvidenceQueries(case).search(artifact='mft', path='payload.exe').total == 1
    assert EvidenceQueries(case).search(timeline=True, start='2019-06-01T00:00:00Z', end='2020-01-01T00:00:00Z').total == case.execute('SELECT count(*) FROM evidence_timestamps').fetchone()[0]
    assert case.execute('SELECT count(*) FROM evidence_timestamps WHERE timestamp_utc IS NOT NULL').fetchone()[0] > 0
    assert case.execute('PRAGMA foreign_key_check').fetchall() == []
    case.close()


@pytest.mark.parametrize('kind', ['prefetch', 'registry', 'browser'])
def test_other_worker_families_keep_normal_schema(tmp_path, kind):
    source = tmp_path / 'empty-source'
    source.write_bytes(b'')
    stage = tmp_path / 'stage.db'
    worker.run(kind, str(source), hashlib.sha256(b'').hexdigest(), stage, {}, reader=lambda *a, **kw: iter(()))
    db = database.connect(stage)
    normal = database.connect(':memory:')
    assert indexes(db) == indexes(normal)
    db.close()
    normal.close()


@pytest.mark.parametrize('private', [False, True])
def test_timestamp_layout_preserves_observations_and_conflicts(tmp_path, private):
    db = database.connect(tmp_path / 'timestamps.db', _mft_stage=private)
    # A real parsed synthetic record supplies the referenced identity.
    from forensic_assistant.database.artifacts import register
    db.execute("INSERT INTO evidence_files VALUES ('hash',1,'fixed')")
    register(db, dict(evidence_id='mft',source_type='mft',artifact_type='mft_record',
                     file_sha256='hash',source_file='synthetic',locator_json='{}',
                     warnings_json='[]',original_json='{}'))
    rows = [
        ('mft','attribute:56:Created','2020-01-01Z','same','FILETIME','SI','created',100,'valid'),
        ('mft','attribute:56:Modified','2020-01-01Z','same','FILETIME','SI','modified',100,'valid'),
        ('mft','attribute:168:Created','2020-01-01Z','same','FILETIME','FN','created',100,'valid'),
        ('mft','attribute:280:Created',None,'0','FILETIME','FN','created',100,'zero'),
    ]
    db.executemany('INSERT INTO evidence_timestamps VALUES (?,?,?,?,?,?,?,?,?)', rows)
    for row in rows:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute('INSERT INTO evidence_timestamps VALUES (?,?,?,?,?,?,?,?,?)', row)
        assert db.execute('INSERT INTO evidence_timestamps VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING', row).rowcount == 0
    assert db.execute('SELECT count(*) FROM evidence_timestamps').fetchone()[0] == 4
    assert sorted(tuple(r) for r in db.execute('SELECT * FROM evidence_timestamps')) == sorted(rows)
    with pytest.raises(sqlite3.IntegrityError):
        db.execute('INSERT INTO evidence_timestamps VALUES (?,?,?,?,?,?,?,?,?)', ('missing', *rows[0][1:]))
    with pytest.raises(sqlite3.IntegrityError):
        db.execute('INSERT INTO evidence_timestamps VALUES (?,?,?,?,?,?,?,?,?)', ('mft', None, *rows[0][2:]))
    plan = ' '.join(r[3] for r in db.execute('EXPLAIN QUERY PLAN SELECT * FROM evidence_timestamps WHERE evidence_id=? ORDER BY slot', ('mft',)))
    assert 'SEARCH' in plan and 'TEMP B-TREE' not in plan
    db.close()

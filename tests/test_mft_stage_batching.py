"""Private MFT batching preserves logical rows and fails closed on write errors."""
import copy
import hashlib
import sqlite3
from contextlib import closing

import pytest

from forensic_assistant.artifacts import mft, mft_stage, worker
from forensic_assistant.artifacts.storage import store
from forensic_assistant.database import db as database
from forensic_assistant.database.artifacts import dump
from v2_fixtures import mft_file


@pytest.fixture
def source(tmp_path, monkeypatch):
    monkeypatch.setattr(database, 'now', lambda: 'fixed')
    monkeypatch.setattr(worker, 'now', lambda: 'fixed')
    path = mft_file(tmp_path / 'synthetic-MFT', parent_sequence=99, allocated=False)
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    template = list(mft.parse(path, sha))[-1]
    return path, sha, template


def entries(source, count):
    for index in range(count):
        pack = copy.deepcopy(source[2])
        pack['record']['evidence_id'] = f'MFT:{source[1]}:Offset:{(index + 6) * 1024}'
        pack['detail']['record_number'] = index + 6
        yield pack


def logical(path):
    with closing(sqlite3.connect(path)) as db:
        assert not db.execute('PRAGMA foreign_key_check').fetchall()
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {table: sorted([tuple(r) for r in db.execute(f'SELECT * FROM "{table}"')], key=repr)
                for table in tables}


def previous_run(source, target, reader):
    """Reference individual-write MFT loop, including legacy error behavior."""
    path, sha, _ = source
    with closing(database.connect(target, _mft_stage=True)) as db:
        with db:
            database.register_source(db, sha, path.stat().st_size, str(path))
            run = db.execute('INSERT INTO ingestion_runs(source_file,started_utc,status) VALUES (?,?,?)',
                             (str(path), 'fixed', 'running')).lastrowid
        inserted = errors = 0
        def error(message, locator):
            nonlocal errors
            errors += 1
            eid = db.execute('INSERT INTO ingestion_errors(run_id,record_offset,stage,message) VALUES (?,?,?,?)',
                             (run, locator.get('offset'), 'parse', message)).lastrowid
            db.execute('INSERT INTO artifact_errors VALUES (?,?)', (eid, dump(locator)))
        try:
            for index, pack in enumerate(reader()):
                if 'error' in pack:
                    error(pack['error'], pack.get('locator', {}))
                    continue
                inserted += store(db, pack, sha, str(path), 'dissect.ntfs', worker.importlib.metadata.version('dissect.ntfs'))
                if index % 500 == 0:
                    db.commit()
        except Exception as exc:
            error(f'Iteration stopped: {type(exc).__name__}: {exc}', {})
        mft.reconstruct_paths(db, sha)
        db.commit()
        return inserted, errors


@pytest.mark.parametrize('count', [3, 251, 2501])
@pytest.mark.parametrize('ending', ['normal', 'fatal', 'duplicate_name'])
def test_logical_equivalence(source, tmp_path, count, ending):
    def reader():
        for i, pack in enumerate(entries(source, count)):
            yield pack
            if i % 200 == 0:
                yield copy.deepcopy(pack)  # Same identity must skip all children.
                yield {'error': 'synthetic malformed record', 'locator': {'offset': i * 1024}}
        if ending == 'fatal':
            raise ValueError('synthetic parser failure')
        if ending == 'duplicate_name':
            pack = next(entries(source, count + 1))
            pack['record']['evidence_id'] += ':duplicate-name'
            pack['detail']['names'].append(copy.deepcopy(pack['detail']['names'][0]))
            yield pack
    old = tmp_path / 'old.db'
    new = tmp_path / 'new.db'
    expected = previous_run(source, old, reader)
    result = worker.run('mft', str(source[0]), source[1], new, {}, reader=lambda *a: reader())
    assert (result['records'], result['errors']) == expected
    assert logical(new) == logical(old)


class ObservedDB:
    def __init__(self, db, fail=None):
        self.db, self.fail = db, fail
        self.commits, self.batches = [], []
    def __getattr__(self, name):
        return getattr(self.db, name)
    def __enter__(self):
        self.db.__enter__()
        return self
    def __exit__(self, *args):
        return self.db.__exit__(*args)
    def executemany(self, sql, rows):
        self.batches.append(len(rows))
        if self.fail == 'batch':
            self.db.execute(sql, rows[0])
            raise sqlite3.OperationalError('injected batch write failure')
        return self.db.executemany(sql, rows)
    def commit(self):
        if self.fail == 'commit':
            raise sqlite3.OperationalError('injected commit failure')
        self.commits.append(tuple(self.db.execute(
            'SELECT (SELECT count(*) FROM evidence_records),(SELECT count(*) FROM ingestion_errors)').fetchone()))
        self.db.commit()


def observe(monkeypatch, fail=None):
    connections = []
    def connect(*args, **kwargs):
        db = ObservedDB(database.connect(*args, **kwargs), fail)
        connections.append(db)
        return db
    monkeypatch.setattr(worker, 'connect', connect)
    return connections


@pytest.mark.parametrize('errors_only', [False, True])
def test_transaction_boundary_includes_errors_and_flushes_tail(source, tmp_path, monkeypatch, errors_only):
    connections = observe(monkeypatch)
    def reader(*args):
        for i, pack in enumerate(entries(source, 20003)):
            yield {'error': 'synthetic', 'locator': {}} if errors_only or i % 2 else pack
    path = tmp_path / 'stage.db'
    result = worker.run('mft', str(source[0]), source[1], path, {}, reader=reader)
    assert connections[0].commits == ([(0, 20000), (0, 20003)] if errors_only
                                      else [(10000, 10000), (10002, 10001)])
    assert result['records'] == (0 if errors_only else 10002)
    assert result['errors'] == (20003 if errors_only else 10001)
    assert all(n <= 2000 for n in connections[0].batches)
    with closing(sqlite3.connect(path)) as db:
        assert not db.execute('PRAGMA foreign_key_check').fetchall()
        assert db.execute('SELECT count(*) FROM evidence_timestamps').fetchone()[0] == result['records'] * 8


@pytest.mark.parametrize('count,retained', [(1, 0), (20001, 20000)])
def test_cancellation_discards_pending_transaction(source, tmp_path, count, retained):
    def reader(*args):
        yield from entries(source, count)
        raise KeyboardInterrupt
    path = tmp_path / 'stage.db'
    with pytest.raises(KeyboardInterrupt):
        worker.run('mft', str(source[0]), source[1], path, {}, reader=reader)
    with closing(sqlite3.connect(path)) as db:
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == retained
        assert db.execute('SELECT count(*) FROM evidence_timestamps').fetchone()[0] == retained * 8
        assert not db.execute('PRAGMA foreign_key_check').fetchall()


@pytest.mark.parametrize('failure,count', [('batch', 300), ('commit', 300), ('commit', 20001)])
def test_write_failure_cannot_return_publishable_result(source, tmp_path, monkeypatch, failure, count):
    observe(monkeypatch, failure)
    path = tmp_path / 'stage.db'
    with pytest.raises(sqlite3.OperationalError, match='injected'):
        worker.run('mft', str(source[0]), source[1], path, {}, reader=lambda *a: entries(source, count))
    with closing(sqlite3.connect(path)) as db:
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM evidence_timestamps').fetchone()[0] == 0


def test_row_and_byte_bounds_and_no_replay():
    class Sink:
        def __init__(self):
            self.batches = []
        def executemany(self, sql, rows):
            self.batches.append(len(rows))
        def execute(self, *args):
            return 'immediate'
    sink = Sink()
    writer = mft_stage.MftStage(sink)
    sql = next(s for s in mft_stage._BATCH_SQL if 'timestamps' in s)
    for i in range(2001):
        writer.execute(sql, ('e', str(i), None, '', '', 's', 'm', 1, 'valid'))
    assert sink.batches == [2000] and writer.rows == 1
    writer.flush()
    assert sink.batches == [2000, 1]
    for i in range(10):
        writer.execute(sql, ('x' * 1000000,))
    assert writer.peak_bytes <= mft_stage.BUFFER_BYTES
    assert writer.peak_rows <= mft_stage.BATCH_ROWS
    assert writer.execute(sql, ('x' * (mft_stage.BUFFER_BYTES + 1),)) == 'immediate'
    assert writer.rows == 0


def test_failed_batch_is_never_replayed():
    class Broken:
        calls = 0
        def executemany(self, sql, rows):
            self.calls += 1
            raise sqlite3.OperationalError('disk failure after prefix')
    db = Broken()
    writer = mft_stage.MftStage(db)
    writer.execute(next(iter(mft_stage._BATCH_SQL)), ('synthetic',))
    with pytest.raises(sqlite3.OperationalError):
        writer.flush()
    assert writer.rows == 0 and writer.failed
    with pytest.raises(RuntimeError):
        writer.flush()
    assert db.calls == 1


def test_conflicting_timestamp_and_object_slots_keep_first_values(source, tmp_path):
    def reader():
        pack = next(entries(source, 1))
        duplicate = dict(pack['timestamps'][0], original_value='different')
        pack['timestamps'].append(duplicate)
        pack['objects'] = [dict(slot='duplicate', role='file_path', original=name)
                           for name in ('first.exe', 'second.exe')]
        yield pack
    old, new = tmp_path / 'old.db', tmp_path / 'new.db'
    previous_run(source, old, reader)
    result = worker.run('mft', str(source[0]), source[1], new, {}, reader=lambda *a: reader())
    assert result['records'] == 1 and result['errors'] == 0
    assert logical(new) == logical(old)
    with closing(sqlite3.connect(new)) as db:
        assert db.execute("SELECT original FROM evidence_objects WHERE slot='duplicate'").fetchone()[0] == 'first.exe'


def test_read_failure_during_reconstruction_never_returns_result(source, tmp_path, monkeypatch):
    def failed(db, sha):
        raise sqlite3.OperationalError('synthetic reconstruction read failure')
    monkeypatch.setattr(mft, 'reconstruct_paths', failed)
    target = tmp_path / 'stage.db'
    with pytest.raises(sqlite3.OperationalError):
        worker.run('mft', str(source[0]), source[1], target, {}, reader=lambda *a: entries(source, 3))
    with closing(sqlite3.connect(target)) as db:
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 0


def test_cancellation_during_reconstruction_rolls_back(source, tmp_path, monkeypatch):
    def cancelled(db, sha):
        # Records and timestamps must already be visible to reconstruction.
        assert db.execute('SELECT count(*) FROM evidence_timestamps').fetchone()[0] == 24
        from forensic_assistant.database.artifacts import add_object
        eid = db.execute('SELECT evidence_id FROM evidence_records LIMIT 1').fetchone()[0]
        add_object(db, eid, 'test-path', 'file_path', 'synthetic.exe')
        raise KeyboardInterrupt
    monkeypatch.setattr(mft, 'reconstruct_paths', cancelled)
    target = tmp_path / 'stage.db'
    with pytest.raises(KeyboardInterrupt):
        worker.run('mft', str(source[0]), source[1], target, {}, reader=lambda *a: entries(source, 3))
    with closing(sqlite3.connect(target)) as db:
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM evidence_objects').fetchone()[0] == 0

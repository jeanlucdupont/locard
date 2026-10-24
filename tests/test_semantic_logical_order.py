"""Logical ordering must survive physical insertion permutations."""
import random
import sqlite3

import pytest

from forensic_assistant.database.db import connect
from forensic_assistant.database.artifacts import register
from forensic_assistant.semantic.documents import _fields, _primary_key, fingerprint, representation


def fixture(count):
    db = connect(':memory:')
    db.execute("INSERT INTO evidence_files VALUES ('hash',123,'fixed')")
    for eid in ('z', 'a'):
        register(db, dict(evidence_id=eid, source_type='mft', artifact_type='mft_record',
                         file_sha256='hash', source_file='synthetic', locator_json='{}',
                         warnings_json='[]', original_json='{}'))
    for i in range(count):
        # Offset is identity, not a priority; include offsets with different widths.
        slot = f'attribute:{56 + (i // 4) * 112}:' + ('Created', 'Modified', 'MFTChanged', 'Accessed')[i % 4]
        for eid in ('z', 'a'):
            db.execute('INSERT INTO evidence_timestamps VALUES (?,?,?,?,?,?,?,?,?)',
                       (eid, slot, None if i % 5 == 0 else '2020-01-01T00:00:00Z',
                        str(i), 'FILETIME', 'MFT SI' if i < 4 else 'MFT FN',
                        'metadata ' + str(i % 4), 100, 'valid' if i % 5 else 'unavailable'))
    db.commit()
    return db


def permuted(source, seed):
    result = sqlite3.connect(':memory:')
    source.backup(result)
    result.row_factory = sqlite3.Row
    result.execute('PRAGMA foreign_keys=OFF')
    for (table,) in result.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
        rows = result.execute('SELECT * FROM "' + table + '"').fetchall()
        result.execute('DELETE FROM "' + table + '"')
        if seed is None:
            rows.reverse()
        else:
            random.Random(seed).shuffle(rows)
        if rows:
            result.executemany('INSERT INTO "' + table + '" VALUES (' + ','.join('?' for _ in rows[0]) + ')', rows)
    result.commit()
    result.execute('PRAGMA foreign_keys=ON')
    assert result.execute('PRAGMA foreign_key_check').fetchall() == []
    return result


@pytest.mark.parametrize('count', [8, 32, 40])
@pytest.mark.parametrize('seed', [None, 7, 29])
def test_timestamp_and_multitable_permutations(count, seed):
    original = fixture(count)
    changed = permuted(original, seed)
    args = ('evidence_timestamps', 'evidence_id', 'a', ['slot', 'timestamp_utc', 'source', 'meaning'], 32)
    assert _fields(original, *args) == _fields(changed, *args)
    assert representation(original, 'a') == representation(changed, 'a')
    assert fingerprint(original) == fingerprint(changed)
    fields, clipped = _fields(changed, *args)
    expected = sorted(r[0] for r in original.execute("SELECT slot FROM evidence_timestamps WHERE evidence_id='a'"))[:32]
    assert [r['slot'] for r in fields] == expected
    assert clipped == (count > 32)
    duplicate = original.execute('SELECT * FROM evidence_timestamps LIMIT 1').fetchone()
    with pytest.raises(sqlite3.IntegrityError):
        changed.execute('INSERT INTO evidence_timestamps VALUES (?,?,?,?,?,?,?,?,?)', tuple(duplicate))
    original.close()
    changed.close()


@pytest.mark.parametrize('column,value', [('timestamp_utc','changed'), ('original_value','changed'),
    ('encoding','changed'), ('source','changed'), ('meaning','changed'), ('precision_ns',999),
    ('normalization_status','changed'), ('slot','new-slot'), ('evidence_id','different')])
def test_every_timestamp_field_remains_significant(column, value):
    db = fixture(8)
    before = fingerprint(db)
    db.execute('PRAGMA foreign_keys=OFF')
    db.execute('UPDATE evidence_timestamps SET ' + column + '=? WHERE evidence_id=? AND slot=?',
               (value, 'a', 'attribute:56:Created'))
    assert fingerprint(db) != before
    db.close()


def test_long_cells_use_logical_key_for_all_chunks():
    db = fixture(8)
    db.execute("UPDATE evidence_records SET original_json=? WHERE evidence_id='a'", ('x' * 150000,))
    db.commit()
    other = permuted(db, None)
    assert fingerprint(db) == fingerprint(other)
    before = fingerprint(other)
    other.execute("UPDATE evidence_records SET original_json=? WHERE evidence_id='a'", ('x' * 149999 + 'y',))
    assert fingerprint(other) != before
    db.execute("UPDATE evidence_timestamps SET original_value=? WHERE evidence_id='a' AND slot='attribute:56:Created'", ('x' * 150000,))
    before = fingerprint(db)
    db.execute("UPDATE evidence_timestamps SET original_value=? WHERE evidence_id='a' AND slot='attribute:56:Created'", ('x' * 149999 + 'y',))
    assert fingerprint(db) != before
    db.close()
    other.close()


def test_all_authoritative_tables_have_keys_and_fail_closed_without_one():
    db = connect(':memory:')
    for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
        assert _primary_key(db, table)
    db.execute('CREATE TABLE unsupported(value TEXT)')
    with pytest.raises(ValueError, match='no declared logical key'):
        fingerprint(db)
    db.close()


def test_null_logical_key_is_not_silently_canonicalized():
    db = connect(':memory:')
    db.execute("INSERT INTO evidence_files VALUES (NULL,1,'fixed')")
    with pytest.raises(ValueError, match='NULL authoritative primary key'):
        fingerprint(db)
    db.close()


def test_real_parser_publication_order_does_not_change_semantics(tmp_path, monkeypatch):
    from forensic_assistant.artifacts import worker, ingest
    from forensic_assistant.database import db as database
    from v2_fixtures import mft_file
    source = mft_file(tmp_path / '$MFT', names=('one.exe', 'TWO.EXE', 'third.exe'))
    monkeypatch.setattr(database, 'now', lambda: '2000-01-01T00:00:00+00:00')
    monkeypatch.setattr(worker, 'now', database.now)
    monkeypatch.setattr(ingest, 'now', database.now)
    results = []
    for reverse in (False, True):
        case = connect(':memory:')
        def runner(kind, path, sha, stage, options, timeout):
            result = worker.run(kind, path, sha, stage, options)
            if reverse:
                c = sqlite3.connect(stage)
                rows = c.execute('SELECT * FROM evidence_timestamps').fetchall()
                c.execute('DELETE FROM evidence_timestamps')
                c.executemany('INSERT INTO evidence_timestamps VALUES (?,?,?,?,?,?,?,?,?)', rows[::-1])
                c.commit()
                c.close()
            return result
        assert ingest.ingest_artifact(case, source, 'mft', runner=runner)['status'] == 'complete'
        ids = [r[0] for r in case.execute('SELECT evidence_id FROM evidence_records ORDER BY evidence_id')]
        results.append((fingerprint(case), [representation(case, eid) for eid in ids],
                        [tuple(r) for r in case.execute('SELECT * FROM evidence_timestamps ORDER BY evidence_id,slot')]))
        assert 'WITHOUT ROWID' not in case.execute("SELECT sql FROM sqlite_master WHERE name='evidence_timestamps'").fetchone()[0]
        case.close()
    assert results[0] == results[1]

"""Real SQLite journal semantics on disposable synthetic Chromium databases."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from forensic_assistant.artifacts import browser
from forensic_assistant.artifacts.browser_journal import SnapshotError
from forensic_assistant.database.db import connect
from test_browser_parser import history
from test_browser_safety import batch, local_runner
from forensic_assistant.artifacts.ingest import ingest_artifact


def persist(path):
    with closing(history(path)) as db:
        assert db.execute('PRAGMA journal_mode=PERSIST').fetchone()[0] == 'persist'
        with db: db.execute("UPDATE urls SET title='Committed synthetic title'")
    journal = Path(str(path) + '-journal')
    assert journal.stat().st_size > 512
    assert journal.read_bytes()[:28] == bytes(28)
    return journal


def files(path):
    return {p.name: p.read_bytes() for p in path.parent.iterdir() if p.name.startswith('History')}


@pytest.mark.parametrize('state', ['absent', 'empty', 'inactive'])
def test_supported_states_preserve_all_bytes_and_record_semantics(tmp_path, state):
    source = tmp_path / 'History'
    if state == 'inactive': persist(source)
    else:
        history(source).close()
        if state == 'empty': Path(str(source) + '-journal').write_bytes(b'')
    before = files(source)
    options = browser.snapshot(source, tmp_path / 'copy', 'edge', 'Default')
    assert options['sqlite_validation']['rollback_journal'] == state
    assert options['sqlite_validation']['recovery_performed'] is False
    rows = list(browser.parse(tmp_path / 'copy', options['manifest']['']['sha256'], **options))
    assert len(rows) == 2
    assert rows[0]['timestamps'][0]['precision_ns'] == 1000
    assert rows[1]['detail']['target_path'] == r'C:\Users\alice\Downloads\tool.exe'
    if state != 'absent':
        assert (tmp_path / 'copy-journal').read_bytes() == before['History-journal']
        assert options['manifest']['-journal']['sha256'] == browser.inventory(source)['-journal']['sha256']
    if state == 'inactive': assert 'Inactive rollback journal accepted' in rows[0]['record']['warnings_json']
    assert files(source) == before


@pytest.mark.parametrize('damage,category', [
    ('short', 'journal_incomplete'), ('garbage', 'journal_malformed'), ('pre-sync', 'journal_indeterminate'),
    ('zero-short', 'journal_indeterminate'), ('counter', 'snapshot_consistency_not_established'),
    ('size', 'snapshot_consistency_not_established'), ('corrupt-page', 'sqlite_validation_failed'),
    ('mixed-wal-mode', 'snapshot_consistency_not_established')])
def test_uncertain_or_inconsistent_sets_fail_closed(tmp_path, damage, category):
    source = tmp_path / 'History'; journal = persist(source)
    if damage == 'short': journal.write_bytes(b'bad')
    elif damage == 'garbage': journal.write_bytes(b'not a journal' * 100)
    elif damage == 'pre-sync': journal.write_bytes(bytes(8) + b'\1' * 1016)
    elif damage == 'zero-short': journal.write_bytes(bytes(100))
    else:
        with source.open('r+b') as stream:
            if damage == 'counter': stream.seek(92); stream.write(b'\xff' * 4)
            elif damage == 'size': stream.seek(28); stream.write((999).to_bytes(4, 'big'))
            elif damage == 'mixed-wal-mode': stream.seek(18); stream.write(b'\2\2')
            else: stream.seek(100); stream.write(b'\xff')
    before = files(source)
    with pytest.raises(SnapshotError) as caught:
        browser.snapshot(source, tmp_path / 'copy', 'edge', 'Default')
    assert caught.value.diagnostics['category'] == category
    assert caught.value.diagnostics['companions']['-journal']['sha256']
    assert files(source) == before


def test_read_only_source_files_and_bounded_validation(tmp_path, monkeypatch):
    import stat
    from forensic_assistant.artifacts import browser_journal
    source = tmp_path / 'History'; journal = persist(source)
    before = files(source)
    try:
        source.chmod(stat.S_IREAD); journal.chmod(stat.S_IREAD)
        assert browser.snapshot(source, tmp_path / 'copy', 'edge', 'Default')['sqlite_validation']['rollback_journal'] == 'inactive'
        assert files(source) == before
    finally:
        source.chmod(stat.S_IREAD | stat.S_IWRITE); journal.chmod(stat.S_IREAD | stat.S_IWRITE)
    with closing(sqlite3.connect(source)) as db:
        with db: db.executemany('INSERT INTO visits VALUES(?,1,1,1)', ((i,) for i in range(2,2002)))
    options = browser.snapshot(source, tmp_path / 'timed', 'edge', 'Default')
    monkeypatch.setattr(browser_journal, 'VALIDATION_SECONDS', -1)
    with pytest.raises(SnapshotError) as caught:
        browser_journal.validate(tmp_path / 'timed', options['manifest'])
    assert caught.value.diagnostics['category'] == 'sqlite_validation_failed'


def test_real_abandoned_hot_journal_not_recovered(tmp_path):
    source = tmp_path / 'History'
    with closing(history(source)) as db:
        db.executescript('CREATE TABLE padding(id INTEGER PRIMARY KEY, data BLOB);')
        with db: db.executemany('INSERT INTO padding(data) VALUES (?)', [(bytes(4096),)] * 50)
    code = '''import sqlite3,sys,os
db=sqlite3.connect(sys.argv[1]);db.execute('PRAGMA cache_size=1')
db.execute('BEGIN IMMEDIATE');db.execute('UPDATE padding SET data=randomblob(4096)')
os._exit(0)
'''
    subprocess.run([sys.executable, '-c', code, str(source)], check=True, timeout=15)
    assert Path(str(source) + '-journal').read_bytes()[:8] == bytes.fromhex('d9d505f920a163d7')
    before = files(source)
    with closing(connect(':memory:')) as db:
        result = ingest_artifact(db, source, 'browser', browser_product='edge', profile='Default',
                                 batch_id=batch(db), runner=local_runner)
        assert result['status'] == 'failed' and result['inserted'] == 0
        detail = json.loads(db.execute('SELECT locator_json FROM artifact_errors').fetchone()[0])
        assert detail['category'] == 'recovery_unsupported'  # No mandatory audit session bound.
        assert detail['recovery_performed'] is False
        assert db.execute('SELECT count(*) FROM browser_record_occurrences').fetchone()[0] == 0
    assert files(source) == before


def test_inactive_retries_preserve_history_identity_and_provenance(tmp_path):
    source = tmp_path / 'History'; journal = persist(source)
    before = files(source)
    with closing(connect(':memory:')) as db:
        bid = batch(db)
        def ingest():
            return ingest_artifact(db, source, 'browser', browser_product='edge', profile='Default',
                                   batch_id=bid, runner=local_runner)
        good = journal.read_bytes()
        journal.write_bytes(b'malformed synthetic journal')
        assert ingest()['status'] == 'failed'
        journal.write_bytes(good)
        first, second = ingest(), ingest()
        assert first['inserted'] == 2 and first['status'] == 'complete'
        assert second['inserted'] == 0 and second['duplicates'] == 2
        assert [r[0] for r in db.execute('SELECT status FROM ingestion_runs ORDER BY id')] == ['failed', 'complete', 'complete']
        assert db.execute('SELECT count(*) FROM browser_record_occurrences').fetchone()[0] == 4
        params = json.loads(db.execute('SELECT parameters_json FROM artifact_runs ORDER BY run_id DESC LIMIT 1').fetchone()[0])
        assert params['sqlite_validation']['rollback_journal'] == 'inactive'
        assert params['manifest']['-journal']['sha256'] == browser.inventory(source)['-journal']['sha256']
        expected = browser.context_id(params['snapshot_sha256'], 'edge', 'Default')
        assert db.execute('SELECT context_id FROM browser_contexts').fetchone()[0] == expected
    assert files(source) == before


@pytest.mark.parametrize('damage', ['none', 'missing-wal', 'invalid-wal', 'wal-checksum'])
def test_wal_companions(tmp_path, damage):
    source = tmp_path / 'History'
    with closing(history(source, wal=True)):
        # Create a synthetic acquired set, without interfering with the open DB.
        acquired = tmp_path / 'acquired'; acquired.mkdir()
        for suffix in ('', '-wal', '-shm'):
            (acquired / ('History' + suffix)).write_bytes(Path(str(source) + suffix).read_bytes())
    path = acquired / 'History'
    if damage == 'missing-wal': (acquired / 'History-wal').unlink()
    if damage == 'invalid-wal': (acquired / 'History-wal').write_bytes(b'bad WAL')
    if damage == 'wal-checksum':
        with (acquired / 'History-wal').open('r+b') as stream:
            stream.seek(24); stream.write(bytes(8))
    before = files(path)
    if damage == 'none':
        options = browser.snapshot(path, tmp_path / 'copy', 'edge', 'Default')
        assert len(list(browser.parse(tmp_path / 'copy', '', **options))) == 2
    else:
        with pytest.raises(SnapshotError) as caught: browser.snapshot(path, tmp_path / 'copy', 'edge', 'Default')
        assert caught.value.diagnostics['category'] == ('missing_required_companion' if damage == 'missing-wal' else 'snapshot_consistency_not_established')
    assert files(path) == before


def test_original_never_connected_and_source_change_rejected(tmp_path, monkeypatch):
    source = tmp_path / 'History'; persist(source)
    original = sqlite3.connect
    def checked(database, *args, **kwargs):
        assert str(source) not in str(database) and source.as_uri() not in str(database)
        assert 'mode=ro' in database and kwargs['uri'] is True
        return original(database, *args, **kwargs)
    monkeypatch.setattr(sqlite3, 'connect', checked)
    browser.snapshot(source, tmp_path / 'copy', 'edge', 'Default')
    original_copy = browser.shutil.copyfileobj
    def changed(src, dst, size):
        original_copy(src, dst, size)
        if str(dst.name).endswith('-journal'):
            with source.open('ab') as stream: stream.write(b'changed synthetic data')
    monkeypatch.setattr(browser.shutil, 'copyfileobj', changed)
    with pytest.raises(SnapshotError, match='changed while copying'):
        browser.snapshot(source, tmp_path / 'copy2', 'edge', 'Default')

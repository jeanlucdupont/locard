"""Generated Chromium fixtures contain only synthetic example.com data."""
from contextlib import closing
import sqlite3
from forensic_assistant.artifacts import browser

T = 13222310400123456  # 2020-01-01 UTC plus 123456 microseconds


def history(path, *, wal=False):
    db = sqlite3.connect(path)
    if wal:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA wal_autocheckpoint=0')
    db.executescript('''CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INTEGER,typed_count INTEGER);
    CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER,transition INTEGER);
    CREATE TABLE downloads(id INTEGER PRIMARY KEY,target_path TEXT,current_path TEXT,start_time INTEGER,end_time INTEGER,state INTEGER,danger_type INTEGER,mime_type TEXT,received_bytes INTEGER,total_bytes INTEGER,referrer TEXT);
    CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT);''')
    db.execute('INSERT INTO urls VALUES (1,?,?,2,1)', ('https://example.com/tool.exe', 'Example'))
    db.execute('INSERT INTO visits VALUES (1,1,?,1)', (T,))
    db.execute('INSERT INTO downloads VALUES (1,?,?,?,?,1,0,?,100,100,?)',
               (r'C:\Users\alice\Downloads\tool.exe', r'C:\Users\alice\Downloads\tool.exe', T+1000000, T+2000000,
                'application/octet-stream', 'https://example.com/'))
    db.executemany('INSERT INTO downloads_url_chains VALUES (1,?,?)',
                   [(2, 'https://example.com/tool.exe'), (0, 'https://example.com/start'), (1, 'https://example.com/redirect')])
    db.commit()
    return db


def test_chromium_times():
    stamp = browser.timestamp(T, 'Browser.VisitTime')
    assert stamp['timestamp_utc'] == '2020-01-01T00:00:00.123456000Z'
    assert stamp['precision_ns'] == 1000
    for value in (0, None):
        assert browser.timestamp(value, 'x')['normalization_status'] == 'missing'
    for value in (-1, '123', 2**63-1):
        assert browser.timestamp(value, 'x')['normalization_status'] == 'invalid'


def test_private_copy_visits_downloads_wal_and_integrity(tmp_path):
    path = tmp_path / 'History'
    with closing(history(path, wal=True)):
        original = browser.inventory(path)
        copied = tmp_path / 'copy'
        options = browser.snapshot(path, copied, 'chrome', 'Default')
        records = list(browser.parse(copied, original['']['sha256'], **options))
        assert len(records) == 2
        assert records[0]['detail']['url'] == 'https://example.com/tool.exe'
        detail = records[1]['detail']
        assert detail['state_name'] == 'complete'
        assert [item['chain_index'] for item in detail['url_chain']] == [0, 1, 2]
        assert detail['target_path'] == r'C:\Users\alice\Downloads\tool.exe'
        assert [s['slot'] for s in records[1]['timestamps']] == ['Browser.DownloadStart', 'Browser.DownloadEnd']
        assert original == browser.inventory(path)
        assert all('Default' == r['detail']['profile'] for r in records)


def test_context_changes_ids_not_row_identity(tmp_path):
    path = tmp_path / 'History'
    history(path).close()
    rows = []
    for index, (product, profile) in enumerate([('chrome', 'Default'), ('chrome', 'Profile 1'), ('edge', 'Profile 1')]):
        copy = tmp_path / str(index)
        opts = browser.snapshot(path, copy, product, profile)
        rows.append(list(browser.parse(copy, opts['manifest']['']['sha256'], **opts)))
    assert len({r['record']['evidence_id'] for group in rows for r in group}) == 6
    assert {r['record']['locator_json'] for r in rows[0]} != {r['record']['locator_json'] for r in rows[1]}


def test_missing_optional_and_required_schema(tmp_path):
    import pytest
    path = tmp_path / 'History'
    with closing(sqlite3.connect(path)) as db:
        db.executescript('CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT); CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER); INSERT INTO urls VALUES(1,\'https://example.com/\'); INSERT INTO visits VALUES(1,1,0);')
    opts = browser.snapshot(path, tmp_path / 'copy', 'edge', 'Profile 1')
    rows = list(browser.parse(tmp_path / 'copy', opts['manifest']['']['sha256'], **opts))
    assert len(rows) == 1 and rows[0]['timestamps'][0]['timestamp_utc'] is None
    assert 'Unavailable optional' in rows[0]['record']['warnings_json']
    bad = tmp_path / 'bad'
    with closing(sqlite3.connect(bad)) as db:
        db.execute('CREATE TABLE irrelevant(x)')
    opts = browser.snapshot(bad, tmp_path / 'bad-copy', 'chrome', 'Default')
    with pytest.raises(ValueError, match='required table/column missing'):
        list(browser.parse(tmp_path / 'bad-copy', opts['manifest']['']['sha256'], **opts))


def test_view_schema_rejected(tmp_path):
    import pytest
    path = tmp_path / 'History'
    with closing(sqlite3.connect(path)) as db:
        db.executescript('CREATE TABLE urls(id INTEGER,url TEXT); CREATE VIEW visits AS SELECT 1 id,1 url,0 visit_time;')
    opts = browser.snapshot(path, tmp_path / 'copy', 'chrome', 'Default')
    with pytest.raises(ValueError, match='view refused'):
        list(browser.parse(tmp_path / 'copy', opts['manifest']['']['sha256'], **opts))

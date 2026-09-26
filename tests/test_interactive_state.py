from contextlib import closing
import json
import sqlite3
import pytest
from forensic_assistant.database.db import connect
from forensic_assistant.interactive.case import validate
from forensic_assistant.interactive.state import State, state_path


def test_validation_preserves_database_and_releases_handles(tmp_path):
    path = tmp_path/'case with spaces é.db'
    connect(path).close()
    before = path.read_bytes()
    assert validate(path) == path.resolve()
    with closing(connect(path, existing_only=True)) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 3
    assert before == path.read_bytes()
    path.rename(tmp_path/'released.db')


@pytest.mark.parametrize('kind', ['missing','invalid','legacy','fake','view'])
def test_invalid_selection_never_creates_or_changes_case(tmp_path, kind):
    path = tmp_path/'case.db'
    if kind == 'invalid': path.write_bytes(b'not sqlite')
    elif kind in ('legacy','fake'):
        with closing(sqlite3.connect(path)) as db:
            db.execute('PRAGMA user_version='+('1' if kind=='legacy' else '3'))
    elif kind=='view':
        with closing(connect(path)) as db:
            db.execute('CREATE VIEW surprise AS SELECT 1')
    before = path.read_bytes() if path.exists() else None
    with pytest.raises((ValueError,sqlite3.Error)): validate(path)
    with pytest.raises((ValueError,sqlite3.Error)): connect(path,existing_only=True)
    assert (path.read_bytes() if path.exists() else None) == before


def test_wal_selection_includes_uncheckpointed_schema(tmp_path):
    path=tmp_path/'case.db'
    with closing(connect(path)) as db:
        db.execute('PRAGMA journal_mode=WAL')
        with db: db.execute('INSERT INTO evidence_files VALUES (?,?,?)',('a'*64,1,'synthetic'))
        assert validate(path)==path.resolve()
    path.rename(tmp_path/'closed.db')


def test_recent_state_is_bounded_atomic_and_contains_only_paths(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    state=State(state_path()).load()
    for n in range(12): state.remember(tmp_path/f'case{n}.db')
    state.remember(tmp_path/'case5.db')
    restored=State(state.path).load()
    assert len(restored.recent)==10 and restored.recent[0].endswith('case5.db')
    assert set(json.loads(state.path.read_text()))=={'format','last_database','recent_databases'}
    assert not list(state.path.parent.glob('*.tmp'))


@pytest.mark.parametrize('raw',[b'{',b'[]',b'{"format":1,"format":1}',b'x'*(1024*1024+1)], ids=['truncated','array','duplicate','oversize'])
def test_corrupt_state_preserved(tmp_path,raw):
    path=tmp_path/'ui-state.json';path.write_bytes(raw)
    state=State(path).load()
    assert state.blocked and state.warning and not state.recent
    state.remember(tmp_path/'valid.db')
    assert path.read_bytes()==raw


def test_failed_atomic_replace_preserves_old_state(tmp_path,monkeypatch):
    state=State(tmp_path/'ui-state.json');state.remember(tmp_path/'a.db')
    before=state.path.read_bytes()
    def fail(*args): raise OSError('synthetic failure')
    monkeypatch.setattr('forensic_assistant.interactive.state.os.replace',fail)
    with pytest.raises(OSError):state.remember(tmp_path/'b.db')
    assert state.path.read_bytes()==before
    assert not list(tmp_path.glob('*.tmp'))

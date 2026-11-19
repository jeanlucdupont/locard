"""Old/new source assertion schemas through actual case-open boundaries."""
from contextlib import closing
import sqlite3

import pytest

from forensic_assistant.database import sources, source_timezone
from forensic_assistant.database.db import connect, register_source
from forensic_assistant.interactive import case
from forensic_assistant.investigation_ai.case import open_readonly
from forensic_assistant.semantic.documents import fingerprint


def legacy(path):
    with closing(connect(path)) as db:
        db.execute('ALTER TABLE source_assertions DROP COLUMN time_zone')
        with db:
            sid = sources.create(db, name='Historical source')
            register_source(db, 'a' * 64, 1, 'synthetic')
            sources.assign(db, sid, ['a' * 64], reason='Synthetic association')
    return sid


@pytest.mark.parametrize('layout', ['legacy', 'null', 'populated', 'migrated'])
def test_actual_open_preserves_bytes_schema_mtime_and_fingerprint(tmp_path, layout):
    path = tmp_path / 'case.db'
    if layout in ('legacy', 'migrated'):
        sid = legacy(path)
    else:
        with closing(connect(path)) as db, db:
            sid = sources.create(db, name='Synthetic', time_zone='America/Chicago' if layout == 'populated' else None)
    if layout == 'migrated':
        with closing(case.open_existing(path)) as db, db:
            sources.update(db, sid, time_zone='America/Chicago')
    before = path.read_bytes(), path.stat().st_mtime_ns
    with closing(open_readonly(path)) as db:
        schema = list(map(tuple, db.execute('SELECT * FROM sqlite_master ORDER BY name')))
        digest = fingerprint(db)
        case.check_structure(db)
        assert sources.current(db, sid)['time_zone'] == ('America/Chicago' if layout in ('populated', 'migrated') else None)
        with pytest.raises(sqlite3.DatabaseError):
            db.execute("UPDATE source_assertions SET display_name='forbidden'")
    assert case.validate(path) == path.resolve()
    with closing(case.open_existing(path)) as db:
        assert list(map(tuple, db.execute('SELECT * FROM sqlite_master ORDER BY name'))) == schema
        assert fingerprint(db) == digest
        assert source_timezone.has_column(db) is (layout != 'legacy')
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


@pytest.mark.parametrize('replacement', ['time_zone INTEGER', 'time_zone TEXT NOT NULL',
                                      "time_zone TEXT DEFAULT 'UTC'", 'unexpected TEXT',
                                      'time_zone TEXT, unexpected TEXT'])
def test_reject_unexpected_extension_and_block_migration(replacement):
    with closing(connect(':memory:')) as db:
        db.execute('DROP TABLE source_assertions')
        db.execute(sources.DDL[1].replace('time_zone TEXT', replacement))
        db.commit()
        before = '\n'.join(db.iterdump())
        with pytest.raises(ValueError, match='source_assertions'):
            case.check_structure(db)
        with pytest.raises(ValueError, match='source_assertions'):
            source_timezone.enable_for_assertion(db, 'America/Chicago')
        assert '\n'.join(db.iterdump()) == before


def test_unrelated_schema_and_trigger_rejection_unchanged():
    with closing(connect(':memory:')) as db:
        db.execute('ALTER TABLE sources ADD COLUMN unexpected TEXT')
        with pytest.raises(ValueError, match='sources'):
            case.check_structure(db)
    with closing(connect(':memory:')) as db:
        db.execute('CREATE TRIGGER unexpected AFTER INSERT ON sources BEGIN SELECT 1; END')
        with pytest.raises(ValueError, match='executable schema'):
            case.check_structure(db)


def test_migration_keeps_history_membership_audit_and_old_fingerprint(tmp_path):
    from forensic_assistant import activity
    path = tmp_path / 'case.db'
    sid = legacy(path)
    with closing(case.open_existing(path)) as db:
        old_digest = fingerprint(db)
        old = dict(db.execute('SELECT * FROM source_assertions').fetchone())
        other = {t: list(map(tuple, db.execute('SELECT * FROM ' + t))) for t in
                 ('sources', 'source_assignments', 'source_assignment_files', 'evidence_files', 'evidence_timestamps')}
    session = activity.Session(path)
    session.record('SYNTHETIC_HISTORY', required=True, historical_fingerprint=old_digest)
    session.end('fixture')
    audit_path = activity.sidecar(path)
    audit_before = audit_path.read_bytes()
    assert activity.inspect(audit_path)['valid']
    with closing(case.open_existing(path)) as db:
        with db:
            sources.update(db, sid, time_zone='America/Chicago')
        with db:
            sources.update(db, sid, time_zone='Europe/Paris')
        history = sources.detail(db, sid)['assertion_history']['records']
        assert [r['time_zone'] for r in history] == [None, 'America/Chicago', 'Europe/Paris']
        assert all(history[0][k] == v for k, v in old.items())
        assert history[1]['supersedes'] == old['assertion_id']
        assert fingerprint(db) != old_digest
        for table, values in other.items():
            assert list(map(tuple, db.execute('SELECT * FROM ' + table))) == values
    assert audit_path.read_bytes() == audit_before and activity.inspect(audit_path)['valid']
    assert old_digest.encode() in audit_before


def test_insert_failure_rolls_back_extension_and_revision(tmp_path):
    path = tmp_path / 'case.db'
    sid = legacy(path)
    class Failing(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith('INSERT INTO source_assertions'):
                raise sqlite3.OperationalError('injected assertion write failure')
            return super().execute(sql, *args)
    with closing(sqlite3.connect(path, factory=Failing)) as db:
        db.row_factory = sqlite3.Row
        before = fingerprint(db)
        with pytest.raises(sqlite3.OperationalError, match='injected'):
            with db:
                sources.update(db, sid, time_zone='America/Chicago')
        assert not source_timezone.has_column(db)
        assert fingerprint(db) == before
    assert case.validate(path) == path.resolve()


def test_schema4_old_and_extended_are_supported(tmp_path):
    path = tmp_path / 'case.db'
    sid = legacy(path)
    with closing(sqlite3.connect(path)) as db:
        db.execute('DROP TABLE browser_record_occurrences')
        db.execute('DROP TABLE browser_contexts')
        db.execute('PRAGMA user_version=4')
    assert case.validate(path) == path.resolve()
    with closing(case.open_existing(path)) as db, db:
        sources.update(db, sid, time_zone='America/Chicago')
    assert case.validate(path) == path.resolve()


def test_remembered_legacy_case_reaches_activation_without_migration(tmp_path, monkeypatch, capsys):
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from test_interactive_shell import Input
    path = tmp_path / 'case.db'
    legacy(path)
    before = path.read_bytes()
    state = State(None)
    state.remember(path)
    shell = Shell(state, Input(''), no_color=True)
    activated = []
    monkeypatch.setattr(shell, 'activate', activated.append)
    monkeypatch.setattr(shell, 'menu', lambda: pytest.fail('Remembered case rejected'))
    assert shell.startup() and activated == [str(path.resolve())]
    assert 'Remembered database unavailable' not in capsys.readouterr().out
    assert path.read_bytes() == before

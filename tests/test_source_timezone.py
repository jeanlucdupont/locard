"""Declarative source metadata: synthetic cases only, no timestamp conversion."""
from contextlib import closing, contextmanager
import io

import pytest

from forensic_assistant.database import sources, source_timezone
from forensic_assistant.database.db import connect, register_source
from forensic_assistant.cli import build_parser
from forensic_assistant import source_cli, activity
from forensic_assistant.interactive import setup, setup_display
from forensic_assistant.terminal import Palette, SGR
from forensic_assistant.semantic.documents import fingerprint
from test_add_evidence import opened, manual, rows
from test_interactive_shell import Input
from v2_fixtures import mft_file


@pytest.mark.parametrize('value', ['America/Chicago', 'Europe/Paris', 'UTC', '', None])
def test_iana(value):
    assert source_timezone.validate(value) == (value or None)


@pytest.mark.parametrize('value', ['Mars/Invented', 'Chicago', '../UTC', '/UTC', ' UTC', 'UTC\x00', 12])
def test_invalid(value):
    with pytest.raises(ValueError):
        source_timezone.validate(value)


def test_missing_database_is_distinct_and_unknown_still_works(monkeypatch):
    def unavailable(value):
        raise source_timezone.ZoneInfoNotFoundError(value)
    monkeypatch.setattr(source_timezone, 'ZoneInfo', unavailable)
    with pytest.raises(ValueError, match='database is unavailable.*tzdata'):
        source_timezone.validate('America/Chicago')
    assert source_timezone.validate('') is None


def test_legacy_reads_no_migration_and_explicit_extension_rolls_back():
    with closing(connect(':memory:')) as db:
        db.execute('ALTER TABLE source_assertions DROP COLUMN time_zone')
        with db:
            sid = sources.create(db, name='Legacy')
        before = fingerprint(db)
        assert sources.detail(db, sid)['assertion_history']['records'][0]['time_zone'] is None
        assert sources.listing(db)['sources'][0]['time_zone'] is None
        assert fingerprint(db) == before and not source_timezone.has_column(db)
        with pytest.raises(RuntimeError):
            with db:
                sources.update(db, sid, time_zone='America/Chicago')
                assert source_timezone.has_column(db)
                raise RuntimeError('rollback')
        assert fingerprint(db) == before and not source_timezone.has_column(db)
        with db:
            sources.update(db, sid, time_zone='America/Chicago')
        history = sources.detail(db, sid)['assertion_history']['records']
        assert [r['time_zone'] for r in history] == [None, 'America/Chicago']
        assert fingerprint(db) != before
        assert db.execute('PRAGMA user_version').fetchone()[0] == 5


def test_metadata_revisions_preserve_all_other_tables():
    with closing(connect(':memory:')) as db:
        with db:
            register_source(db, 'a' * 64, 10, 'synthetic.pf')
            a = sources.create(db, name='A', time_zone='America/Chicago')
            b = sources.create(db, name='B', time_zone='Europe/Paris')
            sources.assign(db, a, ['a' * 64], reason='Synthetic association')
            db.execute('INSERT INTO evidence_records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       ('synthetic-id', 'mft', 'mft', 'a' * 64, 'synthetic.mft', '{}',
                        None, None, 'synthetic', '1', '1', '[]', '{}'))
            db.execute('INSERT INTO evidence_timestamps VALUES (?,?,?,?,?,?,?,?,?)',
                       ('synthetic-id', 'SI.created', '2026-01-01T07:30:00Z', 'local 01:30',
                        'synthetic', 'SI', 'created', 100, 'normalized'))
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'") if r[0] != 'source_assertions']
        def snapshot():
            return {t: [tuple(r) for r in db.execute('SELECT * FROM "' + t + '"')] for t in tables}
        before = snapshot()
        with db:
            sources.update(db, a, time_zone='UTC')
            sources.update(db, a, hostname='new-host')
            sources.update(db, a, time_zone='')
        assert snapshot() == before
        history = sources.detail(db, a)['assertion_history']['records']
        assert [r['time_zone'] for r in history] == ['America/Chicago', 'UTC', 'UTC', None]
        assert all(r['basis'] == 'analyst-supplied' for r in history)
        assert sources.current(db, b)['time_zone'] == 'Europe/Paris'
        assert sources.memberships(db, 'a' * 64)[0]['source_id'] == a


def test_cli_preview_apply_clear_and_single_audit(monkeypatch):
    events = []
    @contextmanager
    def mutation(kind, **fields):
        result = {}
        yield result
        events.append((kind, fields, result))
    monkeypatch.setattr(activity, 'mutation', mutation)
    parser = build_parser()
    with closing(connect(':memory:')) as db:
        def run(*words):
            return source_cli.dispatch(db, parser.parse_args(['evidence', 'source', *words]))
        created = run('create', '--name', 'Synthetic', '--time-zone', 'America/Chicago')
        sid = created['source_id']
        assert created['time_zone'] == 'America/Chicago'
        before = fingerprint(db)
        assert not run('update', sid, '--time-zone', 'UTC')['applied']
        assert fingerprint(db) == before and len(events) == 1
        with pytest.raises(ValueError):
            run('update', sid, '--time-zone', 'Invented')
        changed = run('update', sid, '--time-zone', 'UTC', '--yes')
        assert 'Time zone: America/Chicago -> UTC' in source_cli.render_update(changed, Palette())
        run('update', sid, '--time-zone', '--yes')
        assert sources.current(db, sid)['time_zone'] is None
        assert [e[0] for e in events] == ['SOURCE_CREATE', 'SOURCE_UPDATE', 'SOURCE_UPDATE']
        assert events[1][2]['changes']['time_zone'] == dict(previous_value='America/Chicago', new_value='UTC')


@pytest.mark.parametrize('value', ['America/Chicago', ''])
def test_guided_prompt_confirmation_and_no_default(opened, tmp_path, capsys, value):
    path = tmp_path / 'evidence' / 'synthetic.mft'
    path.parent.mkdir()
    mft_file(path)
    opened.reader = Input(*manual(path, metadata=['Example', 'host', 'user', 'C:', value]))
    plan = setup.collect(opened, adding=True)
    assert plan.metadata['time_zone'] == (value or None)
    assert 'Time zone: ' + (value or 'unknown') in capsys.readouterr().out
    assert 'Source computer time zone (optional): ' in opened.reader.prompts
    assert rows(opened, 'source_assertions') == []  # collection is not consent to mutate


def test_guided_invalid_correction_and_cancel(opened, tmp_path, capsys):
    path = tmp_path / 'evidence' / 'synthetic.mft'
    path.parent.mkdir()
    mft_file(path)
    values = ['2', 'mft', str(path), '', 'yes', '', '', '', '', 'Invalid/Zone']
    opened.reader = Input(*values, 'Europe/Paris', 'yes')
    assert setup.collect(opened, adding=True).metadata['time_zone'] == 'Europe/Paris'
    assert 'Unknown IANA' in capsys.readouterr().out
    opened.reader = Input(*values, 'cancel')
    with pytest.raises(EOFError):
        setup.collect(opened, adding=True)
    assert rows(opened, 'source_assertions') == []


def test_guided_confirmed_metadata_has_one_audit_and_assertion(opened, monkeypatch):
    events = []
    @contextmanager
    def mutation(kind, **fields):
        result = {}
        yield result
        events.append((kind, result))
    monkeypatch.setattr(activity, 'mutation', mutation)
    plan = setup.Plan('Synthetic', '', '', opened.active,
                      metadata=dict(name='Source', time_zone='America/Chicago'))
    setup.execute(plan, opened.audit, Palette())
    assertions = rows(opened, 'source_assertions')
    assert len(assertions) == 1 and assertions[0]['time_zone'] == 'America/Chicago'
    assert len(events) == 1 and events[0][0] == 'SOURCE_CREATE'
    assert events[0][1]['assertion']['time_zone'] == 'America/Chicago'


def test_wizard_question_uses_existing_reader_coloring_once(monkeypatch):
    from types import SimpleNamespace
    from forensic_assistant.session_recording import ReaderProxy
    from forensic_assistant import terminal
    monkeypatch.setattr(terminal, 'enabled', lambda *a, **k: True)
    reader = Input('UTC')
    shell = SimpleNamespace(reader=ReaderProxy(reader))
    assert setup.read_input(shell, Palette(True), 'Time zone: ') == 'UTC'
    assert reader.prompts == [Palette(True)('question', 'Time zone: ')]


def test_discovery_roles_and_plain_projection(tmp_path):
    inv = setup.discovery.Inventory()
    (tmp_path / 'History').write_bytes(b'synthetic')
    inv.add(tmp_path / 'History', 'browser', 'Edge location')
    inv.unsupported.append(tmp_path / 'pagefile.sys')
    inv.profiles_scanned = True
    inv.profiles_found = 2
    inv.redirected['User profiles'].add(tmp_path / 'junction')
    plain = setup.inventory_text(inv, details=True, palette=Palette(False))
    color = setup.inventory_text(inv, details=True, palette=Palette(True))
    assert SGR.sub('', color) == plain and '\x1b' not in plain
    assert Palette(True)('value', 'browser'.ljust(10)) in color
    assert Palette(True)('unknown', ' — not currently supported') in color
    assert Palette(True)('value', str(tmp_path / 'History')) in color


@pytest.mark.parametrize('answers,expected', [(['all'], 2), (['none'], 0), (['2'], 1), (['', '2,1'], 2)])
def test_browser_selection_syntax_and_no_multiple_default(tmp_path, capsys, answers, expected):
    items = [setup.discovery.Candidate(tmp_path / str(n), 'browser', browser_product='edge',
                                       owner='synthetic', profile=f'Profile {n}') for n in (1, 2)]
    reader = Input(*answers)
    selected, options = setup.browser_selection(items, reader.read, Palette(True))
    assert len(selected) == len(options) == expected
    assert set(reader.prompts) == {'Select profiles (all, none, or numbers): '}
    text = capsys.readouterr().out
    assert Palette(True)('forensic_note', 'Location labels are not asserted Windows identities. Selection confirms browser/profile context.') in text
    single, options = setup.browser_selection(items[:1], Input('').read, Palette())
    assert single == items[:1] and len(options) == 1


@pytest.mark.parametrize('kind', ['mft', 'registry', 'prefetch', 'evtx', 'browser'])
def test_progress_uses_shared_role(kind, monkeypatch):
    seen = []
    monkeypatch.setattr(setup_display, 'replace_progress_line', lambda text, stream: seen.append(text) or True)
    meter = setup_display.FileProgress(kind, 4, Palette(True), stream=io.StringIO(), clock=lambda: 0)
    meter.animated = True
    meter._frame()
    assert seen == [Palette(True)('progress', meter.frames[0] + f' {kind}  0 / 4 files  0%  00:00 elapsed  0 records stored')]

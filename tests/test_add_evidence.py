"""Append-only guided additions using synthetic artifacts and existing ingestion."""
from contextlib import closing

import pytest

from forensic_assistant import activity, v2_cli
from forensic_assistant.cli import build_parser, get_thin
from forensic_assistant.database.db import connect
from forensic_assistant.interactive import creation, setup, setup_display, workspace
from forensic_assistant.interactive.completion import complete
from forensic_assistant.interactive.help import catalog, command_help
from forensic_assistant.interactive.shell import Shell, Mode
from forensic_assistant.interactive.state import State
from forensic_assistant.terminal import Palette
from test_interactive_shell import Input
from test_guided_setup import tree, snapshot
from v2_fixtures import mft_file, prefetch_file


@pytest.fixture
def opened(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(workspace, 'cases_root', lambda: tmp_path / 'cases')
    monkeypatch.setattr(workspace, 'elevated', lambda: True)
    shell = Shell(State(None), Input('Human case', 'Examiner', 'Organization', '3', 'yes'), no_color=True)
    assert setup.create(shell)
    capsys.readouterr()
    def forbidden(*args, **kwargs):
        pytest.fail('Adding evidence must not initialize or activate a case')
    monkeypatch.setattr(workspace, 'initialize', forbidden)
    monkeypatch.setattr(creation, 'initialize', forbidden)
    monkeypatch.setattr(shell, 'activate', forbidden)
    yield shell
    shell.audit.end('test complete')


def manual(path, kind='mft', metadata=None, confirm='yes'):
    return ['2', kind, str(path), '', '1', *(['yes', *metadata] if metadata else ['n']), confirm]


def rows(shell, table):
    with closing(connect(shell.active, existing_only=True)) as db:
        return [dict(row) for row in db.execute('SELECT * FROM ' + table)]


def test_navigation_documentation_and_completion():
    assert 'add-evidence' in catalog(build_parser())
    text = command_help('add-evidence')
    for phrase in ('current case', 'manual', 'source metadata', 'preserved', '$MFT', 'cancel'):
        assert phrase in text
    assert complete('add-e', 5).text == 'add-evidence '
    # Interactive workflow does not introduce a JSON/non-interactive command.
    with pytest.raises(SystemExit):
        build_parser().parse_args(['add-evidence'])


@pytest.mark.parametrize('mode', [Mode.EXPERT, Mode.AI])
def test_append_preserves_case_sources_ids_and_mode(opened, tmp_path, capsys, mode):
    shell = opened
    root = tmp_path / 'evidence'
    root.mkdir()
    first, second = root / 'mft', root / 'new.pf'
    mft_file(first)
    prefetch_file(second)
    before_evidence = snapshot(root)
    shell.mode = mode
    target, session, recent = shell.active, shell.audit, list(shell.state.recent)
    shell.reader = Input(*manual(first, metadata=['first', 'HOST-A', 'user-a', 'C:']))
    assert setup.add_evidence(shell)
    old_records = rows(shell, 'evidence_records')
    old_assertions = rows(shell, 'source_assertions')
    assert old_records and old_assertions
    capsys.readouterr()
    shell.reader = Input(*manual(second, 'prefetch', ['second', 'HOST-B', 'user-b', 'D:']))
    assert setup.add_evidence(shell)
    text = capsys.readouterr().out
    assert 'Evidence added to case.' in text and 'Case created' not in text
    assert get_thin() in text
    assert shell.active == target and shell.audit is session and shell.mode is mode
    assert shell.case_label == 'Human case' and shell.state.recent == recent
    assert len(list((tmp_path / 'cases').rglob('case.db'))) == 1
    new_records = rows(shell, 'evidence_records')
    assert len(new_records) > len(old_records)
    assert all(record in new_records for record in old_records)
    assertions = rows(shell, 'source_assertions')
    assert all(record in assertions for record in old_assertions)
    assert {row['hostname'] for row in assertions} == {'host-a', 'host-b'}
    assert len(rows(shell, 'sources')) == 2
    assert len({row['source_id'] for row in rows(shell, 'ingestion_batches')}) == 2
    with closing(connect(target, existing_only=True)) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 5
    audit = activity.inspect(activity.sidecar(target), 100)
    assert audit['valid'] and 'Examiner' in str(audit) and 'Organization' in str(audit)
    assert 'ADD_EVIDENCE' in str(audit)
    assert snapshot(root) == before_evidence
    assert not any('Case name:' in p or 'Analyst name' in p or 'Organization' in p for p in shell.reader.prompts)
    assert 'Add selected evidence to this case? [Y/n]: ' in shell.reader.prompts


@pytest.mark.parametrize('mode', [Mode.EXPERT, Mode.AI])
@pytest.mark.parametrize('stop', ['cancel', '3', 'selection', 'decline', 'interrupt'])
def test_preconfirmation_cancellation_changes_nothing(opened, tmp_path, capsys, mode, stop):
    shell = opened
    root = tmp_path / 'evidence'
    root.mkdir()
    path = root / 'mft'
    mft_file(path)
    lines = {'cancel': ['cancel'], '3': ['3'], 'selection': ['2', 'mft', str(path), '', 'cancel'],
             'decline': manual(path, confirm='n'), 'interrupt': [KeyboardInterrupt()]}[stop]
    shell.mode = mode
    before = snapshot(tmp_path)
    current, audit, recent = shell.active, shell.audit, list(shell.state.recent)
    shell.reader = Input(*lines)
    assert not setup.add_evidence(shell)
    assert snapshot(tmp_path) == before
    assert shell.active == current and shell.audit is audit and shell.mode is mode
    assert shell.state.recent == recent
    assert 'cancelled' in capsys.readouterr().out


def test_duplicate_only_is_honest_and_retains_evidence(opened, tmp_path, capsys):
    root = tmp_path / 'evidence'
    root.mkdir()
    path = root / 'mft'
    mft_file(path)
    opened.reader = Input(*manual(path))
    assert setup.add_evidence(opened)
    original = rows(opened, 'evidence_records')
    capsys.readouterr()
    opened.reader = Input(*manual(path))
    assert setup.add_evidence(opened)
    text = capsys.readouterr().out
    assert 'No new evidence records were added.' in text
    assert 'Evidence added to case.' not in text
    assert '0 new records' in text
    assert rows(opened, 'evidence_records') == original
    assert len(rows(opened, 'sources')) == 2
    runs = rows(opened, 'ingestion_runs')
    assert sum(r['duplicate_count'] for r in runs) == len(original)


def test_failure_summary_does_not_count_old_evidence(opened, tmp_path, capsys):
    root = tree(tmp_path / 'evidence')
    opened.reader = Input(*manual(root / '$MFT'))
    assert setup.add_evidence(opened)
    old = rows(opened, 'evidence_records')
    capsys.readouterr()
    opened.reader = Input(*manual(root / 'Windows/System32/winevt/Logs/System.evtx', 'evtx'))
    assert not setup.add_evidence(opened)
    text = capsys.readouterr().out
    assert 'No evidence was added. Selected evidence ingestion failed.' in text
    assert 'Evidence added to case.' not in text
    assert rows(opened, 'evidence_records') == old
    assert activity.inspect(activity.sidecar(opened.active))['valid']
    capsys.readouterr()
    opened.reader = Input(*manual(root / 'Windows/Prefetch/TEST.EXE-1234.pf', 'prefetch'))
    assert setup.add_evidence(opened)
    text = capsys.readouterr().out
    assert 'Other ingestion limitations and errors' not in text
    assert 'EVTX ingestion limitations' not in text
    assert '0 errors' in text


@pytest.mark.parametrize('found', [True, False])
def test_scan_partial_and_browser_absence_vs_selection(opened, tmp_path, capsys, found):
    root = tree(tmp_path / 'evidence')
    if not found:
        for path in root.rglob('History'):
            path.unlink()  # Only this test's generated fixtures.
    opened.reader = Input('1', str(root), '1', *(['none'] if found else []), 'n', 'yes')
    assert setup.add_evidence(opened)
    text = capsys.readouterr().out
    assert 'Evidence added to case. Ingestion completed with limitations.' in text
    assert 'browser   ' + ('not selected' if found else 'no supported history found') in text
    assert {r['source_type'] for r in rows(opened, 'evidence_records')} == {'mft', 'registry', 'prefetch'}


def test_mid_ingestion_cancel_retains_committed_records(opened, tmp_path, monkeypatch, capsys):
    root = tree(tmp_path / 'evidence')
    original = v2_cli.ingest_sources
    calls = []
    def interrupted(db, args, callback):
        calls.append(args.command)
        if len(calls) == 2:
            raise KeyboardInterrupt
        return original(db, args, callback)
    monkeypatch.setattr(v2_cli, 'ingest_sources', interrupted)
    opened.mode = Mode.AI
    opened.reader = Input('1', str(root), '2', 'mft,prefetch', 'n', 'yes')
    assert not setup.add_evidence(opened)
    assert {r['source_type'] for r in rows(opened, 'evidence_records')} == {'mft'}
    assert opened.mode is Mode.AI
    assert 'Already committed evidence and provenance were retained' in capsys.readouterr().out
    assert activity.inspect(activity.sidecar(opened.active))['valid']


def test_semantic_completion_colors_and_zero_record_outcome():
    p = Palette(True)
    plan = setup.Plan('case', '', '', None)
    totals = setup.Progress()
    totals.records = 1
    assert setup_display.addition_line(plan, {'mft': 'complete', 'evtx': 'failed'}, totals, p) == (
        p('success', 'Evidence added to case.') + ' ' + p('warning', 'Ingestion completed with limitations.'))
    totals.records = 0
    assert setup_display.addition_line(plan, {'mft': 'complete'}, totals, p) == p(
        'warning', 'No evidence records were added. Review the ingestion outcomes.')
    assert setup_display.addition_line(plan, {'evtx': 'failed'}, totals, p) == p(
        'error', 'No evidence was added. Selected evidence ingestion failed.')


@pytest.mark.parametrize('mode', [Mode.EXPERT, Mode.AI])
def test_shell_dispatch_mode_prompt_and_reject_arguments(opened, monkeypatch, capsys, mode):
    shell = opened
    shell.mode = mode
    monkeypatch.setattr(shell, 'startup', lambda: True)
    shell.reader = Input('help add-evidence', 'add-evidence unexpected', 'add-evidence', 'cancel', 'exit')
    assert shell.run() == 0
    text = capsys.readouterr().out
    assert 'add-evidence takes no arguments' in text
    assert 'Add evidence to case: Human case' in text
    assert shell.mode is mode
    assert '[Human case]' + ('# ' if mode is Mode.AI else '> ') in shell.reader.prompts


def test_no_active_case_does_not_create(tmp_path, capsys):
    shell = Shell(State(None), Input(), no_color=True)
    before = snapshot(tmp_path)
    assert not setup.add_evidence(shell)
    assert 'No case is currently open.' in capsys.readouterr().out
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize('with_prefetch', [True, False])
def test_mounted_mft_deferred_without_raw_access(opened, tmp_path, monkeypatch, capsys, with_prefetch):
    from pathlib import Path
    from forensic_assistant.interactive import discovery
    root = tree(tmp_path / 'evidence')
    original = Path.open
    def denied(path, *args, **kwargs):
        if path == root / '$MFT':
            raise PermissionError('synthetic mounted MFT denial')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', denied)
    monkeypatch.setattr(discovery, 'mounted_mft', lambda path: path == root / '$MFT')
    opened.reader = Input('1', str(root), '2', 'mft,prefetch' if with_prefetch else 'mft',
                          *(['n'] if with_prefetch else []), 'yes')
    assert setup.add_evidence(opened) is with_prefetch
    text = capsys.readouterr().out
    assert 'extract $MFT as a standard file' in text
    assert 'requires extraction' in text and 'Direct ingestion: unavailable' in text
    assert len(rows(opened, 'ingestion_runs')) == int(with_prefetch)
    assert len(rows(opened, 'sources')) == int(with_prefetch)
    assert {r['source_type'] for r in rows(opened, 'evidence_records')} == ({'prefetch'} if with_prefetch else set())


def test_audit_intent_failure_blocks_all_ingestion(opened, tmp_path, monkeypatch, capsys):
    root = tmp_path / 'evidence'
    root.mkdir()
    path = root / 'mft'
    mft_file(path)
    original = opened.audit.record
    def fail(action, *args, **kwargs):
        if action == 'ADD_EVIDENCE':
            raise activity.AuditError('Synthetic audit intent failure')
        return original(action, *args, **kwargs)
    monkeypatch.setattr(opened.audit, 'record', fail)
    monkeypatch.setattr(v2_cli, 'ingest_sources', lambda *a, **k: pytest.fail('No ingestion without audit intent'))
    opened.reader = Input(*manual(path))
    assert not setup.add_evidence(opened)
    assert not rows(opened, 'sources') and not rows(opened, 'evidence_records')
    assert 'Synthetic audit intent failure' in capsys.readouterr().out


def test_failed_worker_cleanup_does_not_return_to_prompt(opened, tmp_path, monkeypatch):
    from forensic_assistant.investigation_ai.lifecycle import CleanupError
    root = tmp_path / 'evidence'
    root.mkdir()
    path = root / 'mft'
    mft_file(path)
    def fail(*a, **kw):
        raise CleanupError('Synthetic worker cleanup failure')
    monkeypatch.setattr(v2_cli, 'ingest_sources', fail)
    opened.reader = Input(*manual(path))
    with pytest.raises(CleanupError):
        setup.add_evidence(opened)


def test_browser_subset_uses_existing_context_and_occurrence_provenance(opened, tmp_path):
    root = tree(tmp_path / 'evidence')
    opened.reader = Input('1', str(root), '2', 'browser', '1', 'n', 'yes')
    assert setup.add_evidence(opened)
    contexts = rows(opened, 'browser_contexts')
    occurrences = rows(opened, 'browser_record_occurrences')
    assert len(contexts) == 1 and occurrences
    assert len(rows(opened, 'sources')) == 1
    assert len(rows(opened, 'ingestion_runs')) == 1
    assert {r['source_type'] for r in rows(opened, 'evidence_records')} == {'browser'}
    assert activity.inspect(activity.sidecar(opened.active), 100)['valid']


@pytest.mark.parametrize('mode', [Mode.EXPERT, Mode.AI])
def test_shell_success_returns_to_same_case_and_mode(opened, tmp_path, monkeypatch, capsys, mode):
    path = tmp_path / 'evidence' / 'mft'
    path.parent.mkdir()
    mft_file(path)
    opened.mode = mode
    monkeypatch.setattr(opened, 'startup', lambda: True)
    opened.reader = Input('add-evidence', *manual(path), 'exit')
    assert opened.run() == 0
    assert opened.mode is mode and opened.last_status == 0
    assert rows(opened, 'evidence_records')
    assert 'Evidence added to case.' in capsys.readouterr().out
    prompt = '[Human case]' + ('# ' if mode is Mode.AI else '> ')
    assert opened.reader.prompts.count(prompt) == 2

"""6.48 examiner-facing cleanup with synthetic evidence; no parser changes."""
from contextlib import closing

import pytest

from forensic_assistant.artifacts.context import normalize_volume_root
from forensic_assistant.cli import build_parser
from forensic_assistant.database.db import connect
from forensic_assistant.interactive import setup, setup_display, workspace, creation
from forensic_assistant.interactive.metadata import read_volume_root
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.terminal import Palette, SGR
from test_add_evidence import opened, manual, rows
from test_guided_setup import tree, snapshot
from test_interactive_shell import Input
from v2_fixtures import mft_file


@pytest.mark.parametrize('value,expected', [('C:', 'C:'), ('c:', 'C:'), ('C', 'C:'), ('c', 'C:'), ('', None)])
def test_prompt_volume_normalization(value, expected):
    assert read_volume_root(Input(value).read, 'Volume: ', Palette()) == expected


@pytest.mark.parametrize('invalid', ['C:\\folder', 'foo', r'\\server\share', 'CC', '1', 'é'])
def test_invalid_volume_reprompts_without_weakening_core_validator(invalid, capsys):
    reader = Input(invalid, 'c:')
    assert read_volume_root(reader.read, 'Volume: ', Palette()) == 'C:'
    assert reader.prompts == ['Volume: ', 'Volume: ']
    assert 'Please enter a drive letter followed by a colon, for example C:.' in capsys.readouterr().out
    with pytest.raises(ValueError):
        normalize_volume_root(invalid)
    with pytest.raises(ValueError):
        normalize_volume_root('C')  # CLI/core validation is unchanged.


def test_invalid_field_retains_selection_and_ingests_with_corrected_source(opened, tmp_path, capsys):
    path = tmp_path / 'evidence' / 'mft'
    path.parent.mkdir()
    mft_file(path)
    opened.reader = Input('2', 'mft', str(path), '', 'yes', 'New source', 'HOST-A', 'UserA',
                          'C:\\folder', 'foo', r'\\server\share', 'c', 'yes')
    assert setup.add_evidence(opened)
    text = capsys.readouterr().out
    assert 'Evidence addition failed' not in text
    assert opened.reader.prompts.count('Evidence file or folder: ') == 1
    assert opened.reader.prompts.count('Original volume root, e.g. C: (optional): ') == 4
    assertions = rows(opened, 'source_assertions')
    assert len(assertions) == 1
    assert assertions[0]['volume_root'] == 'C:' and assertions[0]['hostname'] == 'host-a'
    assert assertions[0]['username'] == 'UserA'
    assert len(rows(opened, 'ingestion_runs')) == 1
    assert not hasattr(opened, 'mode')


def test_cancel_after_invalid_volume_changes_nothing(opened, tmp_path):
    path = tmp_path / 'evidence' / 'mft'
    path.parent.mkdir()
    mft_file(path)
    before = snapshot(tmp_path)
    opened.reader = Input('2', 'mft', str(path), '', 'yes', '', '', '', 'foo', 'cancel')
    assert not setup.add_evidence(opened)
    assert snapshot(tmp_path) == before


def test_direct_interactive_new_source_uses_same_volume_prompt(opened):
    from forensic_assistant.interactive.sources import prepare
    args = build_parser().parse_args(['ingest-mft', 'synthetic-file'])
    opened.reader = Input('N', 'Source', '', '', 'foo', 'c')
    assert prepare(opened, args)
    assert args.volume_root == 'C:' and args.source_explicit
    assert not rows(opened, 'sources')  # Selection still does not persist a source.


def test_legacy_case_creation_volume_reprompts(tmp_path):
    path = tmp_path / 'evidence' / 'mft'
    path.parent.mkdir()
    mft_file(path)
    target = tmp_path / 'case.db'
    shell = Shell(State(None), Input(str(target), str(path), 'Source', '', '', 'foo', 'c', 'yes'), no_color=True)
    assert creation.create(shell)
    with closing(connect(target, existing_only=True)) as db:
        assert db.execute('SELECT volume_root FROM source_assertions').fetchone()[0] == 'C:'
    shell.audit.end()


def test_simple_success_is_terse_but_keeps_provenance_and_colors(opened, tmp_path, monkeypatch, capsys):
    path = tmp_path / 'evidence' / 'mft'
    path.parent.mkdir()
    mft_file(path)
    monkeypatch.setattr(setup, 'enabled', lambda shell: True)
    clock = iter([100, 100.5])
    monkeypatch.setattr(setup, 'monotonic', lambda: next(clock))
    opened.reader = Input(*manual(path))
    assert setup.add_evidence(opened)
    colored = capsys.readouterr().out
    text = SGR.sub('', colored)
    ingestion = text.split('Ingestion is starting.', 1)[1]
    assert 'mft: complete |' in ingestion
    assert 'File outcomes:' not in ingestion and 'Added evidence' not in ingestion
    assert 'Large evidence sets can take several minutes.' not in ingestion
    assert 'Source\n' not in ingestion and str(path) not in ingestion
    assert 'continue investigating' not in ingestion
    assert 'Elapsed time: <1 sec' in ingestion
    palette = Palette(True)
    for value in ('complete', '0 duplicates', '0 errors', 'Evidence added to case.'):
        assert palette('success', value) in colored
    assert rows(opened, 'evidence_records')
    assert rows(opened, 'ingestion_batches')[0]['requested_path'] == str(path)
    assert rows(opened, 'source_assertions')


def test_complex_outcomes_keep_detail(opened, tmp_path, capsys):
    root = tree(tmp_path / 'evidence')
    opened.reader = Input('1', str(root), '1', 'none', 'n', 'yes')
    assert setup.add_evidence(opened)
    text = capsys.readouterr().out
    assert 'File outcomes:' in text and 'partial' in text and 'unsupported' in text
    assert 'Registry transaction logs detected but not replayed' in text
    assert 'Ingestion completed with limitations.' in text
    assert 'Added evidence' in text
    assert 'Source\n' not in text.split('Evidence added to case.', 1)[1]
    assert {r['source_type'] for r in rows(opened, 'evidence_records')} == {'mft', 'registry', 'prefetch'}


@pytest.mark.parametrize('statuses,records,duplicates,errors,limits,simple', [
    ({'complete': 1}, 3, 0, 0, {}, True),
    ({'complete': 2}, 3, 0, 0, {}, False),
    ({'complete': 1, 'failed': 1}, 3, 0, 1, {}, False),
    ({'partial': 1}, 3, 0, 1, {}, False),
    ({'unsupported': 1}, 0, 0, 0, {}, False),
    ({'complete': 1}, 0, 3, 0, {}, False),
    ({'complete': 1}, 3, 0, 0, {'limitation': 1}, False),
    ({'complete': 1}, 0, 0, 0, {}, False),
])
def test_simple_success_never_hides_exceptions(statuses, records, duplicates, errors, limits, simple):
    progress = setup.Progress()
    progress.statuses.update(statuses)
    progress.records, progress.duplicates, progress.errors = records, duplicates, errors
    progress.limitations.update(limits)
    assert setup_display.simple_success(progress) is simple


def test_collision_is_readable_reprompts_and_never_overwrites(opened, tmp_path, capsys):
    before = snapshot(tmp_path)
    active = opened.active
    opened.reader = Input('Human case', 'cancel')
    assert not setup.create(opened)
    text = capsys.readouterr().out
    assert 'A case named "Human case" already exists.' in text
    assert 'Choose a different case name, or open the existing case.' in text
    assert opened.reader.prompts.count('Case name: ') == 2
    assert opened.active == active and snapshot(tmp_path) == before


def test_multiple_complete_files_keep_file_outcomes(opened, tmp_path, capsys):
    from v2_fixtures import prefetch_file
    root = tmp_path / 'evidence'
    root.mkdir()
    prefetch_file(root / 'one.pf', name='ONE.EXE')
    prefetch_file(root / 'two.pf', name='TWO.EXE')
    opened.reader = Input(*manual(root, 'prefetch'))
    assert setup.add_evidence(opened)
    text = capsys.readouterr().out
    assert 'File outcomes: 2 complete' in text
    assert 'Added evidence' in text
    assert len(rows(opened, 'ingestion_runs')) == 2


def test_guided_case_creation_uses_reprompting_volume_field(tmp_path, monkeypatch):
    monkeypatch.setattr(workspace, 'cases_root', lambda: tmp_path / 'cases')
    path = tmp_path / 'evidence' / 'mft'
    path.parent.mkdir()
    mft_file(path)
    shell = Shell(State(None), Input('Volume case', '', '', '2', 'mft', str(path), '',
                                    'yes', 'Source', '', '', 'foo', 'c', 'yes'), no_color=True)
    assert setup.create(shell)
    assert shell.reader.prompts.count('Original volume root, e.g. C: (optional): ') == 2
    assert rows(shell, 'source_assertions')[0]['volume_root'] == 'C:'
    assert len(rows(shell, 'ingestion_runs')) == 1
    shell.audit.end()

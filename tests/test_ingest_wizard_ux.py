"""6.47 guided presentation; synthetic evidence and a patched monotonic clock."""
import pytest

from forensic_assistant.cli import build_parser, get_thin
from forensic_assistant.interactive import setup, setup_display, creation, workspace
from forensic_assistant.interactive.help import catalog, command_help
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from test_add_evidence import opened, manual, rows
from test_interactive_shell import Input
from test_guided_setup import tree
from v2_fixtures import mft_file


@pytest.mark.parametrize('seconds,expected', [(0, '<1 sec'), (.9, '<1 sec'), (1, '1 sec'), (42.9, '42 sec'),
    (59.99, '59 sec'), (60, '1 min 0 sec'), (402.283, '6 min 42 sec'),
    (3599, '59 min 59 sec'), (3600, '1 hr 0 min'), (4320, '1 hr 12 min')])
def test_elapsed_format(seconds, expected):
    assert setup_display.duration(seconds) == expected


@pytest.mark.parametrize('mode', ['expert', 'ai'])
@pytest.mark.parametrize('command', ['ingest wizard', 'ingest-wizard', 'add-evidence'])
def test_canonical_and_alias_dispatch_same_workflow(opened, monkeypatch, capsys, mode, command):
    seen = []
    def workflow(shell):
        seen.append((shell.active, hasattr(shell, 'mode')))
        return True
    monkeypatch.setattr(setup, 'add_evidence', workflow)
    monkeypatch.setattr(opened, 'startup', lambda: True)
    opened.reader = Input(mode, command + ' unexpected', command, 'exit')
    assert opened.run() == 0
    assert seen == [(opened.active, False)]
    assert not hasattr(opened, 'mode')
    text = capsys.readouterr().out
    assert 'ingest wizard takes no arguments' in text
    assert ('is deprecated' in text) is (command != 'ingest wizard')


def test_canonical_help_and_direct_ingestion_unchanged():
    text = catalog(build_parser())
    assert 'ingest' in text and 'ingest-wizard' not in text and 'add-evidence' not in text
    assert 'ingest wizard' in command_help('add-evidence')
    details = command_help('ingest-wizard')
    for phrase in ('manual evidence selection', 'Direct ingest subcommands', 'analyst supplied', 'cancel', '$MFT'):
        assert phrase in details
    # These are the existing direct commands, not new wizard parsers.
    for kind in ('mft', 'registry', 'prefetch', 'evtx'):
        parsed = build_parser().parse_args(['ingest-' + kind, 'synthetic-file'])
        assert parsed.command == 'ingest-' + kind and parsed.path == 'synthetic-file'


def test_manual_short_path_and_operation_only_summary(opened, tmp_path, capsys):
    path = tmp_path / 'evidence' / 'mft'
    path.parent.mkdir()
    mft_file(path)
    opened.reader = Input(*manual(path, metadata=['Extracted MFT', '', '', '']))
    assert setup.add_evidence(opened)
    text = capsys.readouterr().out
    assert 'Select evidence manually' in text
    assert any(p.startswith('Artifact type [') for p in opened.reader.prompts)
    assert 'Evidence file or folder: ' in opened.reader.prompts
    assert 'What would you like to do?' not in text
    assert 'Ingest all discovered artifacts' not in text
    assert 'Selected evidence' in text and '1 file' in text
    assert 'Optional analyst-supplied source assertions' not in text
    assert 'using the manual ingest commands' not in text
    assert 'Source metadata' in text and 'name: Extracted MFT' in text
    final = text.split('Evidence added to case.', 1)[1]
    assert 'Human case' not in final and 'Workspace' not in final
    assert 'Added evidence' not in final and 'mft: complete |' in text
    assert 'not selected' not in final
    assert 'Elapsed time:' in final
    assert get_thin() in text
    assert all(row['hostname'] is None for row in rows(opened, 'source_assertions'))


def test_scan_keeps_review_and_category_selection(opened, tmp_path, capsys):
    root = tree(tmp_path / 'evidence')
    opened.reader = Input('1', str(root), '3', '2', 'mft', 'n', 'yes')
    assert setup.add_evidence(opened)
    text = capsys.readouterr().out
    assert 'Artifacts found' in text and 'Review discovered paths' in text
    assert 'Enter categories separated by commas: ' in opened.reader.prompts
    assert {row['source_type'] for row in rows(opened, 'evidence_records')} == {'mft'}


@pytest.mark.parametrize('failed', [False, True])
def test_addition_clock_excludes_navigation_includes_summary(opened, tmp_path, monkeypatch, capsys, failed):
    root = tree(tmp_path / 'evidence')
    clock = {'now': 0, 'calls': []}
    def now():
        clock['calls'].append(clock['now'])
        return clock['now']
    monkeypatch.setattr(setup, 'monotonic', now)
    def confirm():
        assert clock['calls'] == []
        clock['now'] = 600  # Ten minutes of analyst navigation is excluded.
        return 'yes'
    original = setup.execute
    def execute(*args, **kwargs):
        assert clock['calls'] == [600]
        result = original(*args, **kwargs)
        clock['now'] = 642
        return result
    monkeypatch.setattr(setup, 'execute', execute)
    diagnostics = setup_display.print_diagnostics
    def summarize(*args, **kwargs):
        diagnostics(*args, **kwargs)
        clock['now'] = 660  # Summary work is included.
    monkeypatch.setattr(setup_display, 'print_diagnostics', summarize)
    path = root / 'Windows/System32/winevt/Logs/System.evtx' if failed else root / '$MFT'
    opened.reader = Input(*manual(path, 'evtx' if failed else 'mft', confirm=confirm))
    assert setup.add_evidence(opened) is not failed
    text = capsys.readouterr().out
    assert clock['calls'] == [600, 660]
    assert 'Elapsed time: 1 min 0 sec' in text
    if failed:
        assert 'No evidence was added. Selected evidence ingestion failed.' in text
        assert 'Evidence added to case.' not in text
        assert 'Added evidence' not in text


def test_creation_clock_and_preserved_manual_decoration(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(workspace, 'cases_root', lambda: tmp_path / 'cases')
    root = tmp_path / 'evidence'
    root.mkdir()
    path = root / 'mft'
    mft_file(path)
    clock = {'now': 0, 'calls': []}
    def now():
        clock['calls'].append(clock['now'])
        return clock['now']
    monkeypatch.setattr(setup, 'monotonic', now)
    def confirm():
        assert not clock['calls']
        clock['now'] = 600
        return 'yes'
    original = creation.summarize
    def summarize(*args, **kwargs):
        result = original(*args, **kwargs)
        clock['now'] = 1002.283
        return result
    monkeypatch.setattr(creation, 'summarize', summarize)
    shell = Shell(State(None), Input('Case name', 'Examiner', 'Lab', *manual(path, confirm=confirm)), no_color=True)
    assert setup.create(shell)
    text = capsys.readouterr().out
    assert clock['calls'] == [600, 1002.283]
    final = text.split('████ ', 1)[1]
    assert final.startswith('Case ready.')
    assert 'Elapsed time: 6 min 42 sec' in final
    assert 'Case\n' not in final and 'Workspace\n' not in final
    assert 'Ingestion' in final
    assert '\n\n' + get_thin() + '\nYou can add more evidence at any time' in final
    assert shell.case_label == 'Case name' and not hasattr(shell, 'mode')
    shell.audit.end()

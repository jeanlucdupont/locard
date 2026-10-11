"""6.45 human projections over synthetic evidence; raw semantics stay unchanged."""
from contextlib import closing
from pathlib import Path

import pytest

from forensic_assistant import activity
from forensic_assistant.database.db import connect
from forensic_assistant.interactive import discovery, setup, setup_display, workspace
from forensic_assistant.interactive.shell import Shell, Mode
from forensic_assistant.interactive.state import State
from forensic_assistant.terminal import Palette
from forensic_assistant.artifacts.registry_logs import LIMITATION
from forensic_assistant.ingest.evtx import ingest_file
from test_interactive_shell import Input
from test_guided_setup import tree, snapshot
from test_evtx_recovery import chunk, file_bytes, decode


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(workspace, 'cases_root', lambda: tmp_path / 'cases')
    monkeypatch.setattr(workspace, 'elevated', lambda: True)


def test_human_case_prompt_reopen_and_switch(tmp_path):
    shell = Shell(State(None), Input('my 3rd case', '', '', '3', 'yes'))
    assert setup.create(shell)
    first = shell.active
    shell.audit.end()
    reader = Input(str(first), 'ai', 'expert', 'exit')
    reopened = Shell(State(None), reader)
    assert reopened.run() == 0
    assert '[my 3rd case]> ' in reader.prompts and '[my 3rd case]# ' in reader.prompts
    assert not any('[case.db]' in p or '[my_3rd_case]' in p for p in reader.prompts)
    second = tmp_path / 'old-case.db'
    connect(second).close()
    reopened.activate(second)
    assert reopened.case_label == 'old-case.db'
    reopened.activate(first)
    assert reopened.case_label == 'my 3rd case'
    reopened.audit.end()


def test_label_fallback_and_sanitized_control_text(tmp_path):
    case = tmp_path / 'cases/fallback_name/case.db'
    case.parent.mkdir(parents=True)
    connect(case).close()
    assert workspace.case_label(case) == 'fallback_name'
    session = activity.Session(case)
    session.record('CASE_CREATE', required=True, case_name='name\x1b[31m')
    from forensic_assistant.interactive.console import safe
    assert '\x1b' not in safe(workspace.case_label(case))
    activity.sidecar(case).write_bytes(b'broken\n')
    assert workspace.case_label(case) == 'fallback_name'


@pytest.mark.parametrize('found', [False, True])
def test_browser_not_found_vs_not_selected(tmp_path, capsys, found):
    root = tree(tmp_path / 'evidence')
    if not found:
        for file in root.rglob('History'):
            file.unlink()  # Generated fixture setup only.
    before = snapshot(root)
    answers = ['Browser state', '', '', '1', str(root), '1']
    if found:
        answers.append('none')
    answers += ['', 'yes']
    shell = Shell(State(None), Input(*answers))
    assert setup.create(shell)
    output = capsys.readouterr().out
    assert ('browser   not selected' in output) is found
    assert ('browser   no supported history found' in output) is not found
    if not found:
        assert 'accessible profiles/locations scanned' in output
    assert 'Progress updates between files; no mid-file estimate.' not in output
    assert 'Reports\n' not in output and 'prefix natural-language requests with !' in output
    assert 'You can add more evidence to this case later' in output
    assert snapshot(root) == before


def test_profile_discovery_distinctions_and_unsupported_section(tmp_path, monkeypatch):
    root = tree(tmp_path / 'root')
    junction = root / 'Users/All Users'
    junction.mkdir()
    original = discovery.safe_path
    def reject(path):
        if path == junction:
            raise ValueError('File redirection rejected')
        return original(path)
    monkeypatch.setattr(discovery, 'safe_path', reject)
    inventory = discovery.scan(root)
    assert inventory.profiles_found == 1
    assert str(junction) in inventory.redirected['User profiles']
    assert str(junction) not in inventory.access_limits['User profiles']
    inventory.inaccessible(root / 'Users/denied', 'User profiles', 'PermissionError')
    text = setup.inventory_text(inventory)
    assert 'Profiles found: 1' in text and 'Inaccessible: 1' in text
    assert 'Redirected/junction entries skipped: 1' in text
    assert 'inaccessible/redirected' not in text
    assert 'Other forensic artifacts detected\n  pagefile.sys — not currently supported' in text
    assert str(junction) in setup.inventory_text(inventory, details=True)


def test_human_mappings_leave_input_unchanged():
    raw = LIMITATION
    text = setup_display.human_limitation(raw, 'registry', 3)
    assert text == 'Registry transaction logs detected but not replayed. Recent uncommitted Registry changes may be missing.'
    assert raw == LIMITATION
    text = setup_display.human_limitation('Source signature does not match requested artifact type', 'registry', 7)
    assert text == '7 files were skipped because they were not valid Registry hives.'
    assert 'expected artifact format' in setup_display.human_limitation('Source signature does not match requested artifact type')


class SemanticPalette:
    def __call__(self, role, text):
        return f'<{role}>{text}</{role}>'


@pytest.mark.parametrize('status,expected', [('requires extraction', 'error'), ('partial', 'warning'),
    ('complete', 'success'), ('failed', 'error'), ('not selected', 'secondary_text'),
    ('no supported history found', 'secondary_text')])
def test_summary_roles(status, expected):
    assert setup_display.role(status) == expected


def test_split_completion_colors():
    palette = SemanticPalette()
    assert setup_display.completion_line('Case created. Ingestion completed with limitations.', palette) == (
        '<success>Case created.</success><warning> Ingestion completed with limitations.</warning>')
    assert setup_display.completion_line('Case created, but selected evidence ingestion failed.', palette) == (
        '<success>Case created</success><error>, but selected evidence ingestion failed.</error>')
    assert setup_display.completion_line('Case ready.', palette) == '<success>Case ready.</success>'


def test_evtx_outcomes_and_raw_counters(tmp_path, decode, capsys):
    good = tmp_path / 'retained.evtx'
    good.write_bytes(file_bytes([chunk([1, 2]), chunk([3, 4])], declared=1, dirty=True, minor=2))
    empty = tmp_path / 'empty.evtx'
    empty.write_bytes(file_bytes([], minor=2))
    with closing(connect(':memory:')) as db:
        ingest_file(db, good)
        ingest_file(db, empty)
        before = [tuple(r) for r in db.execute('SELECT * FROM ingestion_runs')]
        errors = [tuple(r) for r in db.execute('SELECT * FROM ingestion_errors')]
        setup_display.print_diagnostics(db, Palette())
        text = capsys.readouterr().out
        assert '1 file had header verification issues, but records were recovered and retained.' in text
        assert 'additional validated EVTX chunks' in text
        assert 'could not be successfully ingested because header verification failed' in text
        assert [tuple(r) for r in db.execute('SELECT * FROM ingestion_runs')] == before
        assert [tuple(r) for r in db.execute('SELECT * FROM ingestion_errors')] == errors


def test_unconfirmed_retention_never_becomes_success():
    group = dict(files={'a'}, message='File header verification failed', limitation=False, no_records=False)
    assert 'inspect detailed ingestion diagnostics' in setup_display.evtx_diagnostic(group)
    assert 'recovered and retained' not in setup_display.evtx_diagnostic(group)

def test_registry_feedback_through_real_setup(tmp_path, capsys):
    root = tree(tmp_path / 'registry-source')
    (root / 'Windows/System32/config/SYSTEM').write_bytes(b'not a registry hive')
    before = snapshot(root)
    shell = Shell(State(None), Input('Registry feedback', '', '', '1', str(root), '2', 'registry', '', 'yes'))
    assert setup.create(shell)
    output = capsys.readouterr().out
    assert 'Registry transaction logs detected but not replayed.' in output
    assert 'Recent uncommitted Registry changes may be missing.' in output
    assert '1 file was skipped because it was not a valid Registry hive.' in output
    assert 'Source signature does not match requested artifact type' not in output
    assert 'transaction-log replay is not supported' not in output
    raw = activity.inspect(activity.sidecar(shell.active), 100)
    assert raw['valid'] and 'Source signature does not match requested artifact type' in str(raw)
    assert snapshot(root) == before

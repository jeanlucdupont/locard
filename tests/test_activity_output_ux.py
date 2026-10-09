"""Analyst-facing output authorization and audit ownership; synthetic data only."""
from contextlib import closing
import hashlib
import io
import json
from pathlib import Path

import pytest

from forensic_assistant import activity, output
from forensic_assistant.cli import main, build_parser
from forensic_assistant.database.db import connect
from forensic_assistant.interactive import completion, console, creation
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from test_interactive_shell import Input
from test_output_ux import case
from test_activity import records


def test_report_completion_failure_does_not_claim_unpublished(case, tmp_path, monkeypatch, capsys):
    path, eid, _ = case
    target = tmp_path / 'report'
    append = activity.append
    def denied(log_path, session_id, action, outcome, **fields):
        if action == 'OUTPUT_WRITE' and fields.get('phase') == 'complete':
            raise OSError('synthetic completion failure')
        return append(log_path, session_id, action, outcome, **fields)
    monkeypatch.setattr(activity, 'append', denied)
    assert main(['--db', str(path), 'report', 'generate', '--evidence', eid, '--output', str(target)]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result['published'] is True
    assert (target / 'manifest.json').is_file()
    assert any(e['action'] == 'OUTPUT_WRITE' and e['phase'] == 'intent' for e in records(path))


def test_failed_verification_can_export_diagnostics(case, tmp_path):
    path, _, _ = case
    main(['--db', str(path), 'status'])
    log = activity.sidecar(path)
    # Damage an interior entry; preserve a valid tail so output intent can append.
    content = log.read_bytes().replace(b'SESSION_START', b'CHANGED_START', 1)
    log.write_bytes(content)
    destination = tmp_path / 'verification.json'
    assert main(['--db', str(path), 'activity', '--verify', '--json', '--output', str(destination)]) == 2
    result = json.loads(destination.read_text())
    assert result['valid'] is False and result['first_invalid_entry'] == 1


@pytest.mark.parametrize('answer', ['', 'n', 'y', KeyboardInterrupt(), EOFError()])
def test_interactive_overwrite_is_explicit_and_audited(case, tmp_path, answer):
    path, _, _ = case
    target = tmp_path / 'notes.json'
    target.write_bytes(b'original work product')
    original = target.read_bytes()
    reader = Input(str(path), f'status --json --output "{target}"', answer, 'exit')
    Shell(State(None), reader).run()
    assert 'Overwrite? [y/N]: ' in reader.prompts
    events = [e for e in records(path) if e['action'] == 'OUTPUT_OVERWRITE']
    if answer == 'y':
        assert json.loads(target.read_text())['schema_version'] == 5
        event = next(e for e in events if e['outcome'] == 'success')
        assert event['previous_sha256'] == hashlib.sha256(original).hexdigest()
        assert event['new_sha256'] == hashlib.sha256(target.read_bytes()).hexdigest()
    else:
        assert target.read_bytes() == original
        assert len(events) == 1 and events[0]['outcome'] == 'cancelled'


def test_first_write_force_and_append_have_distinct_events(case, tmp_path, capsys):
    path, _, _ = case
    target = tmp_path / 'notes.json'
    base = ['--db', str(path), 'status', '--json']
    assert main(base + ['--output', str(target)]) == 0
    assert 'Output written to:' in capsys.readouterr().err
    first = target.read_bytes()
    assert main(base + ['--output', str(target)]) == 2
    assert 'use --force' in capsys.readouterr().err and target.read_bytes() == first
    assert main(base + ['--output', str(target), '--force']) == 0
    assert 'Output overwritten:' in capsys.readouterr().err
    before_append = target.read_bytes()
    assert main(base + ['--append', str(target)]) == 0
    assert 'Output appended to:' in capsys.readouterr().err
    completed = [e for e in records(path) if e['action'].startswith('OUTPUT_') and e['outcome'] == 'success']
    assert [e['action'] for e in completed] == ['OUTPUT_WRITE', 'OUTPUT_OVERWRITE', 'OUTPUT_APPEND']
    assert completed[-1]['previous_sha256'] == hashlib.sha256(before_append).hexdigest()
    assert completed[-1]['new_sha256'] == hashlib.sha256(target.read_bytes()).hexdigest()


@pytest.mark.parametrize('mode', ['--force', '--append'])
def test_force_and_append_never_prompt(case, tmp_path, mode):
    path, _, _ = case
    target = tmp_path / 'notes'
    target.write_text('old')
    flags = f'--output "{target}" --force' if mode == '--force' else f'--append "{target}"'
    reader = Input(str(path), 'status ' + flags, 'exit')
    Shell(State(None), reader).run()
    assert not any('Overwrite?' in p for p in reader.prompts)


@pytest.mark.parametrize('mode', ['--output', '--append'])
def test_audit_failure_blocks_output_mutation(case, tmp_path, monkeypatch, mode):
    path, _, _ = case
    target = tmp_path / 'notes'
    target.write_bytes(b'keep')
    def unavailable(*args, **kwargs):
        raise OSError('audit unavailable')
    monkeypatch.setattr(activity, 'append', unavailable)
    assert main(['--db', str(path), 'status', mode, str(target), '--force']) == 2
    assert target.read_bytes() == b'keep'


def test_changed_destination_and_first_write_race_are_rejected(case, tmp_path, monkeypatch):
    path, _, _ = case
    target = tmp_path / 'notes'
    args = build_parser().parse_args(['--db', str(path), 'status', '--output', str(target)])
    handle = output.Output(args)
    handle.write('new')
    target.write_bytes(b'competing work')
    with pytest.raises(ValueError, match='changed'):
        handle.finish()
    handle.close()
    assert target.read_bytes() == b'competing work'
    target.unlink()
    real_link = output.os.link
    def competing(source, destination):
        target.write_bytes(b'won the race')
        return real_link(source, destination)
    monkeypatch.setattr(output.os, 'link', competing)
    assert main(['--db', str(path), 'status', '--output', str(target)]) == 2
    assert target.read_bytes() == b'won the race'
    assert not list(tmp_path.glob('.locard-output-*'))


@pytest.mark.parametrize('mode', ['--output', '--append'])
def test_audit_destination_cannot_be_overwritten_or_appended(case, mode):
    path, _, _ = case
    main(['--db', str(path), 'status'])
    target = activity.sidecar(path)
    assert main(['--db', str(path), 'status', mode, str(target), '--force']) == 2
    assert activity.inspect(target)['valid']


def test_case_creation_concise_flow_and_audit(tmp_path, capsys):
    from test_browser_parser import history
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    history(evidence / 'History').close()
    target = tmp_path / 'browser-case'
    reader = Input('1', str(target), str(evidence), 'chrome', 'Default', '', '', '', '', 'yes', 'exit')
    shell = Shell(State(None), reader)
    assert shell.run() == 0 and shell.active == target
    text = capsys.readouterr().out
    for expected in ('[1] Create case', '[2] Open case', 'Found 1 Chromium History', 'Optional source information',
                     'Ingesting evidence...', 'Case ready:', 'Evidence: 2 records | 0 errors'):
        assert expected in text
    assert 'No active case' not in text and "{'" not in text and 'None' not in text
    assert 'Case name or path (Enter cancels): ' in reader.prompts
    assert '  Browser [chrome/edge]: ' in reader.prompts and '  Profile (required): ' in reader.prompts
    assert any(p.startswith('[browser-case]>') for p in reader.prompts)
    entries = records(target)
    assert entries[0]['action'] == 'CASE_CREATE'
    assert entries[-1]['action'] == 'SESSION_END' and len({e['session_id'] for e in entries}) == 1
    assert any(e['action'] == 'INGEST' and e['outcome'] == 'success' for e in entries)
    with closing(connect(target)) as db:
        assert db.execute('SELECT display_name FROM source_assertions').fetchone()[0] == 'browser-case'


def test_create_directory_error_is_not_open_validation(tmp_path, capsys):
    assert not creation.create(Shell(State(None), Input(str(tmp_path), '')))
    text = capsys.readouterr().out
    assert 'a directory exists at that path' in text
    assert 'existing regular database' not in text


@pytest.mark.parametrize('text,expected', [('help sour', 'help source '), ('help source up', 'help source update '),
                                         ('? sour', '? source ')])
def test_help_completion_through_editor(text, expected):
    assert console.edit([*text, '\t', '\r'], complete=completion.complete, output=io.StringIO()) == expected


def test_help_nested_and_ingest_candidates_use_same_parser():
    for prefix in ('source ', 'ingest-'):
        normal = completion.complete(prefix, len(prefix))
        text = 'help ' + prefix
        helped = completion.complete(text, len(text))
        assert normal.candidates == helped.candidates
    text = 'help source update --'
    assert completion.complete(text, len(text)).text == text
    assert not completion.complete(text, len(text)).candidates

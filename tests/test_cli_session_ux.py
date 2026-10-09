"""CLI-only session, confirmation and literal-path regression coverage."""
from contextlib import closing
import builtins
import json

import pytest

from forensic_assistant import terminal
from forensic_assistant.cli import main, build_parser, get_liner
from forensic_assistant.database import sources
from forensic_assistant.database.db import connect
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.retrieval.presentation import safe_path
from forensic_assistant.semantic.documents import fingerprint
from test_interactive_shell import Input, case
from test_source_path_selection import make_case, ROOT


@pytest.fixture
def colors(monkeypatch):
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)


@pytest.mark.parametrize('name', ['mixeddesktop-evtx626', '01-prefetch', 'case (Ã©)_16.db'])
@pytest.mark.parametrize('ending', ['exit', 'quit', EOFError()])
@pytest.mark.parametrize('color', [False, True])
def test_prompt_and_normal_exit(tmp_path, capsys, colors, name, ending, color):
    path = case(tmp_path, 'parent/' + name)
    reader = Input(str(path), ending)
    before = path.read_bytes()
    assert Shell(State(None), reader, no_color=not color).run() == 0
    assert reader.prompts[-1] == terminal.Palette(color)('prompt', '[' + name + ']> ')
    text = terminal.SGR.sub('', capsys.readouterr().out)
    assert text.count('Locard session ended.') == 1
    assert text.endswith(terminal.SGR.sub('', get_liner()) + '\n\nLocard session ended.\nCase: '
                         + str(path) + '\n' + terminal.SGR.sub('', get_liner()) + '\n')
    assert 'Case closed' not in text
    assert path.read_bytes() == before


@pytest.mark.parametrize('ending', ['exit', 'quit', EOFError()])
def test_exit_before_case_selection(capsys, ending):
    reader = Input(ending)
    assert Shell(State(None), reader).run() == 0
    text = capsys.readouterr().out
    assert text.count('Locard session ended.') == 1
    assert text.endswith(get_liner() + '\n\nLocard session ended.\n' + get_liner() + '\n')
    assert 'Case:' not in text


def test_fatal_error_does_not_claim_normal_shutdown(tmp_path, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise RuntimeError('fatal synthetic failure')
    monkeypatch.setattr('forensic_assistant.cli.dispatch', fail)
    reader = Input(str(case(tmp_path)), 'status')
    with pytest.raises(RuntimeError, match='fatal synthetic'):
        Shell(State(None), reader).run()
    assert 'Locard session ended.' not in capsys.readouterr().out
    assert reader.cleared >= 2


def test_ctrl_c_cancels_input_and_command_then_allows_exit(tmp_path, monkeypatch, capsys):
    def cancel(*args, **kwargs):
        raise KeyboardInterrupt()
    monkeypatch.setattr('forensic_assistant.cli.dispatch', cancel)
    reader = Input(str(case(tmp_path)), KeyboardInterrupt(), 'status', 'version', 'exit')
    assert Shell(State(None), reader).run() == 0
    text = capsys.readouterr().out
    assert 'Input cancelled.' in text and 'Interrupted.' in text and 'Locard version' in text
    assert text.count('Locard session ended.') == 1


def source_command(action, sid, sha):
    return (['source', 'update', sid, '--hostname', 'host.example.local'] if action == 'update'
            else ['source', 'assign', sid, '--file-hash', sha, '--reason', 'Reviewed'])


def applied(db, action, sid):
    if action == 'update':
        return sources.current(db, sid)['hostname'] == 'host.example.local'
    return sources.summary(db, sid)['files'] == 1


@pytest.mark.parametrize('action', ['update', 'assign'])
@pytest.mark.parametrize('interactive', [False, True])
def test_yes_never_prompts_and_retains_provenance(tmp_path, monkeypatch, capsys, action, interactive):
    path = tmp_path / 'case.db'
    sid, hashes = make_case(path)
    words = source_command(action, sid, hashes[0]) + ['--yes']
    def forbidden(*args, **kwargs):
        raise AssertionError('Unexpected confirmation input')
    monkeypatch.setattr(builtins, 'input', forbidden)
    with closing(connect(path)) as db:
        evidence = [tuple(r) for r in db.execute('SELECT * FROM evidence_records')]
    if interactive:
        class NoConfirmation(Input):
            def read(self, prompt, **kwargs):
                if prompt == 'Apply this analyst-supplied change? [y/N]: ':
                    forbidden()
                return super().read(prompt, **kwargs)
        reader = NoConfirmation(str(path), ' '.join(words), 'exit')
        assert Shell(State(None), reader).run() == 0
    else:
        assert main(['--db', str(path), *words]) == 0
    with closing(connect(path)) as db:
        assert applied(db, action, sid)
        assert evidence == [tuple(r) for r in db.execute('SELECT * FROM evidence_records')]
        if action == 'update':
            assert db.execute('SELECT count(*) FROM source_assertions WHERE source_id=?', (sid,)).fetchone()[0] == 2
    assert 'Apply this analyst-supplied change?' not in capsys.readouterr().out


@pytest.mark.parametrize('action', ['update', 'assign'])
@pytest.mark.parametrize('response', ['n', 'N', '', 'y', 'yes'])
def test_without_yes_confirm_or_cancel(tmp_path, capsys, action, response):
    path = tmp_path / 'case.db'
    sid, hashes = make_case(path)
    with closing(connect(path)) as db:
        before = fingerprint(db)
    reader = Input(str(path), ' '.join(source_command(action, sid, hashes[0])), response, 'exit')
    assert Shell(State(None), reader).run() == 0
    assert reader.prompts.count('Apply this analyst-supplied change? [y/N]: ') == 1
    with closing(connect(path)) as db:
        assert applied(db, action, sid) == (response in ('y', 'yes'))
        if response not in ('y', 'yes'):
            assert fingerprint(db) == before


@pytest.mark.parametrize('action', ['update', 'assign'])
@pytest.mark.parametrize('invalid', ['source', 'value'])
def test_yes_does_not_skip_validation(tmp_path, monkeypatch, action, invalid):
    path = tmp_path / 'case.db'
    sid, hashes = make_case(path)
    words = source_command(action, 'missing-source' if invalid == 'source' else sid, hashes[0])
    if invalid == 'value':
        words = (['source', 'update', sid, '--volume-root', 'invalid-drive'] if action == 'update'
                 else ['source', 'assign', sid, '--file-hash', 'f' * 64, '--reason', 'Reviewed'])
    def forbidden(*args, **kwargs):
        raise AssertionError('Unexpected input')
    monkeypatch.setattr(builtins, 'input', forbidden)
    with closing(connect(path)) as db:
        before = fingerprint(db)
    assert main(['--db', str(path), *words, '--yes']) == 2
    with closing(connect(path)) as db:
        assert fingerprint(db) == before


def test_yes_command_inventory():
    import argparse
    commands = []
    def walk(parser, path=()):
        if any('--yes' in a.option_strings for a in parser._actions):
            commands.append(path)
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, child in action.choices.items():
                    walk(child, (*path, name))
    walk(build_parser())
    assert commands == [('source', 'update'), ('source', 'assign')]


@pytest.mark.parametrize('path', [r'C:\tmp\locard\case\001.json', r'\\server\share\case' + chr(92),
                                  'C:\\Cases (lab)\\Ã©vidence_01-test\\æŠ¥å‘Š.txt',
                                  '/tmp/locard/case (Ã©)_01/report.txt', r'C:\literal\n\t\&#x74;.txt'])
def test_literal_human_paths_and_unchanged_json(path):
    assert safe_path(path) == path
    for color in (False, True):
        encoded = terminal.render_json({'output': path}, terminal.Palette(color))
        plain = terminal.SGR.sub('', encoded)
        assert json.loads(plain)['output'] == path
        assert json.dumps(path, ensure_ascii=True) in plain


def test_control_characters_are_not_rendered_as_terminal_actions():
    path = 'C:\\case\\bad\x1b[31m\n\r\t\u202e.txt'
    shown = safe_path(path)
    assert all(c not in shown for c in ('\x1b', '\n', '\r', '\t', '\u202e'))
    assert r'C:\case\bad' in shown
    assert r'\u001b' in shown and r'\u202e' in shown


@pytest.mark.parametrize('json_output', [False, True])
@pytest.mark.parametrize('mode', ['--output', '--append'])
@pytest.mark.parametrize('color', [False, True])
def test_output_paths_and_file_behavior(tmp_path, monkeypatch, capsys, colors, mode, color, json_output):
    path = case(tmp_path, 'cases/db')
    monkeypatch.chdir(tmp_path)
    name = 'rÃ©sult (1)_file-test.json'
    target = tmp_path / name
    target.write_text('original\n', encoding='utf-8')
    words = ['--db', str(path), 'status', mode, name]
    if mode == '--output':
        words.append('--force')
    if json_output:
        words.append('--json')
    if not color:
        words.append('--no-color')
    assert main(words) == 0
    captured = capsys.readouterr()
    assert captured.out == ''
    assert ('\x1b[' in captured.err) == (color and not json_output)
    text = terminal.SGR.sub('', captured.err)
    verb = 'appended to' if mode == '--append' else 'overwritten'
    assert text == 'Output ' + verb + ': ' + str(target) + '\n'
    contents = target.read_text(encoding='utf-8')
    if mode == '--append':
        assert contents.startswith('original\n\n')
        contents = contents[len('original\n\n'):]
    if json_output:
        assert isinstance(json.loads(contents), dict)
    else:
        assert 'CASE STATUS' in contents and '\x1b' not in contents
    assert not (path.parent / name).exists()


def test_human_show_status_assignment_paths_and_json(tmp_path, capsys):
    path = tmp_path / 'case (Ã©)_test.db'
    sid, hashes = make_case(path)
    before = path.read_bytes()
    assert main(['--db', str(path), 'status']) == 0
    assert 'Case: ' + str(path) in capsys.readouterr().out
    eid = 'PREFETCH:' + hashes[0] + ':File'
    assert main(['--db', str(path), 'show', eid]) == 0
    assert 'File: ' + ROOT + r'\APP0.pf' in capsys.readouterr().out
    assert main(['--db', str(path), 'show', eid, '--json']) == 0
    data = json.loads(capsys.readouterr().out)
    assert data['source_file'] == ROOT + r'\APP0.pf'
    assert main(['--db', str(path), 'source', 'assign', sid, '--path', ROOT, '--reason', 'Reviewed']) == 0
    assert 'Recorded path: ' + ROOT in capsys.readouterr().out
    assert path.read_bytes() == before


def test_remembered_selected_and_shutdown_paths(tmp_path, capsys):
    path = case(tmp_path, 'case (é)_01.db')
    state = State(None)
    state.remember(path)
    assert Shell(state, Input('', 'exit')).run() == 0
    text = capsys.readouterr().out
    for label in ('Last database: ', 'Database: ', 'Case: '):
        assert label + str(path) in text


def test_update_preview_and_source_volume_paths(colors):
    from forensic_assistant.source_cli import render_update_preview
    preview = dict(source={'source_id': 'source-synthetic', 'volume_root': 'C:'},
                   proposed={'volume_root': 'D:\\'}, basis='analyst-supplied')
    plain = render_update_preview(preview, terminal.Palette())
    assert 'Volume root: C: -> D:\\' in plain
    assert terminal.SGR.sub('', render_update_preview(preview, terminal.Palette(True))) == plain

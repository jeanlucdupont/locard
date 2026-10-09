from shell_output import before_shutdown
"""Focused shell navigation and presentation regressions; synthetic inputs only."""
import argparse
import copy
import json
from contextlib import closing
import pytest
from forensic_assistant import terminal
from forensic_assistant.cli import build_parser, main
from forensic_assistant.interactive.help import catalog, SHELL_COMMANDS
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.database.db import connect
from forensic_assistant.retrieval.evidence import get_evidence
from forensic_assistant.retrieval.layout import fit_path
from forensic_assistant.retrieval.presentation import safe, PREFETCH_CAUTIONS
from forensic_assistant.retrieval.search_display import render as search
from forensic_assistant.retrieval.show_display import render as show
from test_output_ux import case
from test_interactive_shell import Input


@pytest.mark.parametrize('color', [False, True])
def test_catalog_actual_commands_alphabetical(color):
    parser = build_parser(interactive=True)
    text = catalog(parser, terminal.Palette(color))
    plain = terminal.SGR.sub('', text)
    assert plain.startswith('\n  ?')
    names = [line.split()[0] for line in plain.splitlines() if line.startswith('  ')]
    actual = next(a.choices for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    assert names == sorted(set(actual) | set(SHELL_COMMANDS))
    for bad in ('usage:', 'positional arguments:', 'options:', '--db', '--version', '.venv', 'python.exe', 'Shell:'):
        assert bad not in plain
    assert plain.endswith('Type `help <command>` for details.\n')
    assert ('\x1b[' in text) == color


@pytest.mark.parametrize('setting,no_color,styled', [('on', False, True), ('off', False, False), ('on', True, False)])
def test_shell_help_and_detailed_help(case, monkeypatch, capsys, setting, no_color, styled):
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    if no_color:
        monkeypatch.setenv('NO_COLOR', '1')
    else:
        monkeypatch.delenv('NO_COLOR', raising=False)
    shell = Shell(State(None), Input(str(case[0]), 'color ' + setting, 'help', 'help source assign', 'exit'))
    assert shell.run() == 0
    from forensic_assistant.cli import get_liner
    from importlib.metadata import version
    text = capsys.readouterr().out
    startup = '                         Version ' + version('locard-forensics') + '\n' + get_liner() + '\n'
    assert text.startswith(startup)
    text = before_shutdown(text)[len(startup):]
    plain = terminal.SGR.sub('', text)
    assert 'Type `help <command>` for details.' in plain and 'usage: source assign' in plain and '--file-hash' in plain and '--path' in plain
    assert 'usage: Locard shell' not in plain
    assert ('\x1b[' in text) == styled


@pytest.mark.parametrize(
    'path',
    [
        r'\\?\Volume{long-volume-identifier}\WINDOWS\SYSTEM32\SVCHOST.EXE',
        r'C:\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE',
        '//server/share/long folder/SYSTEM32/SVCHOST.EXE',
    ]
)
@pytest.mark.parametrize('width', [24, 40, 80])
def test_component_shortening(path, width):
    escaped = safe(path)
    shown = fit_path(escaped, width)
    assert len(shown) <= width
    if len(escaped) <= width:
        assert shown == escaped
    else:
        assert shown.startswith('...')
        assert shown[3:].startswith(('\\\\', '/'))
        assert escaped.endswith(shown[3:])
    assert len(fit_path(escaped, 80)) >= len(shown)


def test_overlong_component_and_controls():
    text = fit_path(safe('C:\\' + 'a' * 100 + '\x1b[31m'), 20)
    assert len(text) <= 20 and text.startswith('...\\\\') and text.endswith('...') and '\x1b' not in text


def test_projection_warnings_actual_availability(case):
    with closing(connect(case[0])) as db:
        r = get_evidence(db, case[1])
    r['warnings'] = list(PREFETCH_CAUTIONS)
    before = copy.deepcopy(r)
    text = search(dict(records=[r], total=1, offset=0))
    detail = show(r)
    assert 'object projection' not in text and 'Object projection' not in detail
    assert 'candidate unavailable' not in text and 'candidate unavailable' not in detail
    assert 'Referenced files: 220' in detail and 'Showing 5 of 220' in detail
    assert 'Directory information is not available with the current Prefetch parser.' in detail.split('Parser limitation')[1]
    assert r == before
    r['objects'] = []
    assert 'candidate unavailable' in search(dict(records=[r], total=1, offset=0))
    assert 'candidate unavailable' in show(r)
    r['warnings'] += ['Parser detected corrupt data']
    r['context']['conflicts'] = ['source membership']
    text = search(dict(records=[r], total=19, offset=0))
    assert 'Parser detected corrupt data' in text and 'conflicting context' in text and 'Showing 1 of 19' in text


@pytest.mark.parametrize('multiple', [False, True])
@pytest.mark.parametrize('common', [False, True])
def test_show_source_and_timestamp_semantics(case, multiple, common):
    with closing(connect(case[0])) as db:
        r = get_evidence(db, case[1])
    members = [dict(display_name='Synthetic source', source_id='src-one')]
    if multiple:
        members.append(dict(display_name='Synthetic source', source_id='src-two'))
    r['context'].update(source_assertions=members, basis='analyst-supplied')
    r['timestamps'][0]['meaning'] = 'Recorded execution'
    r['timestamps'][1]['meaning'] = 'Recorded execution' if common else 'Different timestamp meaning'
    before = copy.deepcopy(r)
    text = show(r)
    assert 'Source: Synthetic source' in text and 'Host basis: analyst-supplied' in text
    assert ('Source ID: src-one' in text) == multiple
    if multiple:
        assert 'Source ID: src-two' in text
    assert text.count('Meaning:') == (1 if common else 2)
    if not common:
        assert 'Different timestamp meaning' in text
    assert r == before


def test_raw_json_and_database_unchanged(case, capsys):
    path, eid, _ = case
    before = path.read_bytes()
    for raw, flag in [(False, '--json'), (True, '--raw')]:
        with closing(connect(path)) as db:
            expected = get_evidence(db, eid, raw)
        assert main(['--db', str(path), 'show', eid, flag]) == 0
        assert json.loads(capsys.readouterr().out) == expected
        assert main(['--db', str(path), 'search', flag]) == 0
        data = json.loads(capsys.readouterr().out)
        assert data['records'][0] == expected and data['offset'] == 0 and data['total'] == 1
    assert path.read_bytes() == before

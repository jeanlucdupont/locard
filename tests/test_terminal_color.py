from shell_output import before_shutdown
import io
import json
import os
from contextlib import contextmanager
from types import SimpleNamespace
import pytest
from forensic_assistant import terminal, output
from forensic_assistant.cli import main, build_parser, get_banner
from forensic_assistant.retrieval.search_display import render
from test_output_ux import case, Terminal


@pytest.fixture
def color(monkeypatch):
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)


def plain(text):
    return terminal.SGR.sub('', text)


@pytest.mark.parametrize(
    'value',
    [
        {}, [], {'key': 'value', 'count': 96, 'flag': False, 'unknown': None},
        {'evidence_id': 'PREFETCH:' + 'a' * 64 + ':File', 'raw': '\x1b[31m\\"\n'},
        {'nested': [{'unicode': 'café'}, [], {}, True, 1.25, -2, 1e30]},
        {None: 0, False: 'false', 42: 'number', 1.5: 'float'},
        {'raw': 'A' * 100000}, {'special': [float('nan'), float('inf'), float('-inf')]},
    ]
)
def test_semantic_json_exact_equivalence(value):
    rendered = terminal.render_json(value, terminal.Palette(True))
    assert plain(rendered) == json.dumps(value, ensure_ascii=True, indent=2)
    if value:
        assert '\x1b[' in rendered


def test_cycles_and_unsupported_types():
    value = []
    value.append(value)
    with pytest.raises(ValueError, match='Circular'):
        terminal.render_json(value, terminal.Palette(True))
    with pytest.raises(TypeError):
        terminal.render_json({object(): 1}, terminal.Palette(True))


@pytest.mark.parametrize('flags', [[], ['--raw'], ['--json'], ['--no-color']])
def test_search_and_show_exact_content(case, capsys, color, flags):
    path, eid, _ = case
    for command in (['search', '--ids'], ['show', eid]):
        args = ['--db', str(path), *command, *flags]
        assert main(args) == 0
        colored = capsys.readouterr().out
        assert main(args + ['--no-color']) == 0
        uncolored = capsys.readouterr().out
        assert plain(colored) == uncolored and eid in plain(colored)
        assert ('\x1b[' in colored) == not_plain(flags)
        if '--json' in flags:
            assert json.loads(colored) == json.loads(uncolored)


def not_plain(flags):
    return '--json' not in flags and '--no-color' not in flags


@pytest.mark.parametrize('value', ['', '0', '1', 'false'])
def test_no_color_presence(case, capsys, color, monkeypatch, value):
    monkeypatch.setenv('NO_COLOR', value)
    assert main(['--db', str(case[0]), 'show', case[1]]) == 0
    assert '\x1b' not in capsys.readouterr().out


def test_nontty_and_uncertain_capability(monkeypatch):
    monkeypatch.delenv('NO_COLOR', raising=False)
    assert not terminal.capable(io.StringIO())
    monkeypatch.setenv('TERM', 'dumb')
    assert not terminal.capable(Terminal())
    monkeypatch.delenv('TERM', raising=False)
    if os.name == 'nt':
        def fail(stream):
            raise OSError('console unavailable')
        monkeypatch.setattr(terminal, 'windows_ansi', fail)
    assert not terminal.capable(Terminal())


@pytest.mark.parametrize('mode', ['--output', '--append'])
@pytest.mark.parametrize('flags', [[], ['--raw'], ['--json']])
def test_file_output_always_plain(case, tmp_path, capsys, color, mode, flags):
    target = tmp_path / 'derived.txt'
    assert main(['--db', str(case[0]), 'show', case[1], *flags, mode, str(target)]) == 0
    data = target.read_text(encoding='utf-8')
    assert '\x1b' not in data and case[1] in data
    if flags:
        assert json.loads(data)['id'] == case[1]
    if '--raw' in flags:
        assert json.loads(data)['detail']['raw_file']
    captured = capsys.readouterr()
    assert captured.out == ''
    if '--json' in flags:
        assert '\x1b' not in captured.err


@pytest.mark.parametrize('width', [1, 3, 10, 79])
def test_ansi_wrapping_visible_width(width):
    palette = terminal.Palette(True)
    line = palette('key', 'abcdefgh') + ': ' + palette('string_value', 'a value with spaces')
    rows = list(terminal.wrap_line(line, width))
    assert ''.join(plain(row) for row in rows) == plain(line)
    assert all(len(plain(row)) <= width for row in rows)
    for row in rows:
        assert '\x1b' not in plain(row)
        if '\x1b' in row:
            assert list(terminal.SGR.finditer(row))[-1].group() == terminal.RESET


@pytest.mark.parametrize('no_color', [False, True])
def test_pager_coloring_and_quit(case, color, monkeypatch, no_color):
    stream = Terminal()
    monkeypatch.setattr(output.sys, 'stdout', stream)
    monkeypatch.setattr(output.sys, 'stdin', Terminal())
    monkeypatch.setattr(output.shutil, 'get_terminal_size', lambda **kw: os.terminal_size((40, 6)))
    restored = []
    @contextmanager
    def keyboard():
        try:
            yield lambda: 'q'
        finally:
            restored.append(True)
    monkeypatch.setattr(output, 'keyboard', keyboard)
    args = ['--db', str(case[0]), 'show', case[1], '--page'] + (['--no-color'] if no_color else [])
    assert main(args) == 0
    text = stream.getvalue()
    assert 'Lines 1-4 of' in text
    assert bool(terminal.SGR.search(text)) == (not no_color)
    assert len(plain(text).split('Lines 1-4 of')[0].splitlines()) == 4 and restored == [True]


def test_search_styles_are_types_not_judgments():
    row = dict(
        id='PREFETCH:exact:File',
        source_type='prefetch',
        artifact_type='prefetch_file',
        detail={'executable': 'POWERSHELL.EXE', 'run_count': 5},
        context={}
    )
    result = dict(records=[row], offset=0, limit=10, total=1)
    text = render(result, terminal.Palette(True))
    assert plain(text) == render(result)
    assert terminal.Palette(True)('string_value', 'POWERSHELL.EXE') in text
    assert '\x1b[31m' not in text and '\x1b[33m' not in text


def test_banner_policy_and_startup_flag(color, monkeypatch):
    banner = get_banner()
    assert terminal.banner(banner) == banner
    assert terminal.banner(banner, SimpleNamespace(no_color=True)) == plain(banner)
    monkeypatch.setenv('NO_COLOR', '')
    assert terminal.banner(banner) == plain(banner)


def test_global_nested_and_command_options():
    parser = build_parser()
    for argv in (
        ['--no-color', 'search'],
        ['search', '--no-color'],
        ['report', '--no-color', 'show', 'bundle'],
        ['report', 'show', 'bundle', '--no-color']
    ):
        assert parser.parse_args(argv).no_color


def test_shell_no_color_session(case, color, capsys):
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from test_interactive_shell import Input

    shell = Shell(
        State(None),
        Input(str(case[0]), 'search', 'status', 'exit'),
        no_color=True,
    )

    assert shell.run() == 0

    captured = capsys.readouterr().out

    # The startup banner is intentionally allowed to use ANSI styling.
    # The interactive session itself must honor no_color.
    from forensic_assistant.cli import get_liner
    from importlib.metadata import version
    banner = '                         Version ' + version('locard-forensics') + '\n' + get_liner() + '\n'
    assert captured.startswith(banner)

    session_output = before_shutdown(captured)[len(banner):]
    assert '\x1b' not in session_output

def test_no_external_process(case, color, monkeypatch, capsys):
    import subprocess
    def forbidden(*a, **kw):
        raise AssertionError('External process forbidden')
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(os, 'system', forbidden)
    assert main(['--db', str(case[0]), 'show', case[1]]) == 0
    assert '\x1b' in capsys.readouterr().out

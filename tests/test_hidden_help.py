"""Help remains an early-exit action, including required and nested commands."""
import argparse
import pytest
from forensic_assistant.cli import build_parser, main
from forensic_assistant import terminal
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from test_interactive_shell import Input, case


def assert_hidden(text):
    assert '-h, --help' not in text
    assert '[-h]' not in text
    assert '[--help]' not in text
    assert 'show this help message and exit' not in text


@pytest.mark.parametrize('interactive', [False, True])
def test_every_parser_keeps_invisible_help(interactive, capsys):
    def visit(parser):
        help_action = parser._option_string_actions['--help']
        assert parser._option_string_actions['-h'] is help_action
        assert isinstance(help_action, argparse._HelpAction)
        for flag in ('-h', '--help'):
            with pytest.raises(SystemExit) as exc:
                parser.parse_args([flag])
            assert exc.value.code == 0
            captured = capsys.readouterr()
            assert not captured.err
            assert 'usage:' in captured.out
            assert_hidden(captured.out)
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for child in action.choices.values():
                    visit(child)
    visit(build_parser(interactive=interactive))


@pytest.mark.parametrize('command', [[], ['session'], ['search'], ['source'], ['source', 'assign'], ['report'], ['report', 'show']])
@pytest.mark.parametrize('flag', ['-h', '--help'])
def test_cli_help_does_not_dispatch(command, flag, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail('Help must not dispatch a command')
    monkeypatch.setattr('forensic_assistant.cli.dispatch', forbidden)
    with pytest.raises(SystemExit) as exc:
        main([*command, flag])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert not captured.err
    assert_hidden(captured.out)
    if command == ['session']:
        assert '--logon-id LOGON_ID' in captured.out
    if not command:
        for option in ('--version', '--db', '--no-color'):
            assert option in captured.out


@pytest.mark.parametrize('color', [False, True])
def test_interactive_help_routes_equivalent(color, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    monkeypatch.delenv('NO_COLOR', raising=False)
    def forbidden(*args, **kwargs):
        pytest.fail('Help must not dispatch a command')
    monkeypatch.setattr('forensic_assistant.cli.dispatch', forbidden)
    database = case(tmp_path)
    docs = []
    for command in ('help session', '? session', 'session -h', 'session --help'):
        shell = Shell(State(None), Input(str(database), 'color ' + ('on' if color else 'off'), command, 'exit'))
        assert shell.run() == 0
        assert shell.last_status == 0
        text = capsys.readouterr().out
        # Exclude the independently styled startup banner and case-selection output.
        marker = 'Color: ' + ('on' if color else 'off') + '\n'
        documentation = text.split(marker, 1)[1]
        assert ('\x1b[' in documentation) == color
        plain = terminal.SGR.sub('', documentation)
        assert plain.startswith('usage: session ')
        assert '--logon-id LOGON_ID' in plain
        assert_hidden(plain)
        docs.append(plain)
    assert all(doc == docs[0] for doc in docs)

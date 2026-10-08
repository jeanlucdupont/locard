"""Command summaries share one authority; detailed parsing remains local."""
import argparse

import pytest

from forensic_assistant.cli import build_parser
from forensic_assistant.cli_parser import UnknownCommand, InvalidArguments
from forensic_assistant.command_catalog import COMMANDS, SHELL_COMMANDS
from forensic_assistant.interactive.help import catalog, command_help, SHELL_USAGE
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.terminal import Palette, SGR
from test_interactive_shell import Input, case


# Intentional wording contract, independent of the production metadata.
EXPECTED = dict(line.split('|', 1) for line in """?|Show help for a command
analyze-timeline|Analyze timeline evidence using the local AI model
around|Show evidence near a specific event or timestamp
ask|Ask the local AI questions about case evidence
case|Open or create a case
color|Turn terminal colors on or off
detections|Show  evidence matching Locard detection rules
exit|Exit Locard
help|Show help for a command
ingest|Import EVTX files from a directory
ingest-all|Import all supported forensic artifacts
ingest-browser|Ingest Chrome or Edge browsing history and downloads
ingest-evtx|Import Windows Event Logs (EVTX)
ingest-mft|Import NTFS Master File Table (MFT) evidence
ingest-prefetch|Import Windows Prefetch evidence
ingest-registry|Import Windows Registry evidence
investigate|Gather related evidence around an event
investigate-ai|Analyze case evidence using the local AI model
investigation|Review or replay saved AI investigations
logons|Review Windows logon activity
process-tree|Reconstruct process parent-child relationships
quit|Exit Locard
report|Generate a forensic investigation report
search|Search case evidence
semantic|Search case evidence by meaning
session|Reconstruct activity within a Windows logon session
show|Show details about an evidence record
source|Manage evidence sources
status|Show case ingestion and evidence status
timeline|Browse evidence chronologically
version|Show the Locard version""".splitlines())


def subcommands(parser):
    return next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))


def test_metadata_wording_and_immutability():
    assert COMMANDS == EXPECTED
    assert set(SHELL_COMMANDS) == set(SHELL_USAGE)
    for mapping in (COMMANDS, SHELL_COMMANDS):
        with pytest.raises(TypeError):
            mapping['help'] = 'Changed'


@pytest.mark.parametrize('interactive', [False, True])
def test_every_top_level_parser_has_central_summary(interactive):
    commands = subcommands(build_parser(interactive=interactive))
    names = set(commands.choices) | set(SHELL_COMMANDS)
    assert names == set(COMMANDS), 'Every user-facing command must have command_catalog metadata'
    summaries = {entry.dest: entry.help for entry in commands._choices_actions}
    assert summaries == {name: COMMANDS[name] for name in commands.choices}


@pytest.mark.parametrize('color', [False, True])
def test_catalog_exact_wording_and_order(color):
    text = catalog(build_parser(interactive=True), Palette(color))
    plain = SGR.sub('', text)
    rows = [line.strip().split('  ', 1) for line in plain.splitlines() if line.startswith('  ')]
    assert [(name, description.strip()) for name, description in rows] == sorted(EXPECTED.items())
    assert plain.endswith('Type `help <command>` for details.\n')
    assert ('\x1b' in text) == color
    assert 'Same as' not in plain and 'usage:' not in plain


def test_missing_command_metadata_is_not_silently_replaced():
    parser = build_parser(interactive=True)
    subcommands(parser).add_parser('future-command', help='A forgotten local summary')
    with pytest.raises(KeyError, match='future-command'):
        catalog(parser)


@pytest.mark.parametrize('prefix', ['help', '?'])
def test_shell_help_catalog_and_details(prefix, tmp_path, capsys):
    database = case(tmp_path)
    commands = [prefix, prefix + ' session', prefix + ' source assign']
    commands += [prefix + ' ' + name for name in SHELL_COMMANDS]
    shell = Shell(State(None), Input(str(database), 'color off', *commands, 'exit'))
    assert shell.run() == 0 and shell.last_status == 0
    text = capsys.readouterr().out.split('Color: off\n', 1)[1]
    assert '\x1b' not in text
    assert catalog(build_parser(interactive=True)) in text
    assert 'usage: session ' in text and '--logon-id LOGON_ID' in text
    assert 'Windows authentication Logon ID' in text
    assert 'usage: source assign ' in text and '--confirmation-fingerprint' in text
    for name in SHELL_COMMANDS:
        assert command_help(name) == SHELL_USAGE[name] + ': ' + EXPECTED[name]
        assert command_help(name) in text
    assert '-h, --help' not in text and '[-h]' not in text


@pytest.mark.parametrize('args,expected', [
    (['session', '--logon-id', '0x123'], dict(command='session', logon_id='0x123', max_hours=24, limit=500, text=False)),
    (['process-tree', '--evidence', 'EVTX:synthetic'], dict(command='process-tree', evidence='EVTX:synthetic', pid_window=300, max_nodes=100)),
    (['around', 'EVTX:synthetic', '--text'], dict(command='around', seconds=120, direction='around', text=True, json=False)),
    (['source', 'assign', 'source-id', '--file-hash', 'a', '--file-hash', 'b', '--reason', 'Synthetic test'], dict(command='source', source_command='assign', source_id='source-id', file_hash=['a', 'b'], reason='Synthetic test', yes=False)),
    (['ingest-evtx', 'example.evtx'], dict(command='ingest-evtx', path='example.evtx', parser_timeout=300, hostname=None)),
])
def test_representative_parser_contracts(args, expected):
    normal = vars(build_parser().parse_args(args))
    interactive = vars(build_parser(interactive=True).parse_args(args))
    assert normal == interactive
    assert {key: normal[key] for key in expected} == expected


def test_validation_and_unknown_commands_unchanged():
    with pytest.raises(UnknownCommand) as exc:
        build_parser(interactive=True).parse_args(['unknowncommand'])
    assert str(exc.value) == 'Unknown command: unknowncommand\nType `help` to list available commands.'
    for args in (['session'], ['around', 'id', '--direction', 'invalid'], ['search', '--json', '--text']):
        with pytest.raises(InvalidArguments):
            build_parser(interactive=True).parse_args(args)

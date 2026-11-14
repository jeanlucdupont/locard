"""Canonical navigation; persisted internal operation identities remain stable."""
import argparse
import pytest
from forensic_assistant.cli import build_parser
from forensic_assistant.cli_parser import UnknownCommand, InvalidArguments
from forensic_assistant.command_surface import FAMILIES
from forensic_assistant.interactive.help import catalog,paths
from forensic_assistant.terminal import Palette,SGR

@pytest.mark.parametrize('interactive',[False,True])
def test_canonical_families(interactive):
    p=build_parser(interactive=interactive)
    roots=next(a.choices for a in p._actions if isinstance(a,argparse._SubParsersAction))
    assert set(roots)=={'case','evidence','analyze','investigation','report','ai','audit','settings'}

@pytest.mark.parametrize('color',[False,True])
def test_help_and_advanced_discovery(color):
    p=build_parser(interactive=True)
    normal=catalog(p,Palette(color)); full=catalog(p,all_commands=True)
    for name in FAMILIES:assert name in normal
    assert 'investigation advanced local-query' in full
    assert 'investigation reason' in full
    assert 'new-case' not in normal and 'expert' not in normal
    assert ('\x1b' in normal)==color
    for path,child in paths(p):assert child.format_help()

@pytest.mark.parametrize('name',['new-case','ask','expert','add-evidence','ingest-wizard','ingest-mft','exit','search','briefing','investigate-ai','ai-history'])
def test_obsolete_top_level_rejected(name):
    with pytest.raises(UnknownCommand):build_parser(interactive=True).parse_args([name])

@pytest.mark.parametrize('args,expected', [
    (['analyze','session', '--logon-id', '0x123'], dict(command='session', logon_id='0x123', max_hours=24, limit=500, text=False)),
    (['analyze','process-tree', '--evidence', 'EVTX:synthetic'], dict(command='process-tree', evidence='EVTX:synthetic', pid_window=300, max_nodes=100)),
    (['evidence','around', 'EVTX:synthetic', '--text'], dict(command='around', seconds=120, direction='around', text=True, json=False)),
    (['evidence','source', 'assign', 'source-id', '--file-hash', 'a', '--file-hash', 'b', '--reason', 'Synthetic test'], dict(command='source', source_command='assign', source_id='source-id', file_hash=['a', 'b'], reason='Synthetic test', yes=False)),
    (['evidence','ingest','evtx', 'example.evtx'], dict(command='ingest-evtx', path='example.evtx', parser_timeout=300, hostname=None)),
])
def test_representative_parser_contracts(args, expected):
    normal = vars(build_parser().parse_args(args))
    interactive = vars(build_parser(interactive=True).parse_args(args))
    if args[:1] == ['analyze']:
        assert normal['json'] and not normal['text']
        assert interactive['text'] and not interactive['json']
        assert {k: v for k, v in normal.items() if k not in ('json', 'text')} == {
            k: v for k, v in interactive.items() if k not in ('json', 'text')}
    else:
        assert normal == interactive
    assert {key: normal[key] for key in expected} == expected


def test_validation_and_unknown_commands_unchanged():
    with pytest.raises(UnknownCommand) as exc:
        build_parser(interactive=True).parse_args(['unknowncommand'])
    assert str(exc.value) == 'Unknown command: unknowncommand\nType `help` to list available commands.'
    for args in (['analyze','session'], ['evidence','around', 'id', '--direction', 'invalid'], ['evidence','search', '--json', '--text']):
        with pytest.raises(InvalidArguments):
            build_parser(interactive=True).parse_args(args)


def test_help_separates_advanced_controls_without_changing_defaults():
    parser=build_parser()
    search=dict(paths(parser))[('evidence','search')]
    text=search.format_help()
    assert 'Common options:' in text and 'Advanced options:' in text
    assert '--raw' in text.split('Advanced options:')[1]
    assert parser.parse_args(['evidence','search','--raw']).raw


def test_recorded_review_does_not_offer_ignored_output_flags():
    p=build_parser(interactive=True)
    with pytest.raises(InvalidArguments):
        p.parse_args(['investigation','history','show','synthetic','--output','ignored.json'])

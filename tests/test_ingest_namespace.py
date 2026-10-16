"""6.56 command-surface parity using synthetic evidence only."""
import argparse
from contextlib import closing
import json

import pytest

from forensic_assistant import activity
from forensic_assistant.cli import build_parser, main
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from test_interactive_shell import Input, case
from v2_fixtures import mft_file


KINDS = ('all', 'browser', 'evtx', 'mft', 'prefetch', 'registry')


def choices(parser):
    return next(a.choices for a in parser._actions if isinstance(a, argparse._SubParsersAction))


@pytest.mark.parametrize('interactive', [False, True])
@pytest.mark.parametrize('kind', KINDS)
def test_aliases_share_parser_options_and_stable_internal_command(kind, interactive):
    parser = build_parser(interactive=interactive)
    root = choices(parser)
    assert choices(root['ingest'])[kind] is root['ingest-' + kind]
    options = ['synthetic path', '--source', 'src-example', '--hostname', 'lab', '--user', 'analyst',
               '--volume-root', 'C:', '--record-size', '1024', '--parser-timeout', '42', '--json']
    if kind == 'browser':
        options += ['--browser', 'edge', '--profile', 'Profile 1']
    canonical = vars(parser.parse_args(['ingest', kind, *options]))
    alias = vars(parser.parse_args(['ingest-' + kind, *options]))
    assert canonical.pop('ingest_type') == kind
    assert canonical == alias
    assert canonical['command'] == 'ingest-' + kind
    assert '--source' in choices(root['ingest'])[kind].format_help()


def test_bare_ingest_help_and_invalid_type_never_create_case(tmp_path, capsys):
    database = tmp_path / 'absent.db'
    assert main(['--db', str(database), 'ingest']) == 0
    text = capsys.readouterr().out
    assert all(kind in text for kind in (*KINDS, 'wizard'))
    assert not database.exists()
    with pytest.raises(SystemExit) as exc:
        main(['--db', str(database), 'ingest', 'not-a-type'])
    assert exc.value.code == 2 and not database.exists()
    assert main(['--db', str(database), 'ingest', 'wizard']) == 2
    assert not database.exists()


def test_direct_mft_alias_preserves_ids_counters_json_source_and_audit(tmp_path, capsys):
    artifact = mft_file(tmp_path / 'synthetic-mft')
    original = artifact.read_bytes()
    database = tmp_path / 'case.db'
    base = ['--db', str(database)]
    assert main([*base, 'ingest', 'mft', str(artifact), '--hostname', 'lab', '--json']) == 0
    first = json.loads(capsys.readouterr().out)
    with closing(connect(database)) as db:
        ids = [r[0] for r in db.execute('SELECT evidence_id FROM evidence_records ORDER BY evidence_id')]
        source = sources.listing(db)['sources'][0]
    assert ids and source['hostname'] == 'lab'
    assert main([*base, 'ingest-mft', str(artifact), '--source', source['source_id'], '--json']) == 0
    second = json.loads(capsys.readouterr().out)
    assert first.keys() == second.keys()
    assert sum(r['inserted'] for r in first['results']) == len(ids)
    assert sum(r['inserted'] for r in second['results']) == 0
    assert sum(r['duplicates'] for r in second['results']) == len(ids)
    with closing(connect(database)) as db:
        assert [r[0] for r in db.execute('SELECT evidence_id FROM evidence_records ORDER BY evidence_id')] == ids
        batches = list(db.execute('SELECT source_id, command, status FROM ingestion_batches'))
        assert len(batches) == 2
        assert all(r['source_id'] == source['source_id'] and r['command'] == 'ingest-mft' for r in batches)
        assert sources.listing(db)['total'] == 1
    assert artifact.read_bytes() == original
    assert activity.inspect(activity.sidecar(database))['valid']


def test_historical_mode_events_remain_verifiable_and_new_shell_adds_none(tmp_path):
    database = case(tmp_path)
    session = activity.Session(database)
    session.start()
    session.record('SHELL_MODE', mode='AI')
    session.end()
    before = activity.sidecar(database).read_bytes()
    shell = Shell(State(None), Input(str(database), 'ai', 'expert', 'ingest', 'help ingest wizard', 'help ask', 'exit'), no_color=True)
    assert shell.run() == 0
    after = activity.sidecar(database).read_bytes()
    assert after.startswith(before)
    assert sum(activity.decode(line + b'\n')['action'] == 'SHELL_MODE' for line in after.splitlines()) == 1
    assert activity.inspect(activity.sidecar(database))['valid']
    assert shell.last_status == 0 and not hasattr(shell, 'mode')

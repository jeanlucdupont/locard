from shell_output import before_shutdown
import copy
import json
import os
from contextlib import closing
import pytest
from forensic_assistant import source_cli, terminal
from forensic_assistant.cli import build_parser, main
from forensic_assistant.cli_parser import InvalidArguments, UnknownCommand
from forensic_assistant.database import sources
from forensic_assistant.database.db import connect
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.retrieval.around_display import render, delta, display_time
from test_interactive_shell import Input, case
from test_around_display import example


def source_rows():
    return dict(
        sources=[
            dict(
                source_id='src-' + 'a' * 32,
                display_name='Lab One',
                hostname=None,
                batches=0,
                files=196,
                artifacts={'prefetch': 196}
            ),
            dict(
                source_id='src-' + 'b' * 32,
                display_name='Other',
                hostname='host',
                batches=12,
                files=4,
                artifacts={'registry': 2, 'evtx': 3}
            )
        ],
        total=2,
        offset=0,
        truncated=False
    )


def test_source_alignment_styles_and_full_ids():
    data = source_rows()
    before = copy.deepcopy(data)
    text = source_cli.render_list(data, width=160)
    colored = source_cli.render_list(data, terminal.Palette(True), width=160)
    assert terminal.SGR.sub('', colored) == text and '\x1b[' in colored
    assert 'Prefetch: 196' in text and 'EVTX: 3, Registry: 2' in text and 'unknown' in text
    lines = text.splitlines()
    header = lines[0]
    first = lines[2]
    second = lines[3]
    assert first.index('Lab One') == second.index('Other') == header.index('NAME')
    assert first.index('unknown') == second.index('host') == header.index('HOSTNAME')
    assert all(r['source_id'] in text for r in data['sources'])
    assert data == before and '\x1b[31m' not in colored


def test_source_narrow_long_values_warnings():
    data = source_rows()
    data['sources'][0]['display_name'] = 'Long name ' * 30
    data['sources'][0].update(host_conflict=True, ambiguous_files=2)
    data.update(total=10, truncated=True)
    plain = source_cli.render_list(data, width=40)
    assert max(map(len, plain.splitlines())) <= 40 and '...' in plain
    assert 'source list --ids' not in plain and 'Showing 2 of 10' in plain
    assert 'conflicting host' in plain and 'multiple source' in plain
    full = source_cli.render_list(data, width=40, ids=True)
    assert all(r['source_id'] in full for r in data['sources'])


@pytest.mark.parametrize(
    'stamp,expected',
    [
        ('2020-09-19T05:08:37.532877300Z', '2020-09-19T05:08:37.533Z'),
        ('2020-09-19T05:08:43.031392300Z', '2020-09-19T05:08:43.031Z'),
        ('2020-12-31T23:59:59.999500000Z', '2021-01-01T00:00:00.000Z'),
        ('2020-01-01T00:00:00.000500000Z', '2020-01-01T00:00:00.001Z'),
        ('9999-12-31T23:59:59.999999999Z', '10000-01-01T00:00:00.000Z')]
)
def test_timestamp_rounding(stamp, expected):
    assert display_time(stamp) == expected


@pytest.mark.parametrize(
    'stamp,expected',
    [
        ('2020-09-19T05:08:37.532877300Z', '-5.499s'),
        ('2020-09-19T05:08:50.218877300Z', '+7.187s'),
        ('2020-09-19T05:08:43.031392299Z', '0.000s'),
        ('2020-09-19T05:08:43.031892300Z', '+0.001s'),
        ('2020-09-19T05:08:43.030892300Z', '-0.001s')]
)
def test_relative_rounding_uses_unrounded_anchor(stamp, expected):
    assert delta(stamp, '2020-09-19T05:08:43.031392300Z') == expected


def test_clean_header_and_detail_preservation():
    a, r, args = example()
    for record in [a, *r['records']]:
        record['context'] = {'source_assertions': [dict(source_id='src-exact', display_name='Lab One')]}
    before = copy.deepcopy(r)
    text = render(r, a, a['timestamps'][1]['timestamp_utc'], args, width=120)
    assert 'Lab One | Prefetch' in text and text.count('<- anchor') == 1
    for unwanted in ('Anchor slot', 'src-exact', 'Timestamp meaning', 'Correlation', 'causation', 'execution'):
        assert unwanted not in text
    args.ids = True
    detailed = render(r, a, a['timestamps'][1]['timestamp_utc'], args, width=120)
    for value in ('src-exact', 'run:2', '000000002Z', 'Timestamp meaning', 'execution', a['id']):
        assert value in detailed
    assert r == before
    r.update(truncated=True, total=3)
    assert 'Showing 2 of 3' in render(r, a, a['timestamps'][1]['timestamp_utc'], args, width=120)


def test_usage_and_local_argument_errors(monkeypatch, capsys):
    monkeypatch.setattr('sys.argv', [r'C:\Synthetic install\.venv\Scripts\locard'])
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(['source', 'assign', '--help'])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    assert text.startswith('usage: locard source assign') and '.venv' not in text and 'python.exe' not in text
    parser = build_parser(interactive=True)
    with pytest.raises(SystemExit):
        parser.parse_args(['source', 'assign', '--help'])
    assert capsys.readouterr().out.startswith('usage: source assign')
    with pytest.raises(InvalidArguments) as exc:
        parser.parse_args(['source', 'assign'])
    assert 'usage: source assign' in str(exc.value) and 'ingest-all' not in str(exc.value)
    with pytest.raises(InvalidArguments) as exc:
        parser.parse_args(['source', 'assign', 'src-test', '--reason', 'x', '--bogus'])
    assert 'usage: source assign' in str(exc.value)
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(['source', 'assign'])
    assert exc.value.code == 2 and 'locard source assign' in capsys.readouterr().err


def test_unknown_command_and_session_recovery(tmp_path, capsys):
    reader = Input(str(case(tmp_path)), 'donotexist', 'source assign', 'help source assign', 'status', 'exit')
    assert Shell(State(None), reader).run() == 0
    text = capsys.readouterr().out
    error = text.split('Unknown command: donotexist', 1)[1].split('Invalid arguments.', 1)[0]
    assert 'Type `help`' in error and 'usage:' not in error and 'ingest-evtx' not in error
    assert 'usage: source assign' in text and 'CASE STATUS' in text and 'Total evidence records:' in text
    with pytest.raises(UnknownCommand):
        build_parser(interactive=True).parse_args(['--no-color', 'donotexist'])


def test_source_output_modes_and_session_color(tmp_path, monkeypatch, capsys):
    path = case(tmp_path)
    dest = tmp_path / 'sources.txt'
    with closing(connect(path)) as db:
        with db:
            sid = sources.create(db, name='Synthetic Lab')
        expected = sources.listing(db)
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    base = ['--db', str(path), 'source', 'list']
    assert main(base + ['--json']) == 0
    assert json.loads(capsys.readouterr().out) == expected
    assert main(base + ['--output', str(dest)]) == 0
    plain = dest.read_text(encoding='utf-8')
    assert '\x1b' not in plain
    assert main(base + ['--append', str(dest)]) == 0
    assert dest.read_text(encoding='utf-8') == plain + '\n' + plain
    capsys.readouterr()
    assert main(base + ['--page']) == 0
    assert terminal.SGR.sub('', capsys.readouterr().out) == plain
    reader = Input(str(path), 'color on', 'source list', 'color off', 'source list', 'exit')
    assert Shell(State(None), reader).run() == 0
    text = capsys.readouterr().out
    before, after = before_shutdown(text).split('Color: off\n')
    assert '\x1b[' in before and '\x1b' not in after
    monkeypatch.setenv('NO_COLOR', '')
    assert main(base) == 0 and '\x1b' not in capsys.readouterr().out


def test_generic_cautions_only_removed_from_compact_renderers():
    from forensic_assistant import v2_cli, v1_cli
    from forensic_assistant.retrieval import search_display
    a, r, args = example()
    r.update(limit=100)
    assert 'CAUSATION' in v2_cli.render(r)
    assert 'CAUSATION' not in v2_cli.render(r, methodology=False)
    assert 'CAUSATION' in v1_cli.render(r)
    assert 'CAUSATION' not in v1_cli.render(r, methodology=False)
    assert 'complete execution history' not in search_display.render(r)

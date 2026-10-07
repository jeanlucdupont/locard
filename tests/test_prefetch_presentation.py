"""Presentation stays separate from Prefetch evidence and execution semantics."""
import copy
import json
from contextlib import closing
from types import SimpleNamespace

import pytest

from forensic_assistant import terminal, v2_cli
from forensic_assistant.cli import build_parser, main
from forensic_assistant.database.db import connect
from forensic_assistant.retrieval import around_display, prefetch_display, search_display, show_display
from forensic_assistant.retrieval.evidence import get_evidence
from forensic_assistant.retrieval.presentation import PREFETCH_CAUTIONS
from test_output_ux import case


def record(count=1):
    path = r'\VOLUME{synthetic-volume}\WINDOWS\APP.EXE'
    return dict(
        id='PREFETCH:' + 'a' * 64 + ':File', source_type='prefetch', artifact_type='prefetch_file',
        detail=dict(executable='APP.EXE', run_count=count, prefetch_identifier=1234,
                    references=[path, r'\\server\share\reference.dll', *[f'file{i}.dll' for i in range(7)]],
                    reference_count=9, volumes=[dict(device_path=r'\Device\HarddiskVolume1', serial_number=42,
                                                   creation_filetime='132000000000000000')]),
        source=dict(source_file=r'C:\evidence\APP.pf', sha256='a' * 64),
        context=dict(hostname='synthetic-host', basis='analyst-supplied', volume_root='C:',
                     source_assertions=[dict(source_id='synthetic', display_name='Synthetic source')]),
        warnings=sorted(PREFETCH_CAUTIONS) + ['Synthetic parser quality warning'],
        objects=[dict(role='referenced_file', original='DO_NOT_EXECUTE.EXE'),
                 dict(role='executable_name', original='APP.EXE'),
                 dict(role='executable_path_candidate', original=path)],
        timestamps=[dict(slot=f'run:{i}', timestamp_utc=f'2020-01-0{count-i}T00:00:00.123456700Z',
                         source='Prefetch LastRun', meaning='Recorded execution timestamp; not a process-instance identifier')
                    for i in range(count)]
    )


def timeline(r):
    rows = [dict(r, timestamp_utc=t['timestamp_utc'], timestamp=t) for t in r['timestamps']]
    return dict(records=rows, total=len(rows), offset=0, truncated=False)


@pytest.mark.parametrize('count', [1, 8])
@pytest.mark.parametrize('color', [False, True])
def test_show_run_slots_notes_and_immutable_projection(count, color):
    r = record(count)
    before = copy.deepcopy(r)
    rendered = show_display.render(r, terminal.Palette(color))
    text = terminal.SGR.sub('', rendered)
    assert text == show_display.render(r)
    assert ('\x1b[' in rendered) == color
    assert 'Run times' in text and 'Prefetch identifier' not in text
    assert 'Meaning:' not in text
    positions = [text.index(f'[run:{i}]') for i in range(count)]
    assert positions == sorted(positions)  # Source slot order, not a new chronological sort.
    for t in r['timestamps']:
        assert search_display.timestamp(t['timestamp_utc']) + ' UTC' in text
    notes = text.split('Forensic notes')[1].split('Parser limitation')[0]
    assert 'Missing Prefetch does not prove a program never ran' in notes
    assert 'not a complete execution history' in notes
    assert 'accessed or used' in notes and 'not necessarily executed' in notes
    assert 'do not identify unique process instances' in notes
    assert 'Directory information' not in notes
    assert 'Directory information is not available with the current Prefetch parser' in text.split('Parser limitation')[1]
    assert 'Synthetic parser quality warning' in text.split('Limitations / data quality')[1]
    assert 'Showing 5 of 9' in text and 'file2.dll' in text and 'file3.dll' not in text
    for field in ('Effective host: synthetic-host', 'Host basis: analyst-supplied', 'Volume root: C:', 'SHA-256'):
        assert field in text
    assert r == before


def test_show_missing_run_slots_are_not_fabricated():
    r = record(8)
    for t in r['timestamps'][1:]:
        t['timestamp_utc'] = None
    text = show_display.render(r)
    assert '[run:0]' in text and '[run:1]' not in text
    assert 'Populated run slots: 1 of 8' in text
    r['timestamps'][0]['timestamp_utc'] = None
    assert 'No populated run times.' in show_display.render(r)


@pytest.mark.parametrize('color', [False, True])
@pytest.mark.parametrize('equal', [False, True])
def test_timeline_keeps_observations_ids_and_references_separate(color, equal):
    r = record(8)
    if equal:
        for t in r['timestamps']:
            t['timestamp_utc'] = r['timestamps'][0]['timestamp_utc']
    result = timeline(r)
    before = copy.deepcopy(result)
    rendered = v2_cli.render(result, methodology=False, palette=terminal.Palette(color))
    text = terminal.SGR.sub('', rendered)
    assert text == v2_cli.render(result, methodology=False)
    assert 'TIME (UTC)' in text and 'EXECUTABLE' in text and 'RUN SLOT' in text
    assert r['id'] not in text and 'DO_NOT_EXECUTE' not in text
    assert text.count('APP.EXE') == 8
    for t in r['timestamps']:
        assert text.count('[' + t['slot'] + ']') == 1
        assert search_display.timestamp(t['timestamp_utc']) in text
    assert result == before
    raw = v2_cli.render(result, methodology=True)
    assert r['id'] in raw and r['timestamps'][0]['timestamp_utc'] in raw


def test_timeline_pagination_counts_slots_even_with_identical_values():
    r = record(8)
    for t in r['timestamps']:
        t['timestamp_utc'] = r['timestamps'][0]['timestamp_utc']
    result = timeline(r)
    result['records'] = result['records'][2:4]
    result.update(offset=2, truncated=True)
    text = prefetch_display.render_timeline(result)
    assert 'Showing 3\u20134 of 8' in text
    assert '[run:2]' in text and '[run:3]' in text and '[run:0]' not in text


@pytest.mark.parametrize('slot', ['run:0', 'run:7'])
def test_around_selects_exact_slot_and_preserves_neighbor_deltas(slot):
    anchor = record(8)
    stamp = v2_cli.anchor_time(anchor, slot)
    result = timeline(anchor)
    neighbor = record()
    neighbor['id'] = 'PREFETCH:' + 'b' * 64 + ':File'
    neighbor['detail']['executable'] = 'NEIGHBOR.EXE'
    neighbor['timestamps'][0]['timestamp_utc'] = stamp.replace('00:00:00.', '00:00:01.')
    result['records'].extend(timeline(neighbor)['records'])
    result['records'].sort(key=lambda r: r['timestamp_utc'])
    result['total'] += 1
    before = copy.deepcopy(result)
    args = SimpleNamespace(timestamp_slot=slot, ids=False)
    text = around_display.render(result, anchor, stamp, args, width=120)
    assert f'Anchor: Prefetch run [{slot}]' in text
    assert 'TIME (UTC)' in text and 'DELTA' in text
    assert text.count('<- anchor') == 1 and '+1.000s' in text
    assert 'NEIGHBOR.EXE' in text and 'DO_NOT_EXECUTE' not in text
    assert text.count('APP.EXE') == 8
    assert result == before


def test_missing_candidate_summary_retains_projection_scope_and_data():
    records = [record() for _ in range(3)]
    for r in records:
        r['objects'] = [o for o in r['objects'] if o['role'] != 'executable_path_candidate']
        r['objects_truncated'] = True
    result = dict(records=records, total=3, offset=0)
    before = copy.deepcopy(result)
    text = search_display.render(result)
    assert text.count('executable path candidate unavailable') == 1
    assert 'bounded projection for rows 1, 2, 3' in text
    assert result == before
    records[1]['objects_truncated'] = False
    assert 'bounded projection for rows 1, 3' in search_display.render(result)


def test_volume_root_is_not_a_mapping_and_human_paths_remain_literal():
    r = record()
    original = r['detail']['references'][0]
    for text in (show_display.render(r), search_display.render(dict(records=[r], total=1), width=180)):
        assert original in text
        assert r'C:\WINDOWS\APP.EXE' not in text
        assert r'\\VOLUME' not in text
    assert r'\\server\share\reference.dll' in show_display.render(r)
    assert r['detail']['references'][0] == original


def test_reference_only_projection_never_becomes_executable():
    r = record()
    r['detail']['executable'] = None
    r['objects'] = [dict(role='referenced_file', original='REFERENCE_ONLY.EXE')]
    assert prefetch_display.executable(r) is None
    assert 'REFERENCE_ONLY' not in prefetch_display.render_timeline(timeline(r))


def test_cli_json_raw_slots_ids_and_database_unchanged(case, capsys):
    path, eid, _ = case
    before = path.read_bytes()
    with closing(connect(path)) as db:
        expected = {flag: get_evidence(db, eid, flag == '--raw') for flag in ('--json', '--raw')}
    for flag, value in expected.items():
        assert main(['--db', str(path), 'show', eid, flag]) == 0
        assert json.loads(capsys.readouterr().out) == value
    args = ['--db', str(path), 'timeline', '--artifact', 'prefetch', '--start', '2019-01-01T00:00:00Z', '--end', '2021-01-01T00:00:00Z']
    assert main(args + ['--text']) == 0
    text = capsys.readouterr().out
    assert eid not in text and '[run:1]' in text and '[run:2]' in text
    assert main(args + ['--json']) == 0
    data = json.loads(capsys.readouterr().out)
    assert [r['timestamp']['slot'] for r in data['records']] == ['run:1', 'run:2']
    assert {r['id'] for r in data['records']} == {eid}
    assert main(['--db', str(path), 'search', '--artifact', 'prefetch', '--ids']) == 0
    assert eid in capsys.readouterr().out
    assert build_parser().parse_args(['search', '--artifact', 'prefetch']).limit == 20
    assert path.read_bytes() == before

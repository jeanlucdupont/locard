"""Synthetic EVTX text projections; raw evidence and timestamp slots stay intact."""
import copy
import json
from contextlib import closing
from types import SimpleNamespace

import pytest

from forensic_assistant import v2_cli
from forensic_assistant.cli import build_parser
from forensic_assistant.database.db import connect
from forensic_assistant.retrieval import evtx_display as display, around_display, show_display, search_display
from forensic_assistant.retrieval.evidence import EvidenceQueries, get_evidence
from forensic_assistant.retrieval.presentation import human_detail, safe
from forensic_assistant.terminal import Palette, SGR
from test_sysmon_file_create import add, FIELDS, ACTOR, TARGET


@pytest.fixture
def case():
    with closing(connect(':memory:')) as db:
        anchor = add(db)
        yield db, anchor


def timeline(db):
    return EvidenceQueries(db).search(timeline=True).as_dict()


def arguments(eid, *extra):
    return build_parser().parse_args(['around', eid, '--timestamp-slot', 'SystemTime', '--text', *extra])


def test_equal_time_slots_are_display_only(case):
    db, anchor = case
    result = timeline(db)
    before = copy.deepcopy(result)
    projected = display.page(result, 100, 0)
    grouped = display.groups(projected['records'])
    assert [len(g) for g in grouped] == [2, 1]
    shown = display.render_timeline(projected, width=160)
    assert shown.count('file_create') == 2
    assert 'Sysmon  CreationUtcTime, UtcTime' in shown and 'EVTX  SystemTime' in shown
    assert '14:30:54.123' in shown and '14:30:55.123' in shown
    assert 'Target  ' + TARGET in shown and 'writer.exe' in shown
    assert anchor['id'] not in shown and 'EVIDENCE ID' not in shown
    assert 'TYPE' in shown and 'OBJECT' in shown and 'TIME (UTC)' in shown
    assert result == before and len(result['records']) == 3
    assert len(get_evidence(db, anchor['id'])['timestamps']) == 3
    serialized = json.dumps(result)
    assert TARGET.replace('\\', '\\\\') in serialized


def test_records_with_equal_time_are_not_merged(case):
    db, anchor = case
    other = add(db, offset=1024)
    projected = display.page(timeline(db), 100, 0)
    groups = display.groups(projected['records'])
    assert len(groups) == 4 and [len(g) for g in groups] == [2, 2, 1, 1]
    assert all(len({r['id'] for r in g}) == 1 for g in groups)
    assert {g[0]['id'] for g in groups} == {anchor['id'], other['id']}


def test_distinct_submillisecond_values_never_merge_even_across_pages(case):
    db, _ = case
    result = timeline(db)
    for i, r in enumerate(result['records']):
        r['timestamp_utc'] = f'2026-09-15T14:30:54.12300000{i}Z'
        r['timestamp'] = dict(r['timestamp'], timestamp_utc=r['timestamp_utc'])
    assert len(display.groups(result['records'])) == 3
    for offset in range(3):
        projected = display.page(result, 1, offset)
        assert len(projected['records']) == 1
        assert 'Exact UTC: ' + result['records'][offset]['timestamp_utc'] in display.render_timeline(projected)


@pytest.mark.parametrize('slot', ['SystemTime', 'Sysmon.UtcTime', 'Sysmon.CreationUtcTime'])
def test_around_exact_selected_slot(case, slot):
    db, anchor = case
    args = arguments(anchor['id'])
    args.timestamp_slot = slot
    context = {}
    projected, _ = v2_cli.dispatch(db, args, presentation=context)
    text = around_display.render(projected, context['anchor'], context['stamp'], args, width=180)
    assert text.count('<- anchor') == 1
    assert '[' + slot + ']' in text and '[selected: ' + slot + ']' in text
    assert 'DELTA' in text and 'TYPE' in text and 'OBJECT' in text
    assert 'Artifact:' not in text and 'Timestamp meaning:' not in text
    assert TARGET in text and '\x1b' not in text
    assert text.count('file_create') == 2
    assert 'Source:' not in text  # shared source is shown once in the context


@pytest.mark.parametrize('limit,offset,length', [(1, 0, 2), (1, 1, 1), (1, 2, 0), (2, 0, 3)])
def test_timeline_group_pagination_vs_structured(case, limit, offset, length):
    db, _ = case
    parser = build_parser()
    base = ['timeline', '--around', '2026-09-15T14:30:55Z', '--artifact', 'evtx',
            '--limit', str(limit), '--offset', str(offset)]
    text, _ = v2_cli.dispatch(db, parser.parse_args(base + ['--text']))
    assert len(text['records']) == length
    for flag in ('--json', '--raw'):
        raw, _ = v2_cli.dispatch(db, parser.parse_args(base + [flag]))
        assert len(raw['records']) == min(limit, 3 - offset)
        assert raw['offset'] == offset and raw['limit'] == limit and raw['total'] == 3
        assert '_evtx_page' not in raw
        if flag == '--raw':
            assert all('raw_xml' in r for r in raw['records'])
        json.dumps(raw)


@pytest.mark.parametrize('direction', ['around', 'before', 'after'])
@pytest.mark.parametrize('offset', [0, 20])
def test_around_anchor_survives_pagination_and_direction(case, direction, offset):
    db, anchor = case
    args = arguments(anchor['id'], '--direction', direction, '--limit', '1', '--offset', str(offset))
    context = {}
    projected, _ = v2_cli.dispatch(db, args, presentation=context)
    assert len(projected['records']) == 1
    assert projected['records'][0]['timestamp']['slot'] == 'SystemTime'
    shown = around_display.render(projected, context['anchor'], context['stamp'], args)
    assert '<- anchor' in shown
    args.text, args.json = False, True
    raw, _ = v2_cli.dispatch(db, args)
    assert raw['limit'] == 1 and raw['offset'] == offset and '_evtx_page' not in raw
    if offset:
        assert raw['records'] == []
    elif direction == 'before':
        assert raw['records'][0]['timestamp']['slot'].startswith('Sysmon.')


@pytest.mark.parametrize('width', [40, 80, 160])
@pytest.mark.parametrize('colored', [False, True])
def test_wrapping_color_controls_and_neutral_paths(case, width, colored):
    db, anchor = case
    args = arguments(anchor['id'])
    projected, _ = v2_cli.dispatch(db, args)
    stamp = v2_cli.anchor_time(anchor, 'SystemTime')
    plain = around_display.render(projected, anchor, stamp, args, width=width)
    calls = []
    def palette(role, text):
        calls.append((role, text))
        return Palette(colored)(role, text)
    rendered = around_display.render(projected, anchor, stamp, args, palette, width=width)
    assert SGR.sub('', rendered) == plain
    assert ('\x1b[' in rendered) == colored
    assert '<- anchor' in plain and max(map(len, plain.splitlines())) <= width
    if width == 160:
        assert TARGET in plain
    else:
        assert 'target.bin' in plain.replace('\n', '').replace(' ', '')
    assert any(role == 'string_value' and 'file_create' in value for role, value in calls)
    assert all(TARGET not in value and ACTOR not in value for _, value in calls)
    assert '\x1b' not in plain


@pytest.mark.parametrize('path', [r'C:\Windows\System32\cmd.exe', r'\\server\share\file.txt', 'C:\\a\x1b[31m\nfile.exe'])
def test_path_rendering_show_process_and_file_targets(path):
    with closing(connect(':memory:')) as db:
        anchor = add(db)
        anchor['event_data_json'] = json.dumps([dict(name=key, value=path if key == 'TargetFilename' else value)
                                               for key, value in FIELDS])
        shown = show_display.render(anchor)
        expected = path.replace('\x1b', r'\u001b').replace('\n', r'\n')
        assert 'Observation: writer.exe - file creation/overwrite: ' + expected in shown
        assert 'Meaning: Sysmon-reported target-file creation timestamp' in shown
        assert 'Meaning: Sysmon-reported event time' in shown and 'Meaning: Event timestamp' in shown
        process = dict(anchor, artifact_type='process', kind='process', parent_process_name=path, process_name=ACTOR)
        assert human_detail(process) == expected + ' -> ' + ACTOR
        result = timeline(db)
        result['records'] = [dict(process, timestamp=result['records'][0]['timestamp'], timestamp_utc=result['records'][0]['timestamp_utc'])]
        result.update(total=1)
        text = display.render_timeline(result, width=200)
        assert expected in text and '\n    -> ' + ACTOR in text
        assert '\x1b' not in shown + text


@pytest.mark.parametrize('kind', ['powershell', 'unmapped'])
def test_command_and_script_content_stays_escaped(kind):
    value = r'Get-Item \\server\share; regex="\\w+"' + '\x1b[31m\n'
    assert human_detail(dict(kind=kind, script_block=value)) == safe(value)


def test_process_search_layout_only_path_escaping_changes(case):
    _, anchor = case
    process = dict(anchor, artifact_type='process', kind='process', process_name=ACTOR, parent_process_name=r'C:\cmd.exe')
    text = search_display.render(dict(records=[process], total=1), width=220)
    assert 'OBSERVATION' in text and r'C:\cmd.exe -> ' + ACTOR in text


def test_raw_render_unchanged_and_detailed_ids_available(case):
    db, anchor = case
    result = timeline(db)
    raw = v2_cli.render(result, methodology=True, palette=Palette(True))
    assert 'UTC | EVIDENCE ID | SOURCE' in raw and anchor['id'] in raw
    assert TARGET.replace('\\', '\\\\') in raw and '\x1b' not in raw
    args = arguments(anchor['id'], '--ids')
    projected, _ = v2_cli.dispatch(db, args)
    text = around_display.render(projected, anchor, v2_cli.anchor_time(anchor, 'SystemTime'), args)
    assert anchor['id'] in text and '14:30:55.123456700Z' in text
    assert 'Timestamp: ' in text


def test_incomplete_windows_rejected_and_input_unchanged(case):
    db, _ = case
    result = timeline(db)
    snapshot = copy.deepcopy(result)
    display.render_timeline(display.page(result, 1, 0), palette=Palette(True))
    assert result == snapshot
    with pytest.raises(ValueError, match='Complete timestamp window'):
        display.page(dict(result, records=result['records'][:1]), 1, 0)


def test_evtx_cap_precedes_hydration_and_releases_snapshot(case, monkeypatch):
    db, anchor = case
    with db:
        db.executemany('''INSERT INTO evidence_timestamps
            (evidence_id,slot,original_value,encoding,source,meaning,precision_ns,timestamp_utc,normalization_status)
            SELECT evidence_id,?,original_value,encoding,source,meaning,precision_ns,timestamp_utc,normalization_status
            FROM evidence_timestamps WHERE evidence_id=? AND slot='SystemTime' ''',
            [(f'extra:{i}', anchor['id']) for i in range(10000)])
    from forensic_assistant.retrieval import evidence
    monkeypatch.setattr(evidence, 'get_evidence', lambda *a, **k: pytest.fail('Cap must precede hydration'))
    args = build_parser().parse_args(['timeline', '--around', '2026-09-15T14:30:55Z', '--artifact', 'evtx', '--text'])
    with pytest.raises(ValueError, match='10,000'):
        v2_cli.dispatch(db, args)
    assert not db.in_transaction


def test_mixed_timeline_keeps_mft_groups_and_prefetch_individual_slots(case):
    db, _ = case
    from test_mft_presentation import example as mft_example, timeline as mft_timeline
    from test_around_display import example as prefetch_example
    result = timeline(db)
    mft = mft_timeline(mft_example())['records']
    prefetch = prefetch_example()[1]['records']
    rows = mft + prefetch + result['records']
    projected = display.page(dict(records=rows, total=len(rows), offset=0, truncated=False), 100, 0)
    grouped = display.groups(projected['records'])
    assert len([g for g in grouped if g[0]['source_type'] == 'mft']) == 1
    assert len([g for g in grouped if g[0]['source_type'] == 'prefetch']) == 2
    shown = display.render_timeline(projected, width=160)
    assert 'STATE' in shown and 'SI  Created' in shown and 'FN  Created' in shown
    assert 'Prefetch LastRun' in shown and 'Sysmon  CreationUtcTime, UtcTime' in shown


def test_evtx_paths_in_other_artifact_around_remain_safe(case):
    db, _ = case
    from test_around_display import example
    anchor, result, args = example()
    event = timeline(db)['records'][0]
    result['records'].append(event)
    result['total'] += 1
    shown = around_display.render(result, anchor, anchor['timestamps'][1]['timestamp_utc'], args, width=250)
    assert TARGET in shown and TARGET.replace('\\', '\\\\') not in shown


def test_timeline_cli_forwards_palette(case, tmp_path, monkeypatch, capsys):
    from forensic_assistant.cli import main
    from forensic_assistant import terminal
    db, _ = case
    path = tmp_path / 'synthetic.db'
    with closing(connect(path)) as destination:
        db.backup(destination)
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    monkeypatch.delenv('NO_COLOR', raising=False)
    command = ['--db', str(path), 'timeline', '--around', '2026-09-15T14:30:55Z', '--artifact', 'evtx', '--text']
    assert main(command) == 0
    colored = capsys.readouterr().out
    assert '\x1b[' in colored
    assert main(command + ['--no-color']) == 0
    assert capsys.readouterr().out == SGR.sub('', colored)

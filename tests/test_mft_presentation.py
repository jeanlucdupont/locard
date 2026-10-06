"""Synthetic MFT display contracts; no examiner evidence or case writes."""
import copy
import json
from types import SimpleNamespace

import pytest

from forensic_assistant import v2_cli
from forensic_assistant.cli import build_parser
from forensic_assistant.retrieval import mft_display, search_display, show_display, around_display
from forensic_assistant.retrieval.presentation import safe, safe_path
from forensic_assistant.terminal import Palette, SGR


TIME = '2026-01-01T00:00:00.000000000Z'
OTHER = '2026-01-01T00:00:01.000000000Z'
LIMITATION = 'Filesystem metadata; timestamps do not establish a download or user action'


def example():
    stamps = [dict(slot=f'attribute:{offset}:{label}', source=f'MFT {kind} {label}',
                   meaning=f'Filesystem metadata {kind} {label} timestamp', timestamp_utc=TIME)
              for kind, offset in [('SI', 56), ('FN', 128)] for label in mft_display.LABELS]
    return dict(id='MFT:' + 'a' * 64 + ':Offset:8192', source_type='mft', artifact_type='mft_record',
                source=dict(source_file=r'C:\Evidence\MFT', sha256='a' * 64),
                context={}, timestamps=stamps, objects=[], warnings=[], observation=LIMITATION,
                detail=dict(record_number=8, sequence_number=2, allocated=0, directory=0,
                            file_size=93, base_record=0, base_sequence=0,
                            names=[dict(reconstructed_path=r'\Users\example\Downloads\sample.zip')]))


def timeline(record):
    rows = [dict(record, timestamp=t, timestamp_utc=t['timestamp_utc'],
                 timeline_id=record['id'] + ':Timestamp:' + t['slot']) for t in record['timestamps']]
    return dict(records=rows, total=len(rows), offset=0, truncated=False)


@pytest.mark.parametrize('path', [r'C:\Windows\System32\cmd.exe', r'\Users\example\Downloads\sample.zip',
                                  r'\$Extend\$Quota', r'\\server\share\file.txt'])
def test_literal_paths_and_json(path):
    r = example()
    r['detail']['names'][0]['reconstructed_path'] = path
    result = dict(records=[r], total=1, offset=0)
    before = json.dumps(result)
    assert path in show_display.render(r)
    assert path in search_display.render(result, width=220)
    assert safe_path(path) == path
    assert json.dumps(result) == before and json.loads(before) == result
    assert safe(path) != path  # serialization-style safety stays unchanged elsewhere


def test_path_controls_not_decoded_and_arbitrary_strings_unchanged():
    path = '\\server\\share\\file\x1b[31m\n'
    assert '\x1b' not in safe_path(path) and '\n' not in safe_path(path)
    literal = r'C:\new\tab\x1b[31m'
    assert safe_path(literal) == literal
    r = example()
    r['warnings'] = [r'regex \\w+']
    assert safe(r['warnings'][0]) in show_display.render(r)


@pytest.mark.parametrize('allocated,label', [(0, 'Unallocated'), (1, 'Allocated'), (None, 'Unknown')])
@pytest.mark.parametrize('directory,kind', [(0, 'File'), (1, 'Directory')])
def test_state_type_and_base_metadata(allocated, label, directory, kind):
    r = example()
    r['detail'].update(allocated=allocated, directory=directory)
    before = copy.deepcopy(r)
    shown = show_display.render(r)
    assert f'State: {label}' in shown and f'Type: {kind}' in shown
    assert 'Base record:' not in shown and 'Base sequence:' not in shown
    assert shown.count(LIMITATION) == 1 and 'Deleted at' not in shown
    assert 'STATE' in search_display.render(dict(records=[r], total=1), width=160)
    assert r == before
    r['detail']['base_sequence'] = 2
    shown = show_display.render(r)
    assert 'Base record: 0' in shown and 'Base sequence: 2' in shown


def test_show_groups_copyable_slots_and_no_repeated_meanings():
    r = example()
    shown = show_display.render(r)
    assert 'STANDARD_INFORMATION (SI)' in shown and 'FILE_NAME (FN)' in shown
    assert 'Meaning:' not in shown and shown.count(LIMITATION) == 1
    for t in r['timestamps']:
        assert shown.count('[' + t['slot'] + ']') == 1
    assert shown.index('STANDARD_INFORMATION') < shown.index('FILE_NAME')


@pytest.mark.parametrize('color', [False, True])
def test_around_equal_values_preserves_anchor_and_all_semantics(color):
    r = example()
    result = timeline(r)
    before = copy.deepcopy(result)
    for slot in ('attribute:56:MFTChanged', 'attribute:128:MFTChanged'):
        args = SimpleNamespace(timestamp_slot=slot, ids=False)
        shown = around_display.render(result, r, TIME, args, Palette(color), width=160)
        plain = SGR.sub('', shown)
        assert plain.count('<- anchor') == 1 and slot in plain
        assert plain.count(r['detail']['names'][0]['reconstructed_path']) == 1
        assert 'SI  Created, Modified, MFT changed' in plain
        assert 'FN  Created, Modified, MFT changed' in plain
        assert 'Accessed' in plain and LIMITATION not in plain
        args.ids = True
        detailed = around_display.render(result, r, TIME, args, width=160)
        assert all('slot: ' + t['slot'] in detailed for t in r['timestamps'])
    assert result == before and len(json.loads(json.dumps(result))['records']) == 8


def test_same_values_one_group_different_values_and_records_separate():
    r = example()
    result = timeline(r)
    shown = v2_cli.render(result, methodology=False)
    assert len(mft_display.groups(result['records'])) == 1
    assert shown.count('sample.zip') == 1 and r['id'] not in shown
    assert 'SI  Created, Modified, MFT changed, Accessed' in shown
    assert 'FN  Created, Modified, MFT changed, Accessed' in shown
    assert LIMITATION not in shown
    r['timestamps'][1]['timestamp_utc'] = OTHER
    result = timeline(r)
    assert len(mft_display.groups(result['records'])) == 2
    second = copy.deepcopy(r)
    second['id'] += '-other'
    result['records'] += timeline(second)['records']
    result['total'] = 16
    assert len(mft_display.groups(result['records'])) == 4
    text = mft_display.render_timeline(result, width=160)
    assert text.count('sample.zip') == 4 and '00:00:01.000' in text


def test_distinct_submillisecond_values_not_merged_by_rounding():
    r = example()
    r['timestamps'][1]['timestamp_utc'] = '2026-01-01T00:00:00.000000100Z'
    result = timeline(r)
    assert len(mft_display.groups(result['records'])) == 2
    text = mft_display.render_timeline(result)
    assert 'Exact UTC: ' + TIME in text
    assert 'Exact UTC: 2026-01-01T00:00:00.000000100Z' in text


def test_multiple_fn_instances_do_not_lose_distinct_slots():
    r = example()
    t = dict(r['timestamps'][4], slot='attribute:256:Created')
    r['timestamps'].append(t)
    text = mft_display.render_timeline(timeline(r))
    assert 'attribute:128:Created' in text and 'attribute:256:Created' in text
    assert show_display.render(r).count('FILE_NAME (FN)') == 2


def test_unnamed_mft_and_page_counts():
    r = example()
    r['detail']['names'] = []
    result = timeline(r)
    result = mft_display.page(result, 1, 0)
    text = mft_display.render_timeline(result)
    assert 'MFT record 8/2' in text and LIMITATION not in text
    assert 'Showing' not in text
    assert 'page may split groups' not in text


def test_no_non_mft_aggregation_and_raw_renderer_preserved():
    r = example()
    result = timeline(r)
    for item in result['records']:
        item['source_type'] = 'evtx'
    assert len(mft_display.groups(result['records'])) == 8
    raw = v2_cli.render(timeline(r), methodology=True)
    assert raw.count(r['id']) == 8 and 'attribute:' not in raw
    assert TIME in raw and 'MFT SI Created' in raw


def test_ambiguous_equal_mft_slots_still_require_selection():
    r = example()
    with pytest.raises(ValueError, match='select --timestamp-slot'):
        v2_cli.anchor_time(r, require_slot=True)
    # Other existing callers (investigation/reporting/AI) retain their contract.
    assert v2_cli.anchor_time(r) == TIME
    for t in r['timestamps']:
        assert v2_cli.anchor_time(r, t['slot']) == TIME


@pytest.mark.parametrize('artifact', ['mft', 'evtx', 'prefetch', 'registry'])
def test_shared_search_limit_and_explicit_override(artifact):
    parser = build_parser()
    assert parser.parse_args(['search', '--artifact', artifact]).limit == 20
    args = parser.parse_args(['search', '--artifact', artifact, '--limit', '7', '--offset', '12'])
    assert (args.limit, args.offset) == (7, 12)
    assert parser.parse_args(['timeline']).limit == 100


def test_timeline_help_and_timezone_validation():
    from forensic_assistant.retrieval.queries import required_time
    parser = build_parser()
    sub = next(a for a in parser._actions if a.dest == 'command').choices['timeline']
    for dest in ('timestamp', 'start', 'end', 'around'):
        action = next(a for a in sub._actions if a.dest == dest)
        assert 'ISO 8601' in action.help and 'explicit UTC offset' in action.help
    assert '--help' not in sub.format_help() and '-h,' not in sub.format_help()
    with pytest.raises(ValueError):
        required_time('2026-01-01 00:00:00')


def test_ingested_observations_source_update_paths_and_pagination(tmp_path):
    from forensic_assistant.database.db import connect
    from forensic_assistant.database import sources
    from forensic_assistant.artifacts.ingest import ingest_artifact
    from forensic_assistant.retrieval.evidence import EvidenceQueries, get_evidence
    from v2_fixtures import mft_file
    db = connect(':memory:')
    try:
        result = ingest_artifact(db, mft_file(tmp_path / 'MFT', allocated=False), 'mft')
        assert result['inserted'] == 3 and result['errors'] == 0
        q = EvidenceQueries(db)
        rows = q.search(artifact='mft').records
        r = next(r for r in rows if r['detail']['record_number'] == 6)
        before = list(map(tuple, db.execute('SELECT * FROM evidence_timestamps ORDER BY evidence_id,slot')))
        sid = sources.create(db, name='Synthetic')
        sources.assign(db, sid, [r['file_sha256']], reason='Synthetic fixture')
        db.commit()
        args = build_parser().parse_args(['around', r['id'], '--timestamp-slot', r['timestamps'][0]['slot'], '--text'])
        with pytest.raises(ValueError, match='Host context missing'):
            v2_cli.dispatch(db, args)
        sources.update(db, sid, hostname='Example-PC')
        db.commit()
        projected = get_evidence(db, r['id'])
        assert projected['host_key'] == 'example-pc' and projected['context']['basis'] == 'analyst-supplied'
        result, code = v2_cli.dispatch(db, args)
        assert code == 0 and result['records']
        assert 'unknown' in search_display.render(dict(records=[r], total=1))
        assert 'example-pc' in show_display.render(projected)
        assert q.search(path=r'\payload.exe').total == 1
        assert q.search(path=r'\\payload.exe').total == 0
        assert q.search(limit=1, offset=1).records[0]['id'] == rows[1]['id']
        text = search_display.render(dict(records=[projected], total=1), ids=True)
        assert '1: ' + r['id'] in text and 'Unallocated' in text
        assert len(projected['timestamps']) == 8
        assert before == list(map(tuple, db.execute('SELECT * FROM evidence_timestamps ORDER BY evidence_id,slot')))
    finally:
        db.close()

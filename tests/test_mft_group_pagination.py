"""Complete display groups, bounded retrieval and unchanged structured contracts."""
import copy
import json
from types import SimpleNamespace

import pytest

from forensic_assistant import v2_cli
from forensic_assistant.cli import build_parser
from forensic_assistant.retrieval import mft_display as display, around_display
from forensic_assistant.retrieval.evidence import EvidenceQueries, get_evidence
from forensic_assistant.terminal import Palette, SGR
from test_mft_presentation import example, timeline, TIME, LIMITATION


def window(count=12):
    rows = []
    anchors = []
    for i in range(count):
        r = example()
        r['id'] += f':fixture-{i}'
        r['detail']['names'] = [dict(filename=f'example-{i}.bin')]
        for t in r['timestamps']:
            t['timestamp_utc'] = f'2026-01-01T00:00:{i:02d}.000000000Z'
        anchors.append(r)
        rows += timeline(r)['records']
    return dict(records=list(reversed(rows)), total=len(rows), offset=0, truncated=False), anchors


@pytest.mark.parametrize('limit,offset,expected', [(1, 0, [0]), (2, 0, [0, 1]), (1, 1, [1]),
                                                  (5, 5, [5, 6, 7, 8, 9]), (5, 100, [])])
def test_complete_group_pages(limit, offset, expected):
    result, anchors = window()
    before = copy.deepcopy(result)
    page = display.page(result, limit, offset)
    groups = display.groups(page['records'])
    assert [g[0]['id'] for g in groups] == [anchors[i]['id'] for i in expected]
    assert all(len(g) == 8 and len({r['timestamp']['slot'] for r in g}) == 8 for g in groups)
    assert result == before


def test_pages_do_not_overlap_and_four_slot_group_is_complete():
    result, _ = window(2)
    result['records'] = [r for r in result['records'] if 'MFT SI ' in r['timestamp']['source']]
    result['total'] = len(result['records'])
    first, second = [display.page(result, 1, offset) for offset in (0, 1)]
    assert len(first['records']) == len(second['records']) == 4
    assert {r['id'] for r in first['records']}.isdisjoint({r['id'] for r in second['records']})


def test_paging_retains_equal_time_records_and_distinct_submillisecond_groups():
    result, anchors = window(2)
    for r in result['records']:
        r['timestamp_utc'] = TIME
    result['records'][0]['timestamp_utc'] = '2026-01-01T00:00:00.000000100Z'
    result['records'][0]['timestamp'] = dict(result['records'][0]['timestamp'], timestamp_utc=result['records'][0]['timestamp_utc'])
    all_groups = display.groups(display.page(result, 100, 0)['records'])
    assert len(all_groups) == 3
    for offset in range(3):
        page = display.page(result, 1, offset)
        assert len(display.groups(page['records'])) == 1
    assert 'Exact UTC:' in display.render_timeline(display.page(result, 1, 2))


@pytest.mark.parametrize('index', [0, 5, 11])
@pytest.mark.parametrize('offset', [0, 3, 100])
def test_around_keeps_anchor_at_edges_and_with_offsets(index, offset):
    result, anchors = window()
    anchor = anchors[index]
    stamp = anchor['timestamps'][0]['timestamp_utc']
    page = display.page(result, 5, offset, anchor=anchor, stamp=stamp)
    groups = display.groups(page['records'])
    assert len(groups) == (5 if offset < 11 else 1)
    assert all(len(g) == 8 for g in groups)
    assert anchor['id'] in {g[0]['id'] for g in groups}
    assert [g[0]['timestamp_utc'] for g in groups] == sorted(g[0]['timestamp_utc'] for g in groups)
    args = SimpleNamespace(timestamp_slot='attribute:56:MFTChanged', ids=False)
    text = around_display.render(page, anchor, stamp, args, width=120)
    assert text.count('<- anchor') == 1 and 'SI MFT changed [attribute:56:MFTChanged]' in text
    assert 'STATE' in text and 'DELTA' in text and 'State:' not in text
    assert 'anchor included' in text


def test_around_offset_skips_nearest_neighbors_not_anchor():
    result, anchors = window(7)
    anchor = anchors[3]
    page = display.page(result, 3, 2, anchor=anchor, stamp=anchor['timestamps'][0]['timestamp_utc'])
    assert [g[0]['id'] for g in display.groups(page['records'])] == [anchors[i]['id'] for i in (1, 3, 5)]


def test_footer_units_complete_and_offset():
    result, _ = window()
    for limit, offset, expected in [(100, 0, ''), (5, 0, 'Showing 5 of 12 groups'),
                                     (5, 5, 'Showing 6\u201310 of 12 groups')]:
        page = display.page(result, limit, offset)
        assert display.footer(page, len(display.groups(page['records']))) == expected
        assert 'page may split groups' not in display.render_timeline(page)


@pytest.mark.parametrize('width', [40, 80, 120])
@pytest.mark.parametrize('colored', [False, True])
def test_layout_wrapping_palette_and_control_safety(width, colored):
    result, anchors = window(2)
    for r in result['records']:
        r['detail']['names'] = [dict(filename=r'\\server\share' + '\\' + 'long-directory\\' * 8 + 'example.bin\x1b[31m')]
    page = display.page(result, 2, 0)
    groups = display.groups(page['records'])
    lines = display.render_blocks(groups, width=width, palette=Palette(colored))
    plain = SGR.sub('', '\n'.join(lines))
    assert max(map(len, plain.splitlines())) <= width
    assert 'TIME (UTC)' in plain and 'STATE' in plain and 'OBJECT' in plain
    assert '\n\n' in plain and '    SI  Created' in plain
    assert '|' not in plain and LIMITATION not in plain and '\x1b' not in plain
    assert 'example.bin' in plain.replace('\n', '').replace(' ', '')
    assert plain == '\n'.join(display.render_blocks(groups, width=width))


@pytest.mark.parametrize('limit,offset', [(0, 0), (10001, 0), (1, -1)])
def test_invalid_group_pagination(limit, offset):
    with pytest.raises(ValueError, match='pagination'):
        display.page(window()[0], limit, offset)


def test_incomplete_window_is_never_published_as_complete_group():
    result, _ = window()
    result['records'] = result['records'][:5]
    with pytest.raises(ValueError, match='Complete timestamp window'):
        display.page(result, 1, 0)


@pytest.fixture
def case(tmp_path):
    from forensic_assistant.database.db import connect
    from forensic_assistant.artifacts.ingest import ingest_artifact
    from v2_fixtures import mft_record
    path = tmp_path / 'synthetic-mft'
    path.write_bytes(b''.join(mft_record(number=i, names=(f'example-{i}.bin',)) for i in range(12)))
    db = connect(':memory:')
    try:
        assert ingest_artifact(db, path, 'mft', hostname='synthetic-pc')['inserted'] == 12
        ids = [r[0] for r in db.execute('SELECT evidence_id FROM mft_records ORDER BY record_number')]
        with db:
            for i, eid in enumerate(ids):
                db.execute('UPDATE evidence_timestamps SET timestamp_utc=? WHERE evidence_id=?',
                           (f'2026-01-01T00:00:{i:02d}.000000000Z', eid))
        yield db, ids
    finally:
        db.close()


def test_dispatch_text_vs_json_and_raw_pagination(case):
    db, ids = case
    parser = build_parser()
    base = ['timeline', '--start', '2026-01-01T00:00:00Z', '--end', '2026-01-01T00:01:00Z',
            '--artifact', 'mft', '--limit', '1', '--offset', '1']
    text, _ = v2_cli.dispatch(db, parser.parse_args(base + ['--text']))
    assert len(text['records']) == 8 and {r['id'] for r in text['records']} == {ids[1]}
    for flag in ('--json', '--raw'):
        raw, _ = v2_cli.dispatch(db, parser.parse_args(base + [flag]))
        assert len(raw['records']) == 1 and raw['records'][0]['id'] == ids[0]
        assert raw['total'] == 96 and '_mft_page' not in raw
        assert raw['offset'] == 1 and raw['limit'] == 1
        json.dumps(raw)


@pytest.mark.parametrize('direction', ['around', 'before', 'after'])
def test_dispatch_direction_preserved_anchor_always_visible(case, direction):
    db, ids = case
    args = build_parser().parse_args(['around', ids[5], '--timestamp-slot', 'attribute:56:Created',
                                     '--seconds', '60', '--direction', direction, '--limit', '5', '--text'])
    result, _ = v2_cli.dispatch(db, args)
    groups = display.groups(result['records'])
    assert len(groups) == 5 and any(g[0]['id'] == ids[5] for g in groups)
    for g in groups:
        assert len(g) == 8
        if g[0]['id'] != ids[5] and direction != 'around':
            assert (g[0]['timestamp_utc'] < '2026-01-01T00:00:05.000000000Z') == (direction == 'before')
    args.text, args.json = False, True
    raw, _ = v2_cli.dispatch(db, args)
    assert len(raw['records']) == 5 and '_mft_page' not in raw
    if direction != 'around':
        assert all(r['id'] != ids[5] for r in raw['records'])


def test_cap_checked_before_hydration_and_read_transaction_released(case, monkeypatch):
    db, ids = case
    with db:
        for i in range(10001):
            db.execute('''INSERT INTO evidence_timestamps
                (evidence_id,slot,original_value,encoding,source,meaning,precision_ns,timestamp_utc,normalization_status)
                SELECT evidence_id,?,original_value,encoding,source,meaning,precision_ns,timestamp_utc,normalization_status
                FROM evidence_timestamps WHERE evidence_id=? AND slot='attribute:56:Created' ''', (f'extra:{i}', ids[0]))
    from forensic_assistant.retrieval import evidence
    monkeypatch.setattr(evidence, 'get_evidence', lambda *a, **k: pytest.fail('Cap must precede hydration'))
    with pytest.raises(ValueError, match='10,000'):
        EvidenceQueries(db).complete_timeline(artifact='mft', start='2026-01-01T00:00:00Z', end='2026-01-01T00:01:00Z')
    assert not db.in_transaction


def test_snapshot_release_preserves_outer_transaction(case):
    db, _ = case
    db.execute('BEGIN')
    result = EvidenceQueries(db).complete_timeline(artifact='mft')
    assert len(result.records) == 96 and db.in_transaction
    db.rollback()


def test_complete_text_hydrates_once_per_evidence_not_per_slot(case, monkeypatch):
    db, ids = case
    from forensic_assistant.retrieval import evidence
    original = evidence.get_evidence
    calls = []
    def tracked(db, eid, raw=False):
        calls.append(eid)
        return original(db, eid, raw)
    monkeypatch.setattr(evidence, 'get_evidence', tracked)
    result = EvidenceQueries(db).complete_timeline(artifact='mft')
    assert len(result.records) == 96 and len(calls) == len(set(calls)) == 12
    assert not db.in_transaction
    snapshots = copy.deepcopy(result.records)
    projected = display.page({**vars(result), 'truncated': result.truncated}, 5, 0)
    display.render_timeline(projected)
    assert result.records == snapshots


def test_evtx_structured_pagination_and_text_group_layout():
    from test_v1_temporal import fixture_db
    db = fixture_db()
    try:
        parser = build_parser()
        argv = ['timeline', '--around', '2026-09-15T14:31:00Z', '--limit', '2', '--offset', '1']
        structured, _ = v2_cli.dispatch(db, parser.parse_args(argv + ['--json']))
        text, _ = v2_cli.dispatch(db, parser.parse_args(argv + ['--text']))
        assert text['records'] == structured['records'] and '_mft_page' not in text
        assert structured['limit'] == 2 and structured['offset'] == 1 and '_evtx_page' not in structured
        shown = v2_cli.render(text, methodology=False)
        assert 'TIME (UTC)' in shown and 'TYPE' in shown and 'EVIDENCE ID' not in shown
        eid = db.execute('SELECT id FROM events WHERE record_offset=513').fetchone()[0]
        argv = ['around', eid, '--limit', '2', '--offset', '1']
        context = {}
        text, _ = v2_cli.dispatch(db, parser.parse_args(argv + ['--text']), presentation=context)
        structured, _ = v2_cli.dispatch(db, parser.parse_args(argv + ['--json']))
        assert structured['limit'] == 2 and structured['offset'] == 1 and '_evtx_page' not in structured
        assert any(r['id'] == eid for r in text['records'])
        shown = around_display.render(text, context['anchor'], context['stamp'], parser.parse_args(argv + ['--text']))
        assert 'OBJECT' in shown and 'TYPE' in shown and 'STATE' not in shown
    finally:
        db.close()

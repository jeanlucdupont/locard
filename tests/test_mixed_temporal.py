"""Synthetic mixed-host/source observations; no real evidence fixtures."""
import codecs
import copy
import json
import struct
from contextlib import closing
from datetime import datetime, timezone

import pytest

from forensic_assistant import v2_cli
from forensic_assistant.cli import build_parser
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant.retrieval import mixed_display, around_display, registry_display, search_display
from forensic_assistant.retrieval.evidence import EvidenceQueries, get_evidence
from forensic_assistant.terminal import Palette, SGR
from v2_fixtures import prefetch_file, registry_file, mft_file, evtx_process
from test_userassist import binary

UA_SLOT = 'UserAssist.LastExecution'
PF_TIME = '2020-01-01T10:00:00.100000000Z'
UA_TIME = '2020-01-01T10:00:00.050000000Z'
BASE_FT = int((datetime(2020, 1, 1, 10, tzinfo=timezone.utc) -
               datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 10_000_000


@pytest.fixture
def mixed_case(tmp_path):
    pf = prefetch_file(tmp_path / 'synthetic.pf', name='TEST.EXE')
    raw = bytearray(pf.read_bytes())
    struct.pack_into('<Q', raw, 120, BASE_FT + 1_000_000)
    pf.write_bytes(raw)
    hive = registry_file(tmp_path / 'synthetic.hive', userassist=[
        (codecs.encode('test.exe', 'rot_13'), 3, binary(ft=BASE_FT + 500_000))])
    with closing(connect(':memory:')) as db:
        sids = []
        for kind, path, user in [('prefetch', pf, None), ('registry', hive, 'analyst')]:
            with db:
                sid = sources.create(db, name=kind, hostname='HOST-A', username=user)
                sids.append(sid)
            result, code = v2_cli.dispatch(db, build_parser().parse_args([
                'ingest-' + kind, str(path), '--source', sid]))
            assert code == 0, result
        pfid = db.execute('SELECT evidence_id FROM prefetch_records').fetchone()[0]
        uaid = db.execute('SELECT evidence_id FROM registry_values WHERE value_name=?', ('grfg.rkr',)).fetchone()[0]
        yield db, pfid, uaid, sids


def around(db, eid, slot, *extra):
    args = build_parser().parse_args(['around', eid, '--timestamp-slot', slot, '--seconds', '1', *extra])
    result, code = v2_cli.dispatch(db, args)
    assert code == 0
    return result, args


def test_cross_source_both_directions_and_exact_deltas(mixed_case):
    db, pfid, uaid, sids = mixed_case
    before = list(db.iterdump())
    for eid, slot, neighbor, delta in [(pfid, 'run:0', uaid, '-0.050s'), (uaid, UA_SLOT, pfid, '+0.050s')]:
        structured, _ = around(db, eid, slot)
        assert {r['id'] for r in structured['records']} == {pfid, uaid}
        rows = {r['id']: r for r in structured['records']}
        assert rows[pfid]['context']['source_ids'] == [sids[0]]
        assert rows[uaid]['context']['source_ids'] == [sids[1]]
        assert rows[pfid]['context']['username'] is None
        assert rows[uaid]['context']['username'] == 'analyst'
        text, args = around(db, eid, slot, '--text')
        anchor = get_evidence(db, eid)
        shown = around_display.render(text, anchor, v2_cli.anchor_time(anchor, slot), args, width=160)
        assert delta in shown and shown.count('<- anchor') == 1
        assert 'TEST.EXE' in shown and 'test.exe' in shown and '[run:0]' in shown and '[' + UA_SLOT + ']' in shown
        assert pfid not in shown and uaid not in shown
        assert [r['timestamp_utc'] for r in text['records']] == [UA_TIME, PF_TIME]
    assert before == list(db.iterdump())


@pytest.mark.parametrize('state', ['other-host', 'unknown', 'conflict', 'ambiguous'])
def test_host_boundaries_and_anchor_refusal(mixed_case, state):
    db, pfid, uaid, sids = mixed_case
    with db:
        if state in ('other-host', 'unknown'):
            sources.update(db, sids[1], hostname='host-b' if state == 'other-host' else None)
        elif state == 'conflict':
            db.execute('UPDATE evidence_records SET hostname=? WHERE evidence_id=?', ('host-b', uaid))
        else:
            sid = sources.create(db, name='second membership', hostname='host-a')
            sources.assign(db, sid, [get_evidence(db, uaid)['file_sha256']], reason='Synthetic ambiguity')
    result, _ = around(db, pfid, 'run:0')
    assert {r['id'] for r in result['records']} == {pfid}
    if state != 'other-host':
        with pytest.raises(ValueError, match='Host context missing|Multiple source'):
            around(db, uaid, UA_SLOT)


def test_shared_source_with_unknown_host_still_refuses(mixed_case):
    db, pfid, _, sids = mixed_case
    with db:
        sources.update(db, sids[0], hostname=None)
    with pytest.raises(ValueError, match='Host context missing'):
        around(db, pfid, 'run:0', '--text')


@pytest.mark.parametrize('kind,filters', [('prefetch', ['--process', 'TEST.EXE']), ('registry', ['--user', 'analyst'])])
@pytest.mark.parametrize('window', [['--start', '2019-01-01T00:00:00Z', '--end', '2021-01-01T00:00:00Z'],
                                   ['--around', '2020-01-01T10:00:00Z', '--minutes', '525600']])
def test_single_artifact_default_timeline_preserves_observation_pagination(mixed_case, kind, filters, window):
    db, _, _, _ = mixed_case
    command = ['timeline', *window, *filters, '--text', '--limit', '1', '--offset', '1']
    implicit, _ = v2_cli.dispatch(db, build_parser().parse_args(command))
    explicit, _ = v2_cli.dispatch(db, build_parser().parse_args([*command, '--artifact', kind]))
    assert implicit == explicit
    assert implicit['offset'] == 1 and implicit['limit'] == 1
    assert v2_cli.render(implicit, methodology=False) == v2_cli.render(explicit, methodology=False)


@pytest.mark.parametrize('direction', ['before', 'after', 'around'])
def test_anchor_survives_limit_offset_and_direction(mixed_case, direction):
    db, pfid, _, _ = mixed_case
    # Equal run times are still separate Prefetch observations; select run:1.
    with db:
        cols = [r[1] for r in db.execute('PRAGMA table_info(evidence_timestamps)')]
        row = dict(db.execute('SELECT * FROM evidence_timestamps WHERE evidence_id=?', (pfid,)).fetchone())
        row['slot'] = 'run:1'
        db.execute('INSERT INTO evidence_timestamps VALUES (' + ','.join('?' for _ in cols) + ')', [row[k] for k in cols])
    result, args = around(db, pfid, 'run:1', '--text', '--limit', '1', '--offset', '100', '--direction', direction)
    assert len(result['records']) == 1 and result['records'][0]['timestamp']['slot'] == 'run:1'
    text = around_display.render(result, get_evidence(db, pfid), PF_TIME, args)
    assert text.count('<- anchor') == 1 and 'run:1' in text


def test_all_families_retrieved_and_grouped_with_complete_slots(mixed_case, tmp_path):
    from forensic_assistant.artifacts.ingest import ingest_artifact
    db, pfid, uaid, _ = mixed_case
    ev = evtx_process(db, host='host-a')
    assert ingest_artifact(db, mft_file(tmp_path / 'synthetic.mft'), 'mft', hostname='host-a')['status'] == 'complete'
    with db:
        db.execute("UPDATE evidence_timestamps SET timestamp_utc=? WHERE evidence_id IN "
                   "(SELECT evidence_id FROM evidence_records WHERE source_type IN ('mft','evtx'))", (PF_TIME,))
    result, args = around(db, pfid, 'run:0', '--text')
    assert {r['source_type'] for r in result['records']} == {'prefetch', 'registry', 'mft', 'evtx'}
    # A page may contain more observations than its group limit, never half an MFT group.
    all_mft = [r for r in result['records'] if r['source_type'] == 'mft']
    assert all_mft
    for eid in {r['id'] for r in all_mft}:
        assert len([r for r in all_mft if r['id'] == eid]) == len(get_evidence(db, eid)['timestamps'])
    keys = [(r['timestamp_utc'], r['id'], r['timestamp']['slot']) for r in result['records']]
    assert keys == sorted(keys)
    assert all(r['host_key'] == 'host-a' for r in result['records'])
    command = ['timeline', '--start', '2020-01-01T10:00:00Z', '--end', '2020-01-01T10:00:01Z']
    output, code = v2_cli.dispatch(db, build_parser().parse_args([*command, '--text']))
    assert code == 0 and mixed_display.is_mixed(output)
    text = v2_cli.render(output, methodology=False)
    assert all(label in text for label in ('MFT', 'EVTX', 'Prefetch', 'UserAssist'))
    for kind in ('mft', 'evtx', 'prefetch', 'registry'):
        args = build_parser().parse_args([*command, '--artifact', kind, '--text'])
        filtered, _ = v2_cli.dispatch(db, args)
        assert {r['source_type'] for r in filtered['records']} == {kind}
        assert not mixed_display.is_mixed(filtered)
        assert 'omitted from this compact page' not in v2_cli.render(filtered, methodology=False)
    structured, _ = v2_cli.dispatch(db, build_parser().parse_args([*command, '--json']))
    assert not any(key.startswith('_') for key in structured)
    assert {r['source_type'] for r in structured['records']} == {'mft', 'evtx', 'prefetch', 'registry'}


def mixed_rows():
    from test_mft_presentation import example, timeline
    from test_around_display import example as pf_example
    from test_sysmon_file_create import add
    mft = timeline(example())['records']
    anchor, pf, args = pf_example()
    with closing(connect(':memory:')) as db:
        add(db)
        evtx = EvidenceQueries(db).search(timeline=True).records
    key = dict(id='REGISTRY:synthetic:key', source_type='registry', artifact_type='registry_key',
               detail=dict(key_path=r'Software\Synthetic\UserAssist'), context={}, warnings=[],
               timestamp_utc=PF_TIME, timestamp=dict(slot='LastWrite', source='Registry LastWrite', meaning='key context'))
    ua = dict(key, id='REGISTRY:synthetic:value', artifact_type='registry_value',
              detail=dict(userassist=dict(decoded_name=r'C:\Apps\test.exe'), key_path=r'Software\Synthetic', value_name='grfg.rkr'),
              timestamp=dict(slot=UA_SLOT, source='UserAssist LastExecution', meaning='interaction'))
    rows = sorted([*mft, *pf['records'], *evtx, key, ua], key=lambda r: (r['timestamp_utc'], r['id'], r['timestamp']['slot']))
    return dict(records=rows, total=len(rows), offset=0, truncated=False), anchor, args


@pytest.mark.parametrize('width', [40, 80, 160])
def test_mixed_renderer_color_semantics_safety_and_immutability(width):
    result, anchor, args = mixed_rows()
    before = copy.deepcopy(result)
    for around_mode in (False, True):
        opts = dict(anchor=anchor, stamp=anchor['timestamps'][1]['timestamp_utc'], args=args) if around_mode else {}
        plain = mixed_display.render(result, width=width, **opts)
        colored = mixed_display.render(result, width=width, palette=Palette(True), **opts)
        assert SGR.sub('', colored) == plain and '\x1b[' in colored
        assert max(map(len, plain.splitlines())) <= width
        for label in ('Prefetch', 'UserAssist', 'RegistryKey', 'EVTX', 'MFT', 'TYPE', 'OBJECT'):
            assert label in plain
        compact = ''.join(plain.split())
        for r in result['records']:
            assert r['id'] not in plain
            assert r['timestamp']['slot'] in compact
        assert 'test.exe' in plain and 'UserAssist' in plain and 'not individual value creation' not in plain
    assert result == before


def test_registry_summary_count_anchor_and_full_modes():
    result, anchor, args = mixed_rows()
    key = next(r for r in result['records'] if r['artifact_type'] == 'registry_key')
    keys = [dict(key, id=f'REGISTRY:synthetic:{i}', warnings=[registry_display.KEY_CORRUPTION] * 2) for i in range(30)]
    result['records'] = [r for r in result['records'] if r is not key] + keys
    result['total'] = len(result['records'])
    before = json.dumps(result)
    plain = mixed_display.render(result, width=200)
    assert '27 additional Registry LastWrite observations omitted' in plain
    assert plain.count('parser reported key corruption') == 1 and '30 records in this page' in plain
    assert json.dumps(result) == before
    anchor = dict(keys[-1], timestamps=[keys[-1]['timestamp'] | dict(timestamp_utc=PF_TIME)])
    args.timestamp_slot = 'LastWrite'
    plain = mixed_display.render(result, anchor=anchor, stamp=PF_TIME, args=args, width=200)
    assert '26 additional' in plain and plain.count('<- anchor') == 1
    args.ids = True
    detailed = mixed_display.render(result, anchor=anchor, stamp=PF_TIME, args=args, width=200)
    assert 'omitted' not in detailed and all(r['id'] in detailed for r in keys)
    registry_only = dict(result, records=keys, total=len(keys))
    assert not mixed_display.is_mixed(registry_only)
    shown = v2_cli.render(registry_only, methodology=False)
    assert all(r['id'] in shown for r in keys) and 'omitted' not in shown


@pytest.mark.parametrize('name', [r'C:\Windows\System32\test.exe', r'\\server\share\test.exe', r'regex \w+'])
def test_registry_value_paths_scoped_to_human_fields(name):
    record = dict(id='REGISTRY:synthetic:value', source_type='registry', detail=dict(
        key_path=r'Software\Example', value_name=name, value_type=3, value_data={}), context={}, timestamps=[], warnings=[])
    result = dict(records=[record], total=1)
    before = json.dumps(result)
    expected = name if registry_display.path_name(name) else name.replace('\\', '\\\\')
    assert expected in registry_display.render(record)
    assert expected in search_display.render(result, width=300)
    assert json.dumps(result) == before and name.replace('\\', '\\\\') in before


def test_text_safety_bound_does_not_silently_truncate(mixed_case):
    db, pfid, _, _ = mixed_case
    with db:
        cols = [r[1] for r in db.execute('PRAGMA table_info(evidence_timestamps)')]
        row = dict(db.execute('SELECT * FROM evidence_timestamps WHERE evidence_id=?', (pfid,)).fetchone())
        data = [dict(row, slot=f'synthetic:{i}') for i in range(10000)]
        db.executemany('INSERT INTO evidence_timestamps VALUES (' + ','.join('?' for _ in cols) + ')',
                       [[r[k] for k in cols] for r in data])
    with pytest.raises(ValueError, match='10,000'):
        around(db, pfid, 'run:0', '--text', '--limit', '1')
    result, _ = around(db, pfid, 'run:0', '--json', '--limit', '1')
    assert len(result['records']) == 1 and result['truncated'] and result['total'] > 10000

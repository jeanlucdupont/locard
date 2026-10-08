"""Bounded deterministic investigations; generated fixtures only."""
import copy
import json
from collections import Counter

import pytest

from forensic_assistant.correlation import investigation as inv
from forensic_assistant.database import sources
from forensic_assistant.database.artifacts import register, add_timestamp
from forensic_assistant.retrieval import evidence as ev
from forensic_assistant.retrieval.analysis_display import render_investigation
from forensic_assistant.retrieval.registry_display import KEY_CORRUPTION
from forensic_assistant.terminal import Palette, SGR
from test_mixed_temporal import mixed_case, PF_TIME, UA_TIME, UA_SLOT


def registry_rows(db, uaid, count, when, *, values=False):
    original = dict(db.execute('SELECT * FROM evidence_records WHERE evidence_id=?', (uaid,)).fetchone())
    t = dict(db.execute('SELECT * FROM evidence_timestamps WHERE evidence_id=?', (uaid,)).fetchone())
    t.update(slot='LastWrite', timestamp_utc=when, source='Registry Key LastWrite', meaning='Key context')
    ids = []
    with db:
        for i in range(count):
            eid = f"REGISTRY:{original['file_sha256']}:KeyOffset:{900000+i}"
            register(db, dict(original, evidence_id=eid, artifact_type='registry_key', warnings_json=json.dumps([KEY_CORRUPTION])))
            db.execute('INSERT INTO registry_keys VALUES (?,?,?,?)', (eid, f'Software\\Synthetic\\Key{i}', None, 900000+i))
            add_timestamp(db, eid, t)
            ids.append(eid)
            if values:
                vid = f"REGISTRY:{original['file_sha256']}:ValueOffset:{910000+i}"
                register(db, dict(original, evidence_id=vid))
                db.execute('INSERT INTO registry_values VALUES (?,?,?,?,?,?,?)', (vid, eid, 'Synthetic', 3, b'x', 'null', 910000+i))
    return ids


@pytest.mark.parametrize('equal', [False, True])
def test_ambiguous_anchor_stops_before_queries_or_correlation(mixed_case, monkeypatch, equal):
    db, _, uaid, _ = mixed_case
    if equal:
        with db:
            key = ev.get_evidence(db, uaid)['detail']['key_id']
            db.execute('UPDATE evidence_timestamps SET timestamp_utc=? WHERE evidence_id=?', (UA_TIME, key))
    def forbidden(*args, **kwargs):
        pytest.fail('Ambiguous anchor performed investigation work')
    for name in ('correlate', 'detections', 'process_tree'):
        monkeypatch.setattr(inv, name, forbidden)
    monkeypatch.setattr(inv.Assembly, 'add_sessions', forbidden)
    monkeypatch.setattr(ev.EvidenceQueries, 'search', forbidden)
    result = inv.investigate(db, uaid, seconds=1)
    assert result['retrieved_record_count'] == 1 and result['source_query_counts'] == []
    assert result['temporal_neighbor_ids'] == [] and result['detections'] == []
    text = render_investigation(result)
    assert 'Available slots:' in text and 'LastWrite' in text and UA_SLOT in text
    assert 'Temporal search not performed' in text and 'Temporal search window:' not in text
    assert 'Not evaluated; temporal anchor unresolved' in text


def test_reciprocal_neighbors_provenance_and_command_cache(mixed_case, monkeypatch):
    db, pfid, uaid, sids = mixed_case
    with db:
        sources.update(db, sids[1], username='alice')
    loads = Counter()
    original = inv.evidence
    def counted(db, eid):
        loads[eid] += 1
        return original(db, eid)
    monkeypatch.setattr(inv, 'evidence', counted)
    queries = []
    search = ev.EvidenceQueries.search
    def counted_query(self, **kw):
        queries.append(kw)
        return search(self, **kw)
    monkeypatch.setattr(ev.EvidenceQueries, 'search', counted_query)
    for eid, slot, neighbor, delta in [(pfid, None, uaid, '-0.050s'), (uaid, UA_SLOT, pfid, '+0.050s')]:
        loads.clear()
        queries.clear()
        result = inv.investigate(db, eid, seconds=1, timestamp_slot=slot)
        assert neighbor in result['temporal_neighbor_ids']
        assert all(count == 1 for count in loads.values())
        temporal = [q for q in queries if q.get('timeline')]
        assert len(temporal) == 1 and temporal[0]['strict_host'] and temporal[0]['hostname'] == 'host-a'
        rows = {r['id']: r for r in result['evidence_records']}
        assert rows[pfid]['context']['source_ids'] == [sids[0]]
        assert rows[uaid]['context']['source_ids'] == [sids[1]]
        assert rows[uaid]['username'] == 'alice' and rows[pfid]['username'] is None
        before = copy.deepcopy(result)
        text = render_investigation(result)
        assert delta in text and 'TEST.EXE' in text and 'test.exe' in text
        assert 'Temporal proximity only; not a causal relationship.' in text
        assert 'Object projection is bounded' not in text
        assert SGR.sub('', render_investigation(result, Palette(True))) == text
        assert result == before
    # A later command must see new analyst assertions, never a retained global cache.
    with db:
        sources.update(db, sids[1], hostname='host-b')
    result = inv.investigate(db, pfid, seconds=1)
    assert uaid not in result['temporal_neighbor_ids']


@pytest.mark.parametrize('mode', ['unknown', 'conflict', 'ambiguous'])
def test_host_safety(mixed_case, mode):
    db, pfid, uaid, sids = mixed_case
    with db:
        if mode == 'unknown':
            sources.update(db, sids[1], hostname=None)
        elif mode == 'conflict':
            db.execute('UPDATE evidence_records SET hostname=? WHERE evidence_id=?', ('host-b', uaid))
        else:
            sid = sources.create(db, hostname='host-a')
            sources.assign(db, sid, [ev.get_evidence(db, uaid)['file_sha256']], reason='Synthetic ambiguity')
    assert uaid not in inv.investigate(db, pfid, seconds=1)['temporal_neighbor_ids']
    result = inv.investigate(db, uaid, seconds=1, timestamp_slot=UA_SLOT)
    assert result['temporal_neighbor_ids'] == []
    assert not any(q.get('query') == 'temporal' for q in result['source_query_counts'])


def test_compaction_counts_notes_and_all_structured_records(mixed_case):
    from forensic_assistant.retrieval.artifact_notes import PREFETCH, USERASSIST
    db, pfid, uaid, _ = mixed_case
    ids = registry_rows(db, uaid, 30, PF_TIME)
    result = inv.investigate(db, uaid, seconds=1, timestamp_slot=UA_SLOT)
    before = json.dumps(result)
    text = render_investigation(result)
    assert set(ids) <= {r['id'] for r in result['evidence_records']}
    assert '27 additional Registry LastWrite observations omitted' in text
    assert f"{len(result['evidence_records'])} evidence records retrieved" in text
    assert 'TYPE' in text and 'RegistryKey' in text and r'Software\Synthetic\Key' in text
    assert 'Registry key last-write; not individual value creation' not in text
    assert text.count('parser reported key corruption for 30 retrieved Registry records') == 1
    assert 'Parser reports key corruption' not in text
    assert all(text.count(note) == 1 for note in (*PREFETCH, *USERASSIST))
    assert json.dumps(result) == before
    # Repeated family notes remain single even when several records carry them.
    clone = copy.deepcopy(next(r for r in result['evidence_records'] if r['id'] == pfid))
    clone['id'] += ':synthetic'
    clone['warnings'].append('Unknown synthetic parser warning')
    clone['objects_truncated'] = True
    result['evidence_records'].append(clone)
    text = render_investigation(result)
    assert all(text.count(note) == 1 for note in PREFETCH)
    assert 'Unknown synthetic parser warning' in text and 'Object projection is bounded' in text


def test_registry_time_candidates_are_bounded_before_userassist_decode(mixed_case, monkeypatch):
    from forensic_assistant.artifacts import userassist
    db, _, uaid, _ = mixed_case
    registry_rows(db, uaid, 250, '2022-01-01T00:00:00.000000000Z', values=True)
    calls = []
    load = userassist.load
    def counted(*args):
        calls.append(args[1])
        return load(*args)
    monkeypatch.setattr(userassist, 'load', counted)
    result = ev.EvidenceQueries(db).search(artifact='registry', evidence_kind='registry_value',
        start=UA_TIME, end=PF_TIME, hostname='host-a', limit=500)
    assert [r['id'] for r in result.records] == [uaid]
    # A fixed number of timeline passes, not one derived scan per Registry value.
    assert len(calls) < 30


@pytest.mark.parametrize('filters', [{}, {'artifact': 'registry'}, {'evidence_kind': 'registry_value'},
                                    {'hostname': 'host-a'}, {'hostname': 'host-a', 'strict_host': True}])
def test_bounded_id_selection_matches_own_or_inherited_time_contract(mixed_case, filters):
    db, _, uaid, _ = mixed_case
    registry_rows(db, uaid, 5, PF_TIME, values=True)
    q = ev.EvidenceQueries(db)
    all_rows = q.search(limit=1000, **filters).records
    expected = {r['id'] for r in all_rows if any(t['timestamp_utc'] and UA_TIME <= t['timestamp_utc'] <= PF_TIME for t in r['timestamps'])}
    found = q.search(start=UA_TIME, end=PF_TIME, limit=1000, **filters)
    assert {r['id'] for r in found.records} == expected
    assert found.total == len(expected)
    assert q.search(start=UA_TIME, end=PF_TIME, limit=1, offset=1, **filters).records == found.records[1:2]


def test_ai_adapter_preserves_explicit_and_unresolved_investigations(mixed_case):
    from forensic_assistant.investigation_ai.tools import execute
    db, pfid, uaid, _ = mixed_case
    config = dict(known_ids=[uaid], semantic_enabled=False, rule_ids=[])
    result = execute(db, 'investigate_evidence', dict(evidence_id=uaid, seconds=1, timestamp_slot=UA_SLOT), config)
    assert result['behavior'] == 'deterministic'
    assert {pfid, uaid} <= {r['id'] for r in result['records']}
    result = execute(db, 'investigate_evidence', dict(evidence_id=uaid, seconds=1), config)
    assert pfid not in {r['id'] for r in result['records']}
    assert any(r['relationship'] == 'temporal' and r['status'] == 'UNRESOLVED' for r in result['relationships'])

"""Record-local host trust must not be poisoned by mixed source coverage."""
from contextlib import closing

from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant.retrieval.evidence import EvidenceQueries, get_evidence
from forensic_assistant.retrieval.search_display import render
from forensic_assistant.correlation.investigation import investigate
from forensic_assistant.detections.engine import detections
from forensic_assistant.cli import build_parser
from forensic_assistant.v2_cli import dispatch
from test_scm_service import add, raw
from test_mixed_temporal import mixed_case


def records(db, hostname='host-a.example.local'):
    result = []
    for index, host in enumerate(['HOST-A.EXAMPLE.LOCAL', 'host-b.example.local', 'host-a', '']):
        result.append(add(db, raw().replace('PC.example', host), 512 + index * 512))
    with db:
        sid = sources.create(db, name='Synthetic mixed source', hostname=hostname)
        sources.assign(db, sid, [result[0]['file_sha256']], reason='Synthetic explicit selection')
    return sid, [r['id'] for r in result]


def test_record_matrix_and_immutable_evidence():
    with closing(connect(':memory:')) as db:
        sid, ids = records(db)
        before = list(db.iterdump())
        rows = [get_evidence(db, eid, True) for eid in ids]
        assert [r['host_key'] for r in rows] == ['host-a.example.local', None, None, 'host-a.example.local']
        assert [r['context']['basis'] for r in rows] == ['source/artifact agreement', 'source/artifact mismatch', 'source/artifact mismatch', 'analyst-supplied']
        assert [r['context']['conflicts'] for r in rows] == [[], ['hostname'], ['hostname'], []]
        summary = sources.summary(db, sid)
        assert summary['host_conflict'] is True
        assert {h.casefold() for h in summary['artifact_hostnames']} >= {'host-a.example.local', 'host-b.example.local', 'host-a'}
        assert before == list(db.iterdump())


def test_unknown_source_keeps_individual_hosts_and_unknown():
    with closing(connect(':memory:')) as db:
        sid, ids = records(db, None)
        rows = [get_evidence(db, eid) for eid in ids]
        assert [r['host_key'] for r in rows] == ['host-a.example.local', 'host-b.example.local', 'host-a', None]
        assert [r['context']['basis'] for r in rows] == ['artifact field'] * 3 + ['unknown']
        assert all(not r['context']['conflicts'] for r in rows)
        assert sources.summary(db, sid)['host_conflict']


def test_current_revision_only_and_multiple_membership_guard():
    with closing(connect(':memory:')) as db:
        sid, ids = records(db, 'old-host')
        assert get_evidence(db, ids[0])['host_key'] is None
        with db:
            sources.update(db, sid, hostname='host-a.example.local')
        assert get_evidence(db, ids[0])['host_key'] == 'host-a.example.local'
        assert db.execute('SELECT count(*) FROM source_assertions WHERE source_id=?', (sid,)).fetchone()[0] == 2
        with db:
            other = sources.create(db, name='Other occurrence', hostname='host-a.example.local')
            sources.assign(db, other, [get_evidence(db, ids[0])['file_sha256']], reason='Synthetic second occurrence')
        assert get_evidence(db, ids[0])['host_key'] is None
        assert 'source membership' in get_evidence(db, ids[0])['context']['conflicts']


def test_search_timeline_around_investigate_and_detection_agree():
    with closing(connect(':memory:')) as db:
        sid, ids = records(db)
        result = EvidenceQueries(db).search(artifact='evtx')
        shown = render(result.as_dict(), ids=True, width=180)
        assert 'host-a.example.local' in shown and 'CONFLICT' in shown
        by_id = {r['id']: r for r in result.records}
        assert by_id[ids[0]]['context']['conflicts'] == []
        assert by_id[ids[1]]['context']['conflicts'] == ['hostname']
        for command in [
            ['timeline', '--hostname', 'host-a.example.local', '--start', '2026-09-15T14:30:54Z', '--end', '2026-09-15T14:30:56Z'],
            ['around', ids[0], '--seconds', '1'],
        ]:
            result, code = dispatch(db, build_parser().parse_args(command))
            assert code == 0
            assert {r['id'] for r in result['records']} == {ids[0], ids[3]}
        inv = investigate(db, ids[0], seconds=1)
        assert ids[3] in inv['temporal_neighbor_ids']
        assert not {ids[1], ids[2]} & set(inv['temporal_neighbor_ids'])
        found = detections(db, rule_id='LOCARD-SVC-001')['detections']
        assert len(found) == 4
        assert sum(ids[0] in d['evidence_ids'] for d in found) == 1
        with db:
            sources.update(db, sid, hostname=None)
        inv = investigate(db, ids[0], seconds=1)
        assert ids[3] not in inv['temporal_neighbor_ids']  # unknown cannot join
        assert not {ids[1], ids[2]} & set(inv['temporal_neighbor_ids'])


def test_single_host_source_still_resolves():
    with closing(connect(':memory:')) as db:
        record = add(db, raw().replace('PC.example', 'HOST-A'))
        with db:
            sid = sources.create(db, name='Single', hostname='host-a')
            sources.assign(db, sid, [record['file_sha256']], reason='Synthetic')
        assert get_evidence(db, record['id'])['host_key'] == 'host-a'
        assert not sources.summary(db, sid)['host_conflict']


def test_sql_resolution_cache_is_query_local(monkeypatch):
    import forensic_assistant.retrieval.evidence as module
    with closing(connect(':memory:')) as db:
        sid, ids = records(db)
        calls = []
        resolver = module.effective_context
        def counted(conn, record):
            calls.append((record['file_sha256'], record['hostname']))
            return resolver(conn, record)
        monkeypatch.setattr(module, 'effective_context', counted)
        query = EvidenceQueries(db, hydrate=lambda eid: {'id': eid})
        statements = []
        db.set_trace_callback(statements.append)
        query.search(hostname='host-a.example.local', strict_host=True)
        assert len(calls) == 4  # count and row selection share four distinct contexts
        assert not any('SELECT DISTINCT lower(e.hostname)' in sql for sql in statements)
        with db:
            sources.update(db, sid, hostname='host-b.example.local')
        result = query.search(hostname='host-b.example.local', strict_host=True)
        assert {r['id'] for r in result.records} == {ids[1], ids[3]}
        assert len(calls) == 8


def test_registry_record_uses_same_resolver(mixed_case):
    db, pfid, uaid, sids = mixed_case
    with db:
        db.execute('UPDATE evidence_records SET hostname=? WHERE evidence_id=?', ('HOST-A', uaid))
    row = get_evidence(db, uaid)
    assert row['host_key'] == 'host-a'
    assert row['context']['basis'] == 'source/artifact agreement'
    with db:
        sources.update(db, sids[1], hostname='host-b')
    assert get_evidence(db, uaid)['host_key'] is None
    assert get_evidence(db, uaid)['context']['basis'] == 'source/artifact mismatch'

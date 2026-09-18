from forensic_assistant.database.db import connect
from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.correlation.investigation import investigate,timeline_context
from v2_fixtures import registry_file,prefetch_file,mft_file,evtx_process


def test_cross_boundary_investigation(tmp_path):
    db=connect(':memory:');e=evtx_process(db)
    ingest_artifact(db,prefetch_file(tmp_path/'pf'),'prefetch',hostname='host')
    ingest_artifact(db,registry_file(tmp_path/'reg'),'registry',hostname='host')
    output=investigate(db,e['id'])
    assert {r['source_type'] for r in output['evidence_records']}=={'evtx','prefetch','registry'}
    assert output['artifact_distribution']['prefetch']==1
    assert any(r['status']=='CORROBORATED' for r in output['correlated_evidence'])
    key=db.execute("SELECT evidence_id FROM registry_keys WHERE key_path LIKE '%\\Run'").fetchone()[0]
    result=investigate(db,key)
    assert any(r['relationship']=='registry_key_contains_value' for r in result['correlated_evidence'])


def test_multi_timestamp_anchor_does_not_invent_temporal_time(tmp_path):
    db=connect(':memory:');ingest_artifact(db,mft_file(tmp_path/'mft'),'mft',hostname='host')
    eid=db.execute('SELECT evidence_id FROM mft_records WHERE record_number=6').fetchone()[0]
    output=investigate(db,eid)
    assert any('multiple timestamps' in r['reason'] for r in output['unresolved_relationships'])
    assert not output['temporal_neighbor_ids']

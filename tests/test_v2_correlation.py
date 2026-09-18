from forensic_assistant.database.db import connect
from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.correlation.cross_artifact import correlate
from forensic_assistant.detections.engine import detections
from v2_fixtures import prefetch_file,mft_file,registry_file,evtx_process


def test_prefetch_exact_path_and_time_corroborates(tmp_path):
    db=connect(':memory:');e=evtx_process(db)
    assert ingest_artifact(db,prefetch_file(tmp_path/'x.pf'),'prefetch',hostname='host')['status']=='complete'
    links=correlate(db,e['id'])['relationships']
    assert len(links)==1 and links[0]['status']=='CORROBORATED'
    result=detections(db,rule_id='LOCARD-X-001')
    assert len(result['detections'])==1
    assert len(result['detections'][0]['evidence_ids'])==2


def test_different_host_and_path_are_unresolved(tmp_path):
    db=connect(':memory:');e=evtx_process(db,path=r'C:\Other\PAYLOAD.EXE')
    ingest_artifact(db,prefetch_file(tmp_path/'x.pf'),'prefetch',hostname='host')
    assert correlate(db,e['id'])['relationships'][0]['status']=='UNRESOLVED'
    db2=connect(':memory:');e=evtx_process(db2)
    ingest_artifact(db2,tmp_path/'x.pf','prefetch',hostname='other')
    assert correlate(db2,e['id'])['relationships'][0]['status']=='UNRESOLVED'


def test_temporal_boundary_and_unknown_host(tmp_path):
    p=prefetch_file(tmp_path/'x.pf')
    for delta,expected in [(20_000_000,'CORROBORATED'),(20_000_001,'POSSIBLE')]:
        db=connect(':memory:');e=evtx_process(db,delta=delta)
        ingest_artifact(db,p,'prefetch',hostname='host')
        assert correlate(db,e['id'])['relationships'][0]['status']==expected
    db=connect(':memory:');e=evtx_process(db);ingest_artifact(db,p,'prefetch')
    assert correlate(db,e['id'])['relationships'][0]['status']=='POSSIBLE'


def test_registry_review_links_key_and_value(tmp_path):
    db=connect(':memory:');ingest_artifact(db,registry_file(tmp_path/'hive'),'registry',hostname='host')
    result=detections(db,rule_id='LOCARD-X-004')
    assert len(result['detections'])==1
    item=result['detections'][0];assert len(item['evidence_ids'])==2 and item['correlation_status']=='POSSIBLE'


def test_ambiguous_observations_not_selected(tmp_path):
    db=connect(':memory:');e=evtx_process(db)
    ingest_artifact(db,prefetch_file(tmp_path/'one',version=17),'prefetch',hostname='host')
    ingest_artifact(db,prefetch_file(tmp_path/'two',version=23),'prefetch',hostname='host')
    assert all(r['status']=='UNRESOLVED' for r in correlate(db,e['id'])['relationships'])
    assert correlate(db,e['id'],limit=1)['truncated']


def test_mft_metadata_and_persistence_sequence_rules(tmp_path):
    db=connect(':memory:');evtx_process(db,path=r'C:\payload.exe')
    ingest_artifact(db,mft_file(tmp_path/'mft'),'mft',hostname='host',volume_root='C:')
    assert len(detections(db,rule_id='LOCARD-X-002')['detections'])==1
    db2=connect(':memory:');evtx_process(db2,path=r'C:\Temp\powershell.exe',delta=-10_000_000,parent='WINWORD.EXE')
    ingest_artifact(db2,registry_file(tmp_path/'hive',target=r'C:\Temp\powershell.exe'),'registry',hostname='host')
    result=detections(db2,rule_id='LOCARD-X-003')['detections']
    assert len(result)==1 and len(result[0]['evidence_ids'])==3

import json
from forensic_assistant.database.db import connect
from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.retrieval.evidence import EvidenceQueries,get_evidence
from forensic_assistant.cli import main
from v2_fixtures import mft_file,prefetch_file,registry_file


def test_mixed_queries_and_timestamp_units(tmp_path):
    db=connect(':memory:')
    for kind,maker in [('mft',mft_file),('prefetch',prefetch_file),('registry',registry_file)]:
        assert ingest_artifact(db,maker(tmp_path/kind),kind,hostname='host')['status']=='complete'
    q=EvidenceQueries(db)
    assert q.search(artifact='prefetch').total==1
    assert q.search(path='payload.exe').total==3  # MFT, Prefetch executable name, and Registry path reference.
    result=q.search(timeline=True,start='2019-06-01T00:00:00Z',end='2020-01-01T00:00:00Z')
    assert {r['source_type'] for r in result.records}=={'mft','prefetch','registry'}
    assert result.total>q.search().total
    for r in result.records:
        assert r['timestamp']['meaning'] and r['timeline_id']
        if r['source_type']=='registry':assert r['artifact_type']=='registry_key'
    value=db.execute("SELECT evidence_id FROM registry_values WHERE value_name='Example'").fetchone()[0]
    shown=get_evidence(db,value)
    assert shown['timestamps'][0]['inherited_from_key']


def test_new_cli_mixed_directory(tmp_path,capsys):
    root=tmp_path/'evidence';root.mkdir()
    mft_file(root/'arbitrary');prefetch_file(root/'exec');registry_file(root/'hive')
    db=tmp_path/'case.db'
    assert main(['--db',str(db),'ingest-all',str(root),'--hostname','pc','--json'])==0
    assert len(json.loads(capsys.readouterr().out)['results'])==3
    assert main(['--db',str(db),'search','--artifact','registry','--json'])==0
    records=json.loads(capsys.readouterr().out)['records'];assert records
    assert main(['--db',str(db),'show',records[0]['id'],'--json'])==0
    assert json.loads(capsys.readouterr().out)['source']['sha256']

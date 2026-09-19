from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.semantic.documents import representation,chunks
from v1_fixtures import database
from v2_fixtures import registry_file,mft_file,prefetch_file
from test_v3_index import FakeModel

def test_all_artifact_representations_and_binary_omission(tmp_path):
    db=database()
    for kind,maker in [('registry',registry_file),('mft',mft_file),('prefetch',prefetch_file)]:
        assert ingest_artifact(db,maker(tmp_path/kind),kind)['status']=='complete'
    for (eid,) in db.execute('SELECT evidence_id FROM evidence_records'):
        record,text,cut=representation(db,eid)
        assert record['semantics']
        docs,_=chunks(db,eid,FakeModel())
        assert docs and all(d['evidence_id']==eid for d in docs)
    binary=db.execute("SELECT evidence_id FROM registry_values WHERE value_name='Binary'").fetchone()[0]
    assert 'AP8bAA==' not in representation(db,binary)[1]
    assert 'omitted_data' in representation(db,binary)[1]

import pytest
from v1_fixtures import database,process
from forensic_assistant.semantic.index import build,status

class FakeModel:
    dimension=384
    document_limit=512
    identity={'model_id':'test-only','revision':'synthetic','dimension':384}
    def count(self,text):return len(text)//4+1
    def encode(self,texts,query=False):return [[1.0]+[0.0]*383 for _ in texts]

def test_lifecycle_and_in_place_staleness(tmp_path):
    db=database();event=process(db,1,'100');root=tmp_path/'index'
    assert status(db,root)['state']=='unavailable'
    result=build(db,root,FakeModel());assert result['indexed']==1
    assert status(db,root)['state']=='current'
    with pytest.raises(ValueError,match='exists'):build(db,root,FakeModel())
    db.execute("UPDATE events SET command_line='changed' WHERE id=?",(event['id'],));db.commit()
    assert status(db,root)['state']=='stale'
    build(db,root,FakeModel(),rebuild=True)
    assert status(db,root)['state']=='current'

def test_failed_rebuild_preserves_generation(tmp_path):
    db=database();process(db,1,'100');process(db,2,'200');root=tmp_path/'index';build(db,root,FakeModel())
    pointer=(root/'CURRENT').read_text()
    with pytest.raises(ValueError,match='cap'):build(db,root,FakeModel(),rebuild=True,max_vectors=1)
    assert (root/'CURRENT').read_text()==pointer
    assert status(db,root)['state']=='current'

def test_corrupt_vectors_and_pointer_rejected(tmp_path):
    db=database();process(db,1,'100');root=tmp_path/'index';build(db,root,FakeModel())
    path=root/(root/'CURRENT').read_text()/'vectors.f32'
    with path.open('r+b') as f:f.write(b'FAIL')
    assert status(db,root)['state']=='unavailable'
    (root/'CURRENT').write_text('../escape')
    assert status(db,root)['state']=='unavailable'

@pytest.mark.parametrize('value',[0.0,float('nan'),float('inf'),1e308])
def test_invalid_embeddings_never_publish(tmp_path,value):
    class BadModel(FakeModel):
        def encode(self,texts,query=False):return [[value]*384 for _ in texts]
    db=database();process(db,1,'100');root=tmp_path/'index'
    with pytest.raises(ValueError):build(db,root,BadModel())
    assert not (root/'CURRENT').exists()

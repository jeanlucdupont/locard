"""Explicit offline integration: real CPU embeddings and FAISS, synthetic data."""
import argparse
import json
from pathlib import Path
import socket
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from v1_fixtures import database,process
from forensic_assistant.semantic.model import LocalModel
from forensic_assistant.semantic.index import build,status,search

def run(model_path,work):
    def deny(*args,**kwargs):raise AssertionError('Network attempted during offline investigation')
    socket.socket.connect=deny;socket.getaddrinfo=deny
    model=LocalModel(model_path)
    db=database();first=process(db,1,'100',host='ONE')
    second=process(db,2,'100',host='ONE')
    other=process(db,3,'200',host='TWO',name='cmd.exe')
    result=build(db,work,model,rebuild=True)
    assert result['embedding_cache_hits']>=1
    assert status(db,work)['state']=='current'
    hits=search(db,work,model,'PowerShell execution',hostname='one',limit=10)
    assert hits['results'] and all(r['evidence_id'] in (first['id'],second['id']) for r in hits['results'])
    assert hits['suppressed_duplicate_ids']
    assert all(-1.00001<=r['semantic_similarity']<=1.00001 for r in hits['results'])
    wrong_identity=model.identity;model.identity={**model.identity,'revision':'invalid'}
    try:
        try:search(db,work,model,'PowerShell')
        except ValueError as exc:assert 'mismatch' in str(exc)
        else:raise AssertionError('Model mismatch accepted')
    finally:model.identity=wrong_identity
    db.execute("UPDATE events SET command_line='changed' WHERE id=?",(first['id'],));db.commit()
    assert status(db,work)['state']=='stale'
    try:search(db,work,model,'PowerShell')
    except ValueError as exc:assert 'stale' in str(exc)
    else:raise AssertionError('Stale index accepted')
    build(db,work,model,rebuild=True)
    assert status(db,work)['state']=='current'
    print(json.dumps({'offline_load_build_search_rebuild':'passed','filters':'passed','duplicate_suppression':'passed','model_mismatch':'rejected','same_count_content_change':'rejected','device':str(model.model.device)}))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--model',type=Path,required=True);p.add_argument('--work',type=Path,required=True);a=p.parse_args();run(a.model,a.work)

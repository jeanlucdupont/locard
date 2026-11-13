"""Recorded empty histories retain view authority without weakening cross-view checks."""
from copy import deepcopy
import hashlib
from pathlib import Path
import pytest
from forensic_assistant.investigation_ai import synthesis as s, explanation as e, organization as o, autonomous as a, d2
from forensic_assistant.investigation_ai.transcript import load
from test_explanation_replay_status import empty_run
from test_synthesis_consumer import setup, reply
from test_organization import rehash


def forbidden(*args,**kwargs):pytest.fail('provider/database access')


def run(tmp_path,count):
    if count==0:return empty_run(tmp_path,'structure')
    config,worker,client,seen,closed=setup(tmp_path)
    if count==1:client.actions=iter(list(client.actions)[:2]+[{},reply,reply])
    return a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)


@pytest.mark.parametrize('count',[0,1,6])
def test_public_reconstruction_view(tmp_path,monkeypatch,count):
    result=run(tmp_path,count);root=tmp_path/'runs';rid=result['investigation_id']
    files=[root/rid/n for n in ('manifest.json','events.jsonl')];before=[f.read_bytes() for f in files]
    monkeypatch.setattr('sqlite3.connect',forbidden)
    monkeypatch.setattr('forensic_assistant.ai.backend.ModelBackend.complete',forbidden)
    m,_=load(root,rid);facts=s.reconstruct(root,rid)
    assert facts['validated_batches']==count and facts['evidence_state']==m['evidence_state']
    session=e.open_history(root,rid);assert session.organization['read_view']==facts['evidence_state']
    assert e.page(session)==e.page(e.open_history(root,rid))
    assert d2.open_history(root,rid)._ctx.factual==facts
    if count:
        legacy=s._Reducer();a.reconstruct(root,rid,_on_validated=legacy.consume)
        assert facts==legacy.finish()
    else:
        assert not facts['clauses'] and not facts['hypotheses']
        assert not any(v['kind']=='finding' for v in session.organization['entities'])
    assert before==[f.read_bytes() for f in files]


@pytest.mark.parametrize('change',['missing','null','unsupported','malformed','manifest_mismatch','delta_mismatch','invalid_chain'])
def test_public_reconstruction_rejects_bad_authority(tmp_path,change):
    result=run(tmp_path,1 if change=='delta_mismatch' else 0);root=tmp_path/'runs';rid=result['investigation_id'];folder=root/rid
    m,events=load(root,rid)
    if change=='missing':del m['evidence_state']
    elif change=='null':m['evidence_state']=None
    elif change=='unsupported':m['evidence_state']['contract']='unsupported'
    elif change=='malformed':m['evidence_state']['view_id']='not-a-view'
    elif change=='manifest_mismatch':m['evidence_state']['view_id']='c'*32
    elif change=='delta_mismatch':next(v['data'] for v in events if v['kind']=='validated_delta')['evidence_state']['view_id']='c'*32
    if change=='invalid_chain':
        events[0]['hash']='0'*64
        import json
        (folder/'events.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in events))
    else:rehash(folder,m,events)
    with pytest.raises((ValueError,KeyError)):s.reconstruct(root,rid)
    with pytest.raises((ValueError,KeyError)):e.open_history(root,rid)
    with pytest.raises((ValueError,KeyError)):d2.open_history(root,rid)


def test_validated_different_views_still_rejected(tmp_path):
    result=run(tmp_path,0);root=tmp_path/'runs';rid=result['investigation_id'];m,_=load(root,rid)
    facts=s.reconstruct(root,rid);org=o.reconstruct(root,rid)
    org['read_view']=dict(org['read_view'],view_id='f'*32)
    with pytest.raises(ValueError,match='Cross-view explanation'):e._Session(e._TOKEN,m,facts,org)


@pytest.mark.parametrize('folder,rid',[
    ('6.118-live','08cfd054f85a4a36b8520832427201c3'),
    ('6.118-live','6ad0c85499564406aa4d949f3b0e72e5'),
    ('6.111-b2','ec81a1af5b1f471ca4f3a4c0bb917fa2')])
def test_copied_history_readonly(folder,rid,monkeypatch):
    root=Path(r'C:\tmp\locard-diagnostics')/folder
    if not (root/rid/'manifest.json').exists():pytest.skip('readable historical copy unavailable')
    paths=[root/rid/n for n in ('manifest.json','events.jsonl')];before=[hashlib.sha256(f.read_bytes()).hexdigest() for f in paths]
    monkeypatch.setattr('sqlite3.connect',forbidden);monkeypatch.setattr('forensic_assistant.ai.backend.ModelBackend.complete',forbidden)
    facts=s.reconstruct(root,rid);m,_=load(root,rid)
    assert facts['evidence_state']==m['evidence_state']
    session=e.open_history(root,rid);assert e.page(session)==e.page(e.open_history(root,rid))
    if facts['validated_batches']:
        old=s._Reducer();a.reconstruct(root,rid,_on_validated=old.consume);assert old.finish()==facts
    else:assert facts['clauses']==[]
    assert before==[hashlib.sha256(f.read_bytes()).hexdigest() for f in paths]

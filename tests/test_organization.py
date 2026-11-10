"""C1 tests use synthetic journals, existing accepted validators and fake providers."""
from copy import deepcopy
import json
import pytest
from forensic_assistant.investigation_ai import organization as o, synthesis_consumer as b
from forensic_assistant.investigation_ai.transcript import load, digest, Transcript
from forensic_assistant.investigation_ai.state import encoded
from test_synthesis_consumer import execute


def test_live_checkpoints_and_independent_replay(tmp_path):
    result,client,seen,closed=execute(tmp_path)
    view=o.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert view==o.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert not view['incomplete'] and view['mode']=='recorded'
    assert len(client.calls)==9 and result['state']['steps']==10 and closed
    assert len([v for v in seen if v[0]=='show_evidence'])==6
    assert view['coverage']['organized_findings']==view['coverage']['observations']+view['coverage']['interpretations']
    assert view['coverage']['accepted_b2_proposals']==len(result['synthesis']['accepted'])
    assert view['state_digest']==result['organization']['digest']
    assert result['organization']['journal_bytes']<=65536
    assert result['organization']['elapsed_seconds']<=2
    assert len(encoded(view).encode())<=262144
    assert view['coverage']['forensic_completeness']=='not_established'
    proposals=[e for e in view['entities'] if e.get('role','').startswith('b2_')]
    assert all(e['classification']=='structurally_accepted_unverified' for e in proposals)
    assert len({e['introduced_by']['request_id'] for e in proposals})==2
    assert 'Request 1 aliases' in o.render_view(view) and 'Request 2 aliases' in o.render_view(view)
    assert all('value' not in d for e in view['entities'] for d in e.get('dependencies',[]))


def rehash(folder,manifest,events):
    chain='0'*64
    for n,event in enumerate(events):
        event.update(sequence=n,previous=chain);event.pop('hash',None)
        chain=digest(event);event['hash']=chain
    manifest.update(event_count=len(events),chain=chain)
    (folder/'events.jsonl').write_text(''.join(encoded(e)+'\n' for e in events),encoding='utf-8')
    (folder/'manifest.json').write_text(encoded(manifest),encoding='utf-8')


@pytest.mark.parametrize('change',['digest','prefix','foreign_frontier','profile'])
def test_checkpoint_corruption_fails_closed(tmp_path,change):
    result,*_=execute(tmp_path);root=tmp_path/'runs';rid=result['investigation_id']
    manifest,events=load(root,rid)
    cp=next(e['data'] for e in events if e['kind']=='organization_checkpoint')
    if change=='digest':cp['result_digest']='a'*64
    if change=='prefix':cp['applied']=129
    if change=='foreign_frontier':cp['frontier']['hash']='b'*64
    if change=='profile':manifest['organization_profile']='future-unknown'
    rehash(root/rid,manifest,events)
    with pytest.raises(ValueError):o.reconstruct(root,rid)
    with pytest.raises(ValueError):b.reconstruct(root,rid)


def source():
    # Pure reference-resource fixture, not an evidence-import endpoint.
    return o._Sources(dict(investigation_id='a'*32,question='Synthetic question',
        authorization={'evidence_ids':[]},evidence_state=dict(contract='sqlite-read-view-v1',
            view_id='b'*32,file_identity={'device':1,'inode':2})))


def test_partial_prefix_replay_ignores_wall_clock():
    s=source()
    for n in range(200):s._entity(str(n),'question','unverified',{'contract':'synthetic'},text='Unanswered')
    reducer=o._Reducer(s,clock=lambda:0)
    prepared,reason=reducer.prepare({'sequence':0,'hash':'c'*64})
    assert prepared[1]['applied']==128 and reason=='operation_prefix'
    reducer.commit(prepared)
    replay=o._Reducer(s,clock=lambda:9999999)
    checked,_=replay.prepare({'sequence':0,'hash':'c'*64},replay=prepared[1])
    replay.commit(checked)
    assert replay.state()==reducer.state() and reducer.coverage['known_unprocessed']==73


@pytest.mark.parametrize('cap',['entities','links','revisions','operations','visits','time','bytes','checkpoints'])
def test_hard_caps_and_large_reference_stream(cap):
    s=source();r=o._Reducer(s,clock=lambda:0)
    if cap=='links':
        r.entities=deepcopy(s.entities)
        for n in range(600):s.links[str(n)]={'id':str(n),'kind':'context_for','endpoints':[s.question_id,s.question_id]}
        r.links={str(n):s.links[str(n)] for n in range(512)}
    elif cap=='revisions':r.revisions[s.question_id]=8
    elif cap=='operations':r.operations=1024
    elif cap=='visits':r.visits=4096
    elif cap=='time':r.elapsed=2
    elif cap=='checkpoints':r.revision=9
    elif cap=='bytes':s.entities[s.question_id]['text']='x'*262144
    else:
        for n in range(2000):s._entity(str(n),'question','unverified',{'contract':'synthetic'},text='Unknown')
        r.entities={str(n):s.entities[str(n)] for n in range(256)}
    prepared,reason=r.prepare({'sequence':0,'hash':'c'*64},final=True)
    if prepared:
        r.commit(prepared)
        assert len(r.entities)<=256 and len(r.links)<=512
        assert r.coverage['known_unprocessed']>0
    assert reason


def test_append_failure_never_commits_organization(tmp_path,monkeypatch):
    original=Transcript.append
    def append(self,kind,data,terminal=False):
        if kind=='organization_checkpoint':raise OSError('synthetic append failure')
        return original(self,kind,data,terminal)
    monkeypatch.setattr(Transcript,'append',append)
    result,client,_,_=execute(tmp_path)
    assert result['validated_batches']==6 and len(client.calls)==9
    assert result['organization']['revision']==0
    assert 'organization_failed' in result['organization']['stops']
    assert o.reconstruct(tmp_path/'runs',result['investigation_id'])['incomplete']


def test_cancelled_revision_not_committed():
    s=source();r=o._Reducer(s)
    def cancel():raise KeyboardInterrupt()
    r.clock=cancel
    with pytest.raises(KeyboardInterrupt):r.prepare({'sequence':0,'hash':'c'*64})
    assert r.revision==0


def test_terminal_control_escaping():
    assert '\x1b' not in o._text('heading\x1b[2J\nnext')
    assert '\\u001b' in o._text('heading\x1b[2J')
    assert o._text('Unicode \u754c')=='Unicode \u754c'


def test_historical_reconstruction_is_read_only_and_provider_free(tmp_path,monkeypatch):
    result,*_=execute(tmp_path);root=tmp_path/'runs';rid=result['investigation_id']
    manifest,events=load(root,rid)
    manifest.pop('organization_profile')
    events=[e for e in events if not e['kind'].startswith('organization_')]
    events[-1]['data'].pop('organization')
    rehash(root/rid,manifest,events)  # Disposable synthetic historical fixture only.
    import hashlib,sqlite3
    from forensic_assistant.ai.backend import ModelBackend
    def forbidden(*args,**kwargs):pytest.fail('Forbidden provider/database call')
    monkeypatch.setattr(ModelBackend,'complete',forbidden);monkeypatch.setattr(sqlite3,'connect',forbidden)
    paths=[root/rid/'manifest.json',root/rid/'events.jsonl']
    before=[hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]
    view=o.reconstruct(root,rid)
    assert view['mode']=='retrospective' and not view['incomplete']
    assert view==o.reconstruct(root,rid)
    assert before==[hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]
    # Rejected model output cannot become an accepted source by rehashing its journal.
    _,current=load(root,rid)
    delta=next(e['data'] for e in current if e['kind']=='validated_delta')
    delta['findings']['observed'][0]['reported_value']='forged'
    rehash(root/rid,manifest,current)
    with pytest.raises(ValueError):o.reconstruct(root,rid)


def test_cumulative_time_and_revision_reservation():
    s=source();r=o._Reducer(s,clock=lambda:0)
    prepared,_=r.prepare({'sequence':0,'hash':'c'*64});r.commit(prepared)
    r.elapsed=2
    s._entity('new','question','unverified',{'contract':'synthetic'},text='Unknown')
    prepared,reason=r.prepare({'sequence':1,'hash':'d'*64})
    assert reason=='time_limit' and prepared[1]['applied']==0
    r.commit(prepared)
    assert 'new' not in r.entities and r.coverage['known_unprocessed']==1


def test_bundle_endpoints_never_half_committed():
    s=source();s._entity('relationship','relationship','validated_recorded_comparison',
                       {'contract':'synthetic'},endpoints=['missing1','missing2'])
    r=o._Reducer(s,clock=lambda:0)
    prepared,reason=r.prepare({'sequence':0,'hash':'c'*64})
    r.commit(prepared)
    assert reason=='unavailable_endpoint' and 'relationship' not in r.entities


def test_unrelated_multisource_reference_adapter(monkeypatch):
    from test_synthesis_relationships import clause, factual
    from forensic_assistant.investigation_ai import synthesis as s1
    # Existing S1 fixture construction; no narrative entity extraction or new rule.
    a=clause('2026-01-01T00:00:00Z',source='workstation-a')
    b=clause('2026-01-01T00:00:03Z',number=1,source='workstation-b')
    accepted=factual(a,b)
    src=source();src.view=accepted['evidence_state']
    reducer=s1._Reducer();reducer.previous='accepted';reducer.batches=1
    monkeypatch.setattr(reducer,'finish',lambda:accepted)
    exposure={'synthetic':'validated fixture'}
    delta=dict(id='accepted',batch=1,disclosure_sha256=digest(exposure),
               evidence_state=src.view,counters={'ai_requests':1},
               findings={'hypotheses':[],'model_proposed_unknowns':[]})
    src.analysis(reducer,delta,exposure)
    organized=o._Reducer(src,clock=lambda:0)
    prepared,_=organized.prepare({'sequence':1,'hash':'d'*64});organized.commit(prepared)
    findings=[e for e in organized.entities.values() if e['kind']=='finding']
    assert len(findings)==2
    assert {tuple(e['dependencies'][0]['source_context']['source_ids']) for e in findings}=={('workstation-a',),('workstation-b',)}
    relationship,=[e for e in organized.entities.values() if e['kind']=='relationship']
    assert relationship['predicate']=='recorded_time_before'
    assert relationship['semantics']['physical_event_order']=='not established'
    assert relationship['semantics']['left']['clock_skew']=='unknown'
    assert relationship['semantics']['right']['source_ids']==['workstation-b']
    assert len(organized.coverage['unassigned_findings'])==2


def test_final_operation_reservation():
    src=source();reducer=o._Reducer(src,clock=lambda:0);reducer.operations=896
    prepared,reason=reducer.prepare({'sequence':1,'hash':'d'*64})
    assert reason=='operation_limit' and prepared[1]['applied']==0
    prepared,_=reducer.prepare({'sequence':1,'hash':'d'*64},final=True)
    assert prepared[1]['applied']==1


def test_primary_journal_reservation():
    class Journal:
        manifest=source().manifest
        size=100;count=1;chain='c'*64
        def append(self,*args,**kwargs):pytest.fail('Primary event reservation must prevent append')
    observer=o.Live(Journal())
    observer.update(lambda:None,remaining_analysis=6,remaining_synthesis=2)
    assert observer.reducer.revision==0
    assert observer.reducer.stops==['journal_reservation']

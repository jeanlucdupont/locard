"""Compact wire receipts never substitute for C1 source reconstruction."""
from copy import deepcopy
import json
import time

import pytest

from forensic_assistant.investigation_ai import explanation_live as x
from forensic_assistant.investigation_ai.transcript import digest, load
from test_explanation_live import synthetic, execute
from test_explanation_replay_status import live_fixture
from test_organization import rehash


def large():
    session,org,facts,make=synthetic()
    n=0
    while len(org.entities)<42:
        key=digest(['compact synthetic question',n]);n+=1
        org.entities[key]=dict(id=key,kind='question',role='analysis_proposal',
            text='Unverified synthetic question',introduced_by={'contract':'synthetic'},dependencies=[])
    receipt=make(final=False)
    receipt['changed']['links']=[digest(['link',n]) for n in range(60)]
    assert len(receipt['changed']['entities'])==42
    event=dict(sequence=receipt['event']['sequence']+1,previous=receipt['event']['hash'])
    return session,org,facts,receipt,event


def test_compact_measurement_and_exact_prefix(capsys):
    session,org,facts,receipt,event=large();src=x.Sources(session.manifest,org,facts)
    reports=[]
    for profile in (x.PROFILE,x.COMPACT_PROFILE):
        reducer=x.Reducer(receipt['run_id'],receipt['read_view'],profile)
        start=time.perf_counter();prepared,reason=reducer.prepare(receipt,src,event=event)
        elapsed=time.perf_counter()-start
        assert prepared
        state,cp=prepared;size=x.event_size(cp,event)
        replay=x.Reducer(receipt['run_id'],receipt['read_view'],profile)
        start=time.perf_counter();again,_=replay.prepare(receipt,src,event=event,replay=cp,clock=lambda:10000)
        replay_seconds=time.perf_counter()-start
        assert again==prepared and state['frontier']['receipt']==receipt
        if profile==x.COMPACT_PROFILE:
            assert 0<cp['applied']<=32 and size<=8192
            assert cp['receipt']['receipt_digest']==digest(receipt)
            assert 'changed' not in cp['receipt']
            assert elapsed<.100 and reducer.peak_owned<=4194304
            reducer.commit(prepared)
            assert reducer.state==state
        else:assert cp['applied']==0 and size>8192
        reports.append(dict(profile=profile,event_bytes=size,operations=cp['applied'],stop=reason,
            prepare_seconds=elapsed,replay_seconds=replay_seconds,peak_owned_heap=reducer.peak_owned,
            committed_revisions=int(size<=8192),journal_bytes=size if size<=8192 else 0,
            pending=len(state['pending']),omitted=len(state['omitted'])))
    breakdown=dict(receipt_bytes=x.d1._size(receipt),changed_bytes=x.d1._size(receipt['changed']),
        changed_entities_bytes=x.d1._size(receipt['changed']['entities']),changed_links_bytes=x.d1._size(receipt['changed']['links']),
        run_read_view_bytes=x.d1._size({k:receipt[k] for k in ('run_id','read_view')}),
        source_checkpoint_bytes=x.d1._size({k:receipt[k] for k in ('source_frontier','event','revision','digest')}),
        compact_receipt_bytes=x.d1._size(x.receipt_reference(receipt)))
    with capsys.disabled():print('COMPACT_MEASUREMENT '+json.dumps(dict(receipt=breakdown,results=reports)))


@pytest.fixture
def recorded(tmp_path):
    result,*_=execute(tmp_path);root=tmp_path/'runs';rid=result['investigation_id']
    manifest,events=load(root,rid)
    assert manifest['explanation_profile']==x.COMPACT_PROFILE
    assert all(e['data']['contract']==x.COMPACT_CHECKPOINT for e in events if e['kind']=='explanation_checkpoint')
    return root,rid,manifest,events


@pytest.mark.parametrize('field',['receipt_digest','event_hash','event_sequence','revision','run_id','read_view',
    'rules','profile','source_frontier','changed','candidate_digest','result_digest','previous_digest','contract','missing','wire_profile','c1_candidates','boolean_revision'])
def test_authenticated_compact_tampering(recorded,field):
    root,rid,manifest,events=recorded
    event=next(e for e in events if e['kind']=='explanation_checkpoint');cp=event['data'];r=cp['receipt']
    if field=='event_hash':r['event']['hash']='0'*64
    elif field=='event_sequence':r['event']['sequence']-=1
    elif field=='revision':r['revision']-=1
    elif field=='boolean_revision':r['revision']=True
    elif field=='read_view':r['read_view']['view_id']='0'*32
    elif field=='source_frontier':r['source_frontier']['hash']='0'*64
    elif field=='changed':r['changed']={'entities':[],'links':[]}
    elif field=='missing':events.remove(next(e for e in events if e['kind']=='organization_checkpoint'))
    elif field=='wire_profile':cp['profile']='unknown'
    elif field=='c1_candidates':next(e for e in events if e['kind']=='organization_checkpoint')['data']['candidate_digest']='0'*64
    elif field in ('candidate_digest','result_digest','previous_digest','contract'):cp[field]='0'*64
    else:r[field]='unsupported'
    rehash(root/rid,manifest,events)
    with pytest.raises((ValueError,KeyError)):x.reconstruct(root,rid)


def test_reconstructed_receipt_and_partial_state(recorded,monkeypatch):
    root,rid,manifest,events=recorded
    seen=[];original=x.Replay.source
    def source(self,receipt,org,facts):
        seen.append(deepcopy(receipt));return original(self,receipt,org,facts)
    monkeypatch.setattr(x.Replay,'source',source)
    result=x.reconstruct(root,rid)
    receipts={r['event']['sequence']:r for r in seen}
    for event in events:
        if event['kind']!='explanation_checkpoint':continue
        ref=event['data']['receipt'];receipt=receipts[ref['event']['sequence']]
        assert ref==x.receipt_reference(receipt) and ref['receipt_digest']==digest(receipt)
    assert result['state']['frontier']['receipt']==seen[-1]
    assert result['clauses'] and result['state']['visits']<=2048
    groups=[k for k,e in result['entities'].items() if e.get('role')=='b2_group']
    assert groups
    for key in groups:
        statement=result['statements'][key]
        assert statement['classification']=='unverified_explanation'
        assert 'Model proposal is unverified; citations do not establish entailment or corroboration.' in statement['qualifications']


def test_zero_operation_compact_and_unknown_rules():
    session,org,facts,r,event=large();src=x.Sources(session.manifest,org,facts)
    reducer=x.Reducer(r['run_id'],r['read_view'],x.COMPACT_PROFILE)
    prepared,_=reducer.prepare(r,src,event=event,deadline=0)
    assert prepared[1]['operations']==[] and x.event_size(prepared[1],event)<8192
    replay=x.Reducer(r['run_id'],r['read_view'],x.COMPACT_PROFILE)
    assert replay.prepare(r,src,event=event,replay=prepared[1])[0]==prepared
    for field in ('rules','profile','contract'):
        bad=deepcopy(r);bad[field]='unknown'
        with pytest.raises(ValueError):x.receipt_reference(bad)
    with pytest.raises(ValueError):x.Reducer(r['run_id'],r['read_view'],'unknown')


@pytest.mark.parametrize('resource',['local','global','slots','time','heap'])
def test_compact_admission_preserves_limits(resource,monkeypatch):
    live,receipt=live_fixture()
    live.reducer=x.Reducer(receipt['run_id'],receipt['read_view'],x.COMPACT_PROFILE)
    if resource=='local':live.journal_bytes=65536
    elif resource=='global':live.transcript.size=x.MAX_BYTES
    elif resource=='slots':
        live.transcript.count=255;receipt['event']['sequence']=254
    elif resource=='heap':monkeypatch.setattr(x,'owned_bytes',lambda _:4194305)
    live.update(receipt,deadline=0 if resource=='time' else float('inf'))
    assert live.reducer.state['revision']==0 and not live.transcript.events


def test_compact_exact_event_ceiling_and_atomic_operation(monkeypatch):
    session,org,facts,r,event=large();src=x.Sources(session.manifest,org,facts)
    calls=[];original=x.event_size
    def measure(cp,event):
        size=original(cp,event);calls.append((deepcopy(cp),size));return size
    monkeypatch.setattr(x,'event_size',measure)
    prepared,_=x.Reducer(r['run_id'],r['read_view'],x.COMPACT_PROFILE).prepare(r,src,event=event,clock=lambda:0)
    cp=prepared[1]
    assert original(cp,event)<=8192 and cp['stop']=='event_byte_limit'
    assert calls[-1][1]>8192 and calls[-1][0]['operations'][:-1]==cp['operations']
    assert cp['applied']==len(cp['operations'])


@pytest.mark.parametrize('failure',['append','fatal_append','commit'])
def test_compact_publication_uncertainty(failure,monkeypatch):
    from forensic_assistant.investigation_ai.transcript import JournalPublicationError
    live,receipt=live_fixture()
    live.reducer=x.Reducer(receipt['run_id'],receipt['read_view'],x.COMPACT_PROFILE)
    calls=[]
    def fail(*args,**kw):
        calls.append(1)
        if failure=='fatal_append':raise JournalPublicationError('synthetic')
        raise OSError('synthetic')
    monkeypatch.setattr(live.reducer if failure=='commit' else live.transcript,
        'commit' if failure=='commit' else 'append',fail)
    with pytest.raises(JournalPublicationError):live.update(receipt,deadline=float('inf'))
    assert calls==[1] and live.reducer.state['revision']==0
    assert live.diagnostics['attempts'][-1]['outcome']=='publication_uncertain'


def test_compact_lifetime_and_final_reservations():
    session,org,facts,r,event=large();src=x.Sources(session.manifest,org,facts)
    def reducer():return x.Reducer(r['run_id'],r['read_view'],x.COMPACT_PROFILE)
    one=reducer();one.state['revision']=9
    assert one.prepare(r,src,event=event)[1]=='checkpoint_limit'
    one=reducer();one.state['admitted']=[digest(n) for n in range(192)]
    assert one.prepare(r,src,event=event)[1]=='admission_limit'
    one=reducer();one.state['operations']=256
    assert one.prepare(r,src,event=event)[1]=='operation_limit'
    one=reducer()
    prepared,reason=one.prepare(r,src,event=event,charged_visits=1920)
    assert reason=='dependency_limit' and not prepared[1]['operations']
    final={**r,'final':True}
    prepared,_=one.prepare(final,src,event=event,charged_visits=1920)
    assert prepared[1]['operations'] and prepared[0]['visits']<=2048


def test_same_final_canonical_statements_under_both_profiles():
    session,org,facts,r,event=large();src=x.Sources(session.manifest,org,facts)
    results=[]
    for profile in (x.PROFILE,x.COMPACT_PROFILE):
        reducer=x.Reducer(r['run_id'],r['read_view'],profile)
        for revision in range(1,10):
            # Later confirmed C1 transitions need not repeat changed keys.
            receipt=deepcopy(r);receipt['revision']=revision;receipt['final']=revision==9
            if revision>1:receipt['changed']={'entities':[],'links':[]}
            reducer.observe(receipt)
            prepared,_=reducer.prepare(receipt,src,event=event,clock=lambda:0)
            if x.event_size(prepared[1],event)<=8192:reducer.commit(prepared)
        assert not reducer.state['pending'] and not reducer.state['omitted']
        results.append({k:src.statement(k,v['section'])[1] for k,v in reducer.state['items'].items()})
    assert results[0]==results[1]

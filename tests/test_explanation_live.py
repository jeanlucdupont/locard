from copy import deepcopy
import pytest
from forensic_assistant.investigation_ai import explanation_live as x, autonomous as a
from forensic_assistant.investigation_ai.transcript import load,Transcript,digest,JournalPublicationError
from test_synthesis_consumer import setup
from test_organization import rehash


def execute(tmp_path,enabled=True):
    config,worker,client,seen,closed=setup(tmp_path)
    config['_live_explanation']=enabled
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    return result,client,seen,closed


def test_live_reference_replay(tmp_path):
    result,client,seen,closed=execute(tmp_path)
    root=tmp_path/'runs';rid=result['investigation_id']
    out=x.reconstruct(root,rid)
    organization=x.c1.reconstruct(root,rid)
    assert 'explanation' not in organization and x.d1._size(organization)<=262144
    assert out==x.reconstruct(root,rid)
    assert out['state']['revision']>1 and not out['incomplete']
    assert result['explanation']['digest']==digest(out['state'])
    assert len(client.calls)==9 and len([s for s in seen if s[0]=='show_evidence'])==6 and closed
    assert result['state']['steps']==10
    manifest,events=load(root,rid)
    cps=[e for e in events if e['kind']=='explanation_checkpoint']
    assert len(cps)==out['state']['revision']
    assert all(len(x.d1.encoded(e).encode())+1<=8192 for e in cps)
    assert all('reported_value' not in x.d1.encoded(e['data']) for e in cps)
    assert out['state']['operations']<=288 and out['state']['visits']<=2048
    assert len(out['state']['admitted'])<=192
    assert result['explanation']['elapsed_seconds']<=1


@pytest.mark.parametrize('change',['candidate','predecessor','result','receipt','operation','profile'])
def test_checkpoint_tampering_rejected(tmp_path,change):
    result,*_=execute(tmp_path);root=tmp_path/'runs';rid=result['investigation_id']
    manifest,events=load(root,rid)
    cp=next(e['data'] for e in events if e['kind']=='explanation_checkpoint')
    if change=='candidate':cp['candidate_digest']='a'*64
    if change=='predecessor':cp['previous_digest']='a'*64
    if change=='result':cp['result_digest']='a'*64
    if change=='receipt':cp['receipt']['read_view']['view_id']='c'*32
    if change=='operation':cp['operations'][0]['new']['id']='b'*64
    if change=='profile':manifest['explanation_profile']='unsupported'
    rehash(root/rid,manifest,events)
    with pytest.raises(ValueError):x.reconstruct(root,rid)


def test_duplicate_receipt_noop(tmp_path,monkeypatch):
    original=x.Live.update
    def twice(self,receipt,**kw):
        original(self,receipt,**kw)
        if receipt is not None and self.last_receipt==receipt:
            before=deepcopy(self.reducer.state);count=self.transcript.count
            original(self,deepcopy(receipt),**kw)
            assert self.reducer.state==before and self.transcript.count==count
    monkeypatch.setattr(x.Live,'update',twice)
    test_live_reference_replay(tmp_path)


def test_publication_uncertainty_preserves_prior_checkpoint(tmp_path,monkeypatch):
    from forensic_assistant.investigation_ai.transcript import JournalPublicationError
    original=Transcript.append;committed=[]
    def append(self,kind,data,terminal=False):
        if kind=='explanation_checkpoint' and committed:raise OSError('prepublication fault')
        result=original(self,kind,data,terminal)
        if kind=='explanation_checkpoint':committed.append(deepcopy(data))
        return result
    monkeypatch.setattr(Transcript,'append',append)
    with pytest.raises(JournalPublicationError):execute(tmp_path)
    assert len(committed)==1
    folder=next((tmp_path/'runs').iterdir());out=x.reconstruct(folder.parent,folder.name)
    assert out['state']['revision']==1 and out['incomplete']
    assert digest(out['state'])==committed[0]['result_digest']


def test_disabled_is_retrospective(tmp_path):
    result,*_=execute(tmp_path,False)
    assert 'explanation' not in result
    assert x.reconstruct(tmp_path/'runs',result['investigation_id'])==dict(mode='retrospective',enabled=False,persisted_checkpoints=0)


def synthetic():
    from types import SimpleNamespace
    from test_explanation import synthetic_session
    session=synthetic_session()
    org=SimpleNamespace(entities=session.entities,coverage=session.organization['coverage'],
        sources=SimpleNamespace(view=session.binding['read_view']))
    org.state=lambda:dict(entities=org.entities,coverage=org.coverage)
    facts=SimpleNamespace(clauses=session.clauses)
    def receipt(revision=1,changed=None,final=True):
        return dict(contract='organization-commit-v1',profile=x.c1.PROFILE,rules=x.c1.RULES,
            run_id=session.binding['run_id'],read_view=session.binding['read_view'],revision=revision,
            previous_digest='0'*64,digest=digest(org.state()),source_frontier={'sequence':revision,'hash':'b'*64},
            event={'sequence':revision+1,'hash':'c'*64},
            changed={'entities':sorted(org.entities if changed is None else changed),'links':[]},final=final)
    return session,org,facts,receipt


def test_exact_prefix_and_replay_clock_independence():
    session,org,facts,receipt=synthetic();src=x.Sources(session.manifest,org,facts)
    reducer=x.Reducer(session.binding['run_id'],session.binding['read_view'])
    ticks=iter([0,.001,.002,.003,.004,.005,.006,.007,.2]+[.2]*100)
    prepared,_=reducer.prepare(receipt(),src,clock=lambda:next(ticks))
    assert prepared and prepared[1]['stop']=='time_limit'
    replay=x.Reducer(session.binding['run_id'],session.binding['read_view'])
    restored,_=replay.prepare(receipt(),src,clock=lambda:10000,replay=prepared[1])
    assert restored==prepared


def test_membership_replace_and_objective_association():
    session,org,facts,receipt=synthetic();reducer=x.Reducer(session.binding['run_id'],session.binding['read_view'])
    prepared,_=reducer.prepare(receipt(),x.Sources(session.manifest,org,facts),clock=lambda:0);reducer.commit(prepared)
    rid=next(k for k,v in org.entities.items() if v['kind']=='relationship')
    initial=reducer.state['items'][rid]['id']
    org.entities[rid]['current_final']=False;org.entities[rid]['membership']='historical_only'
    prepared,_=reducer.prepare(receipt(2,[rid]),x.Sources(session.manifest,org,facts),clock=lambda:0)
    op=next(o for o in prepared[1]['operations'] if o['key']==rid)
    assert op['kind']=='retire_current_membership' and op['old']['id']==initial and op['new']['section']=='historical'
    reducer.commit(prepared)
    org.entities[rid]['current_final']=True;org.entities[rid]['membership']='current_final'
    prepared,_=reducer.prepare(receipt(3,[rid]),x.Sources(session.manifest,org,facts),clock=lambda:0);reducer.commit(prepared)
    assert reducer.state['items'][rid]['id']==initial
    original=next(v for v in org.entities.values() if v.get('role')=='original_question')
    cid=next(iter(facts.clauses));before=reducer.state['items'][cid]['id']
    original['original_assessment']={'status':'NOT_ASSESSABLE','propositions':[{'direct_clauses':[cid]}]}
    prepared,_=reducer.prepare(receipt(4,[original['id']]),x.Sources(session.manifest,org,facts),clock=lambda:0)
    assert prepared[0]['items'][cid]['id']!=before
    assert any(o['kind']=='replace' and o['key']==cid for o in prepared[1]['operations'])


@pytest.mark.parametrize('change',['value','qualifier','view','lineage'])
def test_original_support_cannot_be_changed(change):
    session,org,facts,receipt=synthetic();cid=next(iter(facts.clauses))
    facts.clauses=deepcopy(facts.clauses)
    c=facts.clauses[cid]
    if change=='value':c['arguments']['value']='invented'
    if change=='qualifier':c['qualifications']=[]
    if change=='view':c['evidence_state']['view_id']='f'*32
    if change=='lineage':c['lineage']=[]
    with pytest.raises(ValueError):x.Sources(session.manifest,org,facts).statement(cid,'observations')


def test_pending_dependencies_and_unchanged_components():
    session,org,facts,receipt=synthetic();cid=next(iter(facts.clauses));clause=facts.clauses.pop(cid)
    reducer=x.Reducer(session.binding['run_id'],session.binding['read_view'])
    prepared,_=reducer.prepare(receipt(),x.Sources(session.manifest,org,facts),clock=lambda:0);reducer.commit(prepared)
    assert cid in reducer.state['pending']
    facts.clauses[cid]=clause
    prepared,_=reducer.prepare(receipt(2,[cid]),x.Sources(session.manifest,org,facts),clock=lambda:0);reducer.commit(prepared)
    assert cid in reducer.state['items']
    src=x.Sources(session.manifest,org,facts);calls=[];original=src.statement
    def statement(k,s):calls.append(k);return original(k,s)
    src.statement=statement
    reducer.prepare(receipt(3,[]),src,clock=lambda:0)
    assert set(calls)<= {'coverage','original_assessment'}


@pytest.mark.parametrize('limit,value,reason',[('heap',1,'memory_limit'),('state_bytes',1,'memory_limit'),
    ('checkpoints',0,'checkpoint_limit'),('visits',0,'dependency_limit'),('operations',0,'operation_limit')])
def test_resource_stops(limit,value,reason,monkeypatch):
    session,org,facts,receipt=synthetic();monkeypatch.setitem(x.LIMITS,limit,value)
    reducer=x.Reducer(session.binding['run_id'],session.binding['read_view'])
    prepared,stop=reducer.prepare(receipt(),x.Sources(session.manifest,org,facts),clock=lambda:0)
    assert stop==reason
    assert reducer.state['revision']==0
    if prepared:assert not prepared[1]['operations']


def test_persisted_display_canonical_and_provider_free(tmp_path,monkeypatch):
    import sqlite3,hashlib,subprocess,sys
    from forensic_assistant.ai.backend import ModelBackend
    result,*_=execute(tmp_path);root=tmp_path/'runs';rid=result['investigation_id']
    paths=[root/rid/'manifest.json',root/rid/'events.jsonl'];before=[p.read_bytes() for p in paths]
    def forbidden(*a,**kw):pytest.fail('Forbidden provider or database access')
    monkeypatch.setattr(sqlite3,'connect',forbidden);monkeypatch.setattr(ModelBackend,'complete',forbidden)
    session,out=x.session(root,rid);cursor=None;pages=[]
    while True:
        page=x.page(session,out,cursor);pages.append(page)
        assert x.d1._size(page)<=16384 and len(x.render(page).encode())<=16384
        cursor=page['next_cursor']
        if not cursor:break
    assert pages[0]['mode']=='persisted'
    expanded=x.page(session,out,canonical=True)
    assert expanded['mode']=='persisted' and expanded['statements']
    assert x.d1._size(expanded)<=16384 and len(x.render(expanded).encode())<=16384
    historical=x.d1.open_history(root,rid)
    canonical={k:historical._statement(s,k) for s,k in historical.candidates}
    assert all(statement==canonical[k] for k,statement in out['statements'].items())
    code='import sys;from forensic_assistant.investigation_ai.explanation_live import reconstruct;from forensic_assistant.investigation_ai.transcript import digest;print(digest(reconstruct(sys.argv[1],sys.argv[2])))'
    a=subprocess.check_output([sys.executable,'-B','-c',code,str(root),rid])
    b=subprocess.check_output([sys.executable,'-B','-c',code,str(root),rid])
    assert a==b
    assert before==[p.read_bytes() for p in paths]


@pytest.mark.parametrize('failure',['prepare','c1_final','after_append'])
def test_partial_failures_preserve_confirmed_state(tmp_path,monkeypatch,failure):
    if failure=='prepare':
        monkeypatch.setattr(x.Sources,'statement',lambda *a,**kw:(_ for _ in ()).throw(ValueError('synthetic')))
    elif failure=='c1_final':
        original=x.c1.Live.update
        def update(self,source_update,**kw):
            if kw.get('final'):kw['deadline']=0
            return original(self,source_update,**kw)
        monkeypatch.setattr(x.c1.Live,'update',update)
    else:
        monkeypatch.setattr(x.Reducer,'commit',lambda *a,**kw:(_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        result,*_=execute(tmp_path);rid=result['investigation_id']
        assert result['validated_batches']==6
    except (KeyboardInterrupt, JournalPublicationError):
        assert failure=='after_append';rid=next((tmp_path/'runs').iterdir()).name
    out=x.reconstruct(tmp_path/'runs',rid)
    assert out['incomplete']
    if failure=='prepare':assert out['state']['revision']==0
    else:assert out['state']['revision']>0


def test_interpretation_premises_and_qualifications():
    from test_factual_clauses import batch
    from test_organization import source
    state,delta,exposure=batch();delta['counters']={'ai_requests':1}
    facts=x.s1._Reducer();facts.consume(state,delta,exposure)
    src=source();src.view=delta['evidence_state'];src.manifest['evidence_state']=src.view
    src.analysis(facts,delta,exposure)
    org=x.c1._Reducer(src,clock=lambda:0)
    prepared,_=org.prepare({'sequence':1,'hash':'b'*64});org.commit(prepared)
    adapter=x.Sources(src.manifest,org,facts)
    cid=next(k for k,v in adapter.clauses.items() if v['type']=='deterministic_interpretation')
    section,statement=adapter.statement(cid,'interpretations')
    assert statement['classification']=='deterministic_interpretation'
    assert statement['dependencies'][0]['premises_digest']==digest(adapter.clauses[cid]['supports'][0]['premises'])
    assert any('does not establish successful' in q for q in statement['qualifications'])
    adapter.clauses[cid]=deepcopy(adapter.clauses[cid])
    adapter.clauses[cid]['supports'][0]['premises'].clear()
    with pytest.raises(ValueError):adapter.statement(cid,'interpretations')


def test_large_stream_bound_and_explicit_omissions():
    session,org,facts,receipt=synthetic()
    for n in range(240):
        key=digest(['question',n]);org.entities[key]=dict(id=key,kind='question',role='analysis_proposal',
            text='Unverified question '+str(n),introduced_by={'contract':'synthetic'},dependencies=[])
    reducer=x.Reducer(session.binding['run_id'],session.binding['read_view'])
    prepared,_=reducer.prepare(receipt(),x.Sources(session.manifest,org,facts),clock=lambda:0)
    assert prepared
    state,cp=prepared
    assert state['omitted'] and state['coverage']['omitted']==len(state['omitted'])
    assert len(state['pending'])<=192 and len(cp['operations'])<=32
    assert x.d1._size(state)<=131072 and reducer.peak_owned<=4194304


def test_replay_rejects_unprofiled_checkpoints(tmp_path):
    result,*_=execute(tmp_path);root=tmp_path/'runs';rid=result['investigation_id']
    manifest,events=load(root,rid);del manifest['explanation_profile']
    rehash(root/rid,manifest,events)
    with pytest.raises(ValueError,match='Unprofiled'):x.reconstruct(root,rid)


@pytest.mark.parametrize('mutation',['run','view','changed','profile','predecessor'])
def test_live_forged_receipt_rejected(tmp_path,monkeypatch,mutation):
    original=x.Live.update
    def forged(self,receipt,**kw):
        if receipt is None:return
        altered=deepcopy(receipt)
        if mutation=='run':altered['run_id']='d'*32
        elif mutation=='view':altered['read_view']['view_id']='d'*32
        elif mutation=='changed':altered['changed']['entities']=[]
        elif mutation=='profile':altered['profile']='unknown'
        else:altered['previous_digest']='f'*64
        with pytest.raises(ValueError,match='receipt'):original(self,altered,**kw)
        return original(self,receipt,**kw)
    monkeypatch.setattr(x.Live,'update',forged)
    result,*_=execute(tmp_path)
    assert result['validated_batches']==6


def test_reference_admission_and_reserved_final_visits():
    session,org,facts,receipt=synthetic();src=x.Sources(session.manifest,org,facts)
    reducer=x.Reducer(session.binding['run_id'],session.binding['read_view'])
    reducer.state['admitted']=[digest(n) for n in range(192)]
    prepared,stop=reducer.prepare(receipt(),src,clock=lambda:0)
    assert stop=='admission_limit' and not prepared[1]['operations']
    reducer=x.Reducer(session.binding['run_id'],session.binding['read_view'])
    prepared,stop=reducer.prepare(receipt(final=False),src,clock=lambda:0,charged_visits=1920)
    assert stop=='dependency_limit' and not prepared[1]['operations']
    prepared,stop=reducer.prepare(receipt(final=True),src,clock=lambda:0,charged_visits=1920)
    assert prepared[1]['operations'] and prepared[0]['visits']<=2048


@pytest.mark.parametrize('block',['bytes','slots','deadline'])
def test_live_reservations_prevent_append(tmp_path,monkeypatch,block):
    original=x.Live.update;checked=[]
    def blocked(self,receipt,**kw):
        if receipt is None:return
        if not checked:
            t=self.transcript;before=(t.size,t.count,deepcopy(self.reducer.state))
            if block=='bytes':t.size=x.MAX_BYTES-512*1024
            elif block=='slots':t.count=255
            else:kw['deadline']=0
            # Event identity must still refer to the actual confirmed journal.
            if block=='slots':
                receipt=deepcopy(receipt);receipt['event']['sequence']=254
                self.organizer.last_receipt=deepcopy(receipt)
            original(self,receipt,**kw)
            assert self.reducer.state==before[2]
            t.size,t.count=before[:2];checked.append(True)
            return
        return original(self,receipt,**kw)
    monkeypatch.setattr(x.Live,'update',blocked)
    result,*_=execute(tmp_path)
    assert checked and result['validated_batches']==6


def test_local_opt_in_requires_b2(tmp_path):
    from test_autonomous_stage_a import setup as stage_a
    config,worker,client,_,_=stage_a(tmp_path);config['_live_explanation']=True
    with pytest.raises(ValueError,match='S4-B2'):a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert not client.calls and not (tmp_path/'runs').exists()


def test_cli_opt_in_is_explicit():
    from forensic_assistant.cli import build_parser
    from forensic_assistant import briefing_cli
    args=build_parser().parse_args(['briefing','--show','--live-explanation'])
    with pytest.raises(ValueError,match='requires --synthesize'):briefing_cli.run(args)
    args=build_parser().parse_args(['briefing','--investigate','latest','--autonomous','--decompose','--synthesize','--live-explanation'])
    assert args.live_explanation

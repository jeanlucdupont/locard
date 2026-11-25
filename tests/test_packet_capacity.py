"""Context-capacity reproduction using synthetic records and scripted OpenAI."""
from copy import deepcopy
import json
import pytest
from forensic_assistant.investigation_ai import autonomous as a, context_inspection as c, follow_up as f
from forensic_assistant.investigation_ai.state import Budget,ContextBudget,State
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.ai.openai_schema import instruct
from test_investigation_progress import row,grant,discovery_grant,envelope,answer,Scripted


def sequence(tmp_path,*,runner=None,large=True,note_length=200,empty=False):
    path=tmp_path/'case.db';path.touch();calls=[];closed=[];retained={};rounds=[];target=[]
    seed=row('browser',1);seed['source_context']={'source_ids':['source-test']};seed['url_chain']=[]
    g=discovery_grant(grant(path,[seed]));g.update(contract=c.CAPACITY_CONTRACT if large else c.CONTRACT,
        tools=['show_evidence','follow_up','inspect_context'],context_inspection=deepcopy(c.LIMITS),families=['browser','evtx'])
    if large:g['limits']['prompt_bytes']=24576
    g['objective']='Explain the recorded sequence and its limitations. '+('Distinguish recorded actor, affected object, timestamps, provenance and uncertainty. '*5)
    view=dict(contract='sqlite-read-view-v1',view_id='a'*32,file_identity=dict(device=1,inode=1))
    class Worker:
        def __init__(self,config):pass
        def close(self):closed.append(True)
        def call(self,name,args=None,**kw):
            calls.append(name)
            if name in ('initial','check'):result=envelope([])
            elif name=='show_evidence':result=envelope([seed])
            elif name=='follow_up':
                n=10*calls.count(name);rows=[row('evtx',n+i) for i in range(3)]
                for r in rows:
                    r.pop('command_line',None);r['source_context']={'source_ids':['source-test'],'basis':'Unverified analyst metadata'}
                    r['timestamps'][0]['utc']=f'2026-09-30T12:0{calls.count(name)}:00Z'
                result=envelope(rows);result['tool']='follow_up';result['plan']=dict(f.record_window(g,args,retained),returned_ids=[r['id'] for r in rows],complete=False)
            else:
                r=deepcopy(retained[args['evidence_id']]);r['context_category']=args['category']
                actor=args['category']=='actor'
                r['original_event_data']=[dict(name='SubjectUserName' if actor else 'ObjectName',ordinal=10 if actor else 11,
                    value='SyntheticAccount' if actor else 'C:/synthetic/'+('nested/'*55)+'item.dat',truncated=False)]
                note=('Acquisition was partial; original source metadata is unverified. Retained fields cannot establish execution or causality. '*40)[:note_length]
                r['coverage_notes']=[note]
                result=envelope([r]);result.update(tool='inspect_context',truncated=True,
                    plan=dict(contract=c.CONTRACT,**args,selected_ordinals=[10 if actor else 11],retained_fields=12,omitted_fields=11,limitations=[note]))
                c.validate_result(g,args,result)
            retained.update((r['id'],r) for r in result['records'])
            return dict(result=result,evidence_state=view,database_changes=0,schema=5,fingerprint=None)
    def model(messages):
        body=json.loads(messages[1]['content']);p=body['UNTRUSTED FORENSIC EVIDENCE'];rounds.append(body)
        if len(rounds)<=2:
            eid,pointer=next((r['id'],i[1]) for r in p['records'] for i in r['observations'] if i[1]=='/timestamps/0/utc' and (len(rounds)==1 or r['id'].startswith('EVTX:')))
            return dict(action='tool',tool='follow_up',arguments=dict(evidence_id=eid,field=pointer,family='evtx'),reason='Inspect temporal context')
        if len(rounds)==3:target.append(next(r['id'] for r in p['records'] if r['id'].startswith('EVTX:')))
        if len(rounds) in (3,4):return dict(action='tool',tool='inspect_context',arguments=dict(evidence_id=target[0],category='actor' if len(rounds)==3 else 'object'),reason='Inspect distinct original context')
        ans=answer(p);ans['interpretations']=[];ans['hypotheses']=[]
        if empty:ans['observed']=[];ans['unknowns']=['Available evidence does not establish the requested conclusion.']
        else:
            eid,pointer=next((r['id'],i[1]) for r in p['records'] for i in r['observations'] if str(i[2]).startswith('C:/synthetic/'))
            ans['observed']=[dict(evidence_id=eid,field=pointer)]
        return dict(action='final',answer=ans)
    client=Scripted([model]*6);client.provider_name='openai';client.model_name='synthetic'
    result=(runner or a.run)(dict(case_path=str(path),_stage_a=g),g['objective'],tmp_path/'runs',client=client,worker_factory=Worker)
    assert closed and path.read_bytes()==b''
    return result,client,calls,rounds


@pytest.mark.parametrize('empty',[False,True])
def test_two_contexts_then_valid_analysis(tmp_path,empty):
    r,client,calls,rounds=sequence(tmp_path,empty=empty)
    assert r['validated_batches']==1,(r['termination'],r.get('failure_diagnostic'))
    assert calls==['initial','show_evidence','follow_up','follow_up','inspect_context','inspect_context','check']
    assert len(client.calls)==5 and r['follow_up']['context_completed']==2
    assert r['follow_up']['records_returned']==7
    assert bool(r['findings']['observed']) is not empty
    assert all(sum(len(m['content'].encode()) for m in instruct(call))<=24576 for call in client.calls)
    one=a.reconstruct(tmp_path/'runs',r['investigation_id'])
    assert one==a.reconstruct(tmp_path/'runs',r['investigation_id'])
    m,e=load(tmp_path/'runs',r['investigation_id'])
    last=next(v['data'] for v in reversed(e) if v['kind']=='exposure')
    assert last['progress_summary']['contract']=='context-progress-summary-v1'
    assert len(json.dumps(last['progress_summary']))<len(json.dumps(last['operation_ledger']))
    assert last['packet_capacity']['actual_bytes']==last['prompt_bytes']


def test_budget_not_globally_expanded(tmp_path):
    with pytest.raises(ValueError):Budget(prompt_bytes=24576)
    assert ContextBudget().prompt_bytes==24576
    from forensic_assistant.investigation_ai import autonomous_policy as policy
    path=tmp_path/'case.db';path.touch();g=discovery_grant(grant(path,[row('browser',1)]))
    g['limits']['prompt_bytes']=24576
    with pytest.raises(ValueError):policy.validate(g,path)


def test_legacy_packet_limit_still_fails_with_safe_diagnostics(tmp_path):
    r,client,calls,_=sequence(tmp_path,large=False)
    assert r['termination']=='PROMPT_BUDGET_EXHAUSTED'
    assert calls.count('inspect_context')==2 and len(client.calls)==4
    assert r['packet_capacity']['ceiling']==5600
    assert r['packet_capacity']['cause']=='overhead'
    assert r['packet_capacity']['required_bytes']<=5600
    a.reconstruct(tmp_path/'runs',r['investigation_id'])


def test_oversized_original_fails_without_silent_truncation():
    from forensic_assistant.investigation_ai.failure_diagnostics import PacketFailure
    s=State(ContextBudget());s.compact_final=True;s.finalization_requested=True
    record=row('evtx',99)
    for k in ('timestamps','timestamp_utc','provider','channel','event_id','original_event_data'):record.pop(k,None)
    record['command_line']='x'*30000
    s.ingest(envelope([record]));before=deepcopy(s.records)
    with pytest.raises(PacketFailure,match='PROMPT_BUDGET_EXHAUSTED'):
        a.packet(s,'Inspect original context',{},record['id'],True,search_context={'contextual':True},completed_context=[])
    assert s.records==before and s.packet_capacity['cause']=='mandatory_evidence'
    assert s.packet_capacity['required_bytes']>24576


def test_optional_history_removed_before_current_evidence():
    s=State(ContextBudget());s.compact_final=True;s.finalization_requested=True
    r=row('evtx',88);s.ingest(envelope([r]));before=deepcopy(s.records)
    messages,exposure,n=a.packet(s,'Inspect context',{'model_proposed_unknowns':['optional '*20000]},r['id'],True,
        search_context={'contextual':True,'completed':[],'unused_notes':'optional '*20000},completed_context=[])
    assert n<=24576 and s.records==before
    assert r['id'] in {v['id'] for v in exposure['records']}
    assert json.loads(messages[1]['content'])['incremental']['previous_unresolved_unverified']==[]


@pytest.mark.parametrize('part',['grant','summary','bytes','field'])
def test_replay_rejects_modified_authority_and_disclosure(tmp_path,part):
    r,*_=sequence(tmp_path);m,e=load(tmp_path/'runs',r['investigation_id']);m=deepcopy(m);e=deepcopy(e)
    exposure=next(v['data'] for v in reversed(e) if v['kind']=='exposure')
    if part=='grant':m['authorization']['contract']=c.CONTRACT
    elif part=='summary':exposure['progress_summary']['repeat']=True
    elif part=='bytes':exposure['prompt_bytes']=24577
    else:exposure['content']['records'][0]['observations'][0][2]='forged original'
    with pytest.raises(ValueError):a._replay(m,e,r['investigation_id'])


def test_new_grant_real_worker_readonly_and_history_service(tmp_path):
    from test_context_inspection import case
    from forensic_assistant.investigation_ai.runner import ForensicWorker
    path=tmp_path/'case.db';g=case(path);g['contract']=c.CAPACITY_CONTRACT;g['limits']['prompt_bytes']=24576
    before=path.read_bytes();w=ForensicWorker(dict(case_path=str(path),semantic_enabled=False,_transaction_view=True,_stage_a=g))
    try:
        initial=w.call('initial',question=g['objective'])
        eid=g['evidence_ids'][0];w.call('show_evidence',{'evidence_id':eid},known_ids=[eid])
        result=w.call('inspect_context',dict(evidence_id=eid,category='actor'),known_ids=[eid])
        assert result['evidence_state']==initial['evidence_state'] and result['database_changes']==0
    finally:w.close()
    assert w.process.poll() is not None and path.read_bytes()==before
    sub=tmp_path/'synthetic';sub.mkdir();r,*_=sequence(sub)
    from forensic_assistant.investigation_ai.recorded import open_history
    assert open_history(sub/'runs',r['investigation_id']).factual_state()

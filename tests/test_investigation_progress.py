"""Tool-only loop reproduction and provider-free progress acceptance."""
from copy import deepcopy
import json
import pytest
from forensic_assistant.investigation_ai import autonomous as a, follow_up as f, context_inspection as c, progress
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.ai.openai_schema import instruct
from test_post_retrieval_packet import row
from test_autonomous_stage_a import grant
from test_follow_up_discovery import discovery_grant
from test_compact_disclosure import envelope, answer
from test_v4_controller import Scripted


def sequence(tmp_path, *, runner=None, empty_answer=False, only_seed=False, empty_context=False):
    path=tmp_path/'case.db';path.touch();before=path.read_bytes()
    seeds=[row('browser',1)] if only_seed else [row('browser',1),row('browser',2)]
    for seed in seeds:
        seed['url_chain']=[];seed['source_context']={'source_ids':['source-test']}
    g=discovery_grant(grant(path,seeds));g.update(contract=c.CONTRACT,context_inspection=deepcopy(c.LIMITS),tools=['show_evidence','follow_up','inspect_context'],families=['browser','evtx'])
    calls=[];closed=[];retained={};rounds=[];target=[]
    view=dict(contract='sqlite-read-view-v1',view_id='a'*32,file_identity=dict(device=1,inode=1))
    class Worker:
        def __init__(self,config):pass
        def close(self):closed.append(True)
        def call(self,name,args=None,**kw):
            calls.append(name)
            if name in ('initial','check'):result=envelope([])
            elif name=='show_evidence':result=envelope([next(r for r in seeds if r['id']==args['evidence_id'])])
            elif name=='follow_up':
                n=10*calls.count('follow_up');rows=[row('evtx',n+i) for i in range(3)]
                for r in rows:
                    r['source_context']={'source_ids':['source-test']};r.pop('command_line',None)
                    r['timestamps'][0]['utc']=f'2026-09-30T12:0{calls.count("follow_up")}:00Z'
                result=envelope(rows);result['tool']='follow_up'
                result['plan']=dict(f.record_window(g,args,retained),returned_ids=[r['id'] for r in rows],complete=False)
            else:
                r=deepcopy(retained[args['evidence_id']]);r['context_category']=args['category']
                r['original_event_data']=[] if empty_context else [dict(name='SubjectUserName',ordinal=10,value='Taylor',truncated=False),dict(name='SubjectLogonId',ordinal=11,value='0x42',truncated=False)]
                result=envelope([r]);result['tool']='inspect_context';result['truncated']=True
                result['plan']=dict(contract=c.CONTRACT,**args,selected_ordinals=[e['ordinal'] for e in r['original_event_data']],retained_fields=12,omitted_fields=12-len(r['original_event_data']),limitations=['Other fields omitted'])
                c.validate_result(g,args,result)
            retained.update((r['id'],r) for r in result['records'])
            return dict(result=result,evidence_state=view,database_changes=0,schema=5,fingerprint=None)
    def model(messages):
        body=json.loads(messages[1]['content']);p=body['UNTRUSTED FORENSIC EVIDENCE'];rounds.append(body)
        if len(rounds)<=2:
            eid,pointer=next((r['id'],i[1]) for r in p['records'] for i in r['observations'] if i[1]=='/timestamps/0/utc' and (len(rounds)==1 or r['id'].startswith('EVTX:')))
            return dict(action='tool',tool='follow_up',arguments=dict(evidence_id=eid,field=pointer,family='evtx'),reason='Compare nearby original activity')
        if len(rounds)==3:
            target.append(next(r['id'] for r in p['records'] if r['id'].startswith('EVTX:')))
        if len(rounds) in (3,4):
            return dict(action='tool',tool='inspect_context',arguments=dict(evidence_id=target[0],category='actor'),reason='Inspect actor context')
        ans=answer(p);ans['interpretations']=[];ans['hypotheses']=[]
        if empty_answer or empty_context:
            ans['observed']=[];ans['unknowns']=['No supported observation resolves the question.']
        else:
            matches=[(r['id'],i[1]) for r in p['records'] for i in r['observations'] if i[2]=='Taylor']
            assert matches,'Context must be redisclosed, not cited from the operation ledger'
            ans['observed']=[dict(evidence_id=matches[0][0],field=matches[0][1])]
        assert body['controller']['final_only'] and not body['controller']['tools']
        return dict(action='final',answer=ans)
    client=Scripted([model]*6);client.provider_name='openai';client.model_name='synthetic'
    result=(runner or a.run)(dict(case_path=str(path),_stage_a=g),g['objective'],tmp_path/'runs',client=client,worker_factory=Worker)
    assert closed and path.read_bytes()==before
    return result,client,calls,rounds


def test_duplicate_continues_to_seed_and_grounded_analysis(tmp_path):
    result,client,calls,rounds=sequence(tmp_path)
    assert calls==['initial','show_evidence','follow_up','follow_up','inspect_context','show_evidence','check']
    assert len(client.calls)==5 and result['validated_batches']==1
    assert result['findings']['observed'][0]['reported_value']=='Taylor'
    stats=result['follow_up'];assert stats['context_completed']==1 and stats['redundant_context_proposals']==1
    assert stats['families_retrieved']==['browser','evtx'] and stats['families_in_findings']==['evtx']
    ledger=rounds[3]['incremental']['completed_context'];entry=ledger['rows'][0]
    assert entry[2:5]==[2,2,True] and ledger['repeat_available'] is False
    assert all(sum(len(m['content'].encode()) for m in instruct(call))<=5600 for call in client.calls)
    one=a.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert one==a.reconstruct(tmp_path/'runs',result['investigation_id']) and one['findings']==result['findings']
    from forensic_assistant.investigation_ai.presentation import render
    text=render(result)
    assert 'Artifact families retrieved: browser, evtx' in text
    assert 'Artifact families in accepted findings: evtx' in text
    assert 'redundant proposals rejected: 1' in text


@pytest.mark.parametrize('empty_context',[False,True])
def test_honest_no_findings_is_partial(tmp_path,empty_context):
    result,client,calls,rounds=sequence(tmp_path,empty_answer=True,empty_context=empty_context)
    assert not result['findings']['observed'] and result['answer_assessment']['status']=='PARTIAL'
    assert result['follow_up']['no_findings_reason'] and calls.count('inspect_context')==1
    a.reconstruct(tmp_path/'runs',result['investigation_id'])


def test_no_seed_no_retry_or_fabricated_finding(tmp_path):
    result,client,calls,rounds=sequence(tmp_path,only_seed=True)
    assert result['termination']=='CONTEXT_DUPLICATE' and len(client.calls)==4
    assert calls.count('inspect_context')==1 and result['validated_batches']==0
    assert result['follow_up']['no_findings_reason']
    a.reconstruct(tmp_path/'runs',result['investigation_id'])


@pytest.mark.parametrize('change',['ledger','duplicate','family','allocation'])
def test_replay_rejects_forged_progress(tmp_path,change):
    result,*_=sequence(tmp_path);m,e=load(tmp_path/'runs',result['investigation_id']);e=deepcopy(e)
    if change=='ledger':next(v for v in e if v['kind']=='exposure' and v['data']['operation_ledger']['rows'])['data']['operation_ledger']['rows'][0][3]=99
    if change=='duplicate':next(v for v in e if v['kind']=='redundant_context')['data']['next_seed']='EVTX:'+'e'*64+':Offset:99'
    if change=='family':next(v for v in e if v['kind']=='terminal')['data']['follow_up']['families_retrieved']=['browser']
    if change=='allocation':next(v for v in reversed(e) if v['kind']=='exposure')['data']['analysis_only']=False
    with pytest.raises(ValueError):f.validate_journal(m,e)


def test_ledger_reports_partial_disclosure_and_bounded_size():
    from forensic_assistant.investigation_ai import disclosure
    results=[]
    for n in range(6):
        r=row('evtx',n)
        r['original_event_data']=[dict(name='SubjectName',ordinal=i,value='untrusted'*20,truncated=False) for i in range(8)]
        results.append(dict(records=[r],plan={'category':'actor'},truncated=False))
    empty=disclosure.encode(dict(contract=disclosure.CONTRACT,records=[],relationships=[],detections=[]))
    value=progress.ledger(results,empty)
    assert all(r[2]==8 and r[3]==0 and r[6]==[] for r in value['rows'])
    assert len(disclosure.encoded(progress.ledger(results)).encode())<=2400
    assert 'untrusted' not in disclosure.encoded(value)


def test_ledger_cannot_ground_observations():
    from forensic_assistant.investigation_ai.state import State,Budget
    from forensic_assistant.investigation_ai import disclosure
    s=State(Budget());s.compact_final=True;s.finalization_requested=True
    r=row('evtx',77);s.ingest(envelope([r]))
    empty=disclosure.encode(dict(contract=disclosure.CONTRACT,records=[],relationships=[],detections=[]))
    s.disclose(empty)
    value=answer(empty);value['observed']=[dict(evidence_id=r['id'],field='/event_id')]
    with pytest.raises(ValueError):s.render(value)


def test_prior_findings_survive_duplicate_continuation(tmp_path):
    from test_context_inspection import case
    path=tmp_path/'case.db';g=case(path,count=3);target=[]
    def final(m):
        value=answer(json.loads(m[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']);value['interpretations']=[]
        return dict(action='final',answer=value)
    def inspect(m):
        if not target:target.append(json.loads(m[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']['records'][0]['id'])
        return dict(action='tool',tool='inspect_context',arguments=dict(evidence_id=target[0],category='actor'),reason='Inspect actor')
    client=Scripted([final,inspect,inspect,final]);client.provider_name='openai';client.model_name='synthetic'
    r=a.run(dict(case_path=str(path),_stage_a=g,_transaction_view=True,semantic_enabled=False),g['objective'],tmp_path/'runs',client=client)
    assert r['validated_batches']==2 and r['follow_up']['redundant_context_proposals']==1
    assert r['follow_up']['context_completed']==1 and r['metrics']['ai_requests']==4
    manifest,events=load(tmp_path/'runs',r['investigation_id'])
    first=next(e['data']['findings'] for e in events if e['kind']=='validated_delta')
    assert all(o in r['findings']['observed'] for o in first['observed'])
    assert a.reconstruct(tmp_path/'runs',r['investigation_id'])['findings']==r['findings']

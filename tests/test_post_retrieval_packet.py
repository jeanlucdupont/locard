"""Synthetic post-retrieval pressure; no case access or provider requests."""
from copy import deepcopy
import json
import pytest
from forensic_assistant.investigation_ai import autonomous as a, follow_up as f, disclosure
from forensic_assistant.investigation_ai.state import State, Budget
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.ai.openai_schema import instruct
from test_compact_disclosure import records, envelope, answer
from test_autonomous_stage_a import grant
from test_follow_up_discovery import discovery_grant
from test_v4_controller import Scripted


def row(family, n):
    r=deepcopy(records()[0 if family=='browser' else 1])
    r['id']=family.upper()+':'+f'{n:064x}'+(':'+f'download:{n}' if family=='browser' else f':Offset:{n}')
    r.pop('defender_asr',None);r.pop('interpretation_ids',None)
    r['source_context']={'source_ids':['source-test'],'basis':'analyst assertion',
        'assertions':[{'hostname':'neutral-lab','basis':'Unverified metadata '*25} for _ in range(8)]}
    r['timestamps']=[dict(utc=f'2026-09-30T12:0{i}:00Z',type='Recorded metadata time',slot=f'slot{i}',meaning='Recorded, not execution') for i in range(3)]
    if family=='browser':
        r['target_path']='C:/neutral/report.dat'
        r['url_chain']=[dict(chain_index=i,url='https://neutral.invalid/'+str(i)+'/'+'x'*200) for i in range(4)]
    else:
        r.update(event_id=7,command_line='neutral '*100,original_event_data=[dict(name='Message',ordinal=i,value='context '*100,truncated=False) for i in range(3)])
    return r


def chain(tmp_path, monkeypatch, failure=None):
    path=tmp_path/'case.db';path.touch();before=path.read_bytes()
    seeds=[row('browser',1),row('evtx',2)]
    batches=[[row('evtx',n) for n in range(10,13)],[row('browser',n) for n in range(20,23)]]
    g=discovery_grant(grant(path,seeds));retained={};calls=[];closed=[];rounds=[]
    view=dict(contract='sqlite-read-view-v1',view_id='a'*32,file_identity=dict(device=1,inode=1))
    class Worker:
        def __init__(self,config):pass
        def close(self):closed.append(True)
        def call(self,name,args=None,**kw):
            calls.append(name)
            if name in ('initial','check'):result=envelope([])
            elif name=='show_evidence':result=envelope([next(r for r in seeds if r['id']==args['evidence_id'])])
            else:
                rows=batches.pop(0);result=envelope(rows);result['tool']='follow_up'
                result['plan']={**f.record_window(g,args,retained),'returned_ids':[r['id'] for r in rows],'complete':False}
            retained.update((r['id'],r) for r in result['records'])
            return dict(result=result,evidence_state=view,database_changes=0,fingerprint=None,schema=5)
    def model(messages):
        packet=json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE'];rounds.append(deepcopy(packet))
        if len(rounds)<=2:
            for group in packet['records']:
                for item in group['observations']:
                    if item[1]=='/timestamps/0/utc':
                        return dict(action='tool',tool='follow_up',arguments=dict(evidence_id=group['id'],field=item[1],family='evtx' if len(rounds)==1 else 'browser'),reason='Compare nearby recorded activity')
            pytest.fail('Anchor timestamp unavailable')
        value=answer(packet);value['interpretations']=[]
        if len(rounds)==3:
            # Select an actually disclosed low-ranked original field, not a guess.
            group=next(r for r in packet['records'] if r['id'].startswith('BROWSER:'))
            value['observed']=[dict(evidence_id=group['id'],field=group['observations'][-1][1])]
        return dict(action='final',answer=value)
    if failure:
        original=a.packet
        def injected(*args,**kw):
            if calls.count('show_evidence')==2:raise failure
            return original(*args,**kw)
        monkeypatch.setattr(a,'packet',injected)
    client=Scripted([model]*6);client.provider_name='openai';client.model_name='synthetic'
    result=a.run(dict(case_path=str(path),_stage_a=g),g['objective'],tmp_path/'runs',client=client,worker_factory=Worker)
    assert closed and path.read_bytes()==before
    return result,client,calls,rounds


def test_two_followups_then_show_continues(tmp_path,monkeypatch):
    result,client,calls,rounds=chain(tmp_path,monkeypatch)
    assert calls==['initial','show_evidence','follow_up','follow_up','show_evidence','check']
    assert result['validated_batches']==2, (result['termination'],result.get('failure_diagnostic'))
    assert len(client.calls)==4 and result['follow_up']['records_returned']==8
    assert all(sum(len(m['content'].encode()) for m in instruct(call))<=5600 for call in client.calls)
    one=a.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert one==a.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert one['findings']==result['findings']


def prepared():
    s=State(Budget());s.compact_final=True;s.finalization_requested=True
    prior=row('browser',1);current=row('evtx',2)
    s.ingest(envelope([prior]));_,e,_=a.packet(s,'Compare activity',{},prior['id'],True);s.disclose(e)
    selected=next(g for g in e['records'] if g['id']==prior['id'])['observations'][-1][1]
    ans=answer(e);ans['observed']=[dict(evidence_id=prior['id'],field=selected)];ans['interpretations']=[]
    previous=s.render(ans);s.ingest(envelope([current]))
    return s,previous,current,prior,selected


def test_exact_prior_support_and_current_priority():
    s,previous,current,prior,pointer=prepared();before=deepcopy(s.records)
    messages,e,size=a.packet(s,'Compare activity',previous,current['id'],True)
    fields={(g['id'],item[1]) for g in e['records'] for item in g['observations']}
    assert current['id'] in {eid for eid,p in fields}
    assert (prior['id'],pointer) in fields
    assert size==sum(len(m['content'].encode()) for m in instruct(messages))<=5600
    assert s.records==before
    disclosure.validate(e,s)


def test_optional_context_removed_before_mandatory_evidence():
    s,previous,current,_,_=prepared()
    context={'completed':[{'returned_ids':['x'*160]*3,'family':'browser','complete':False}]*2,
             'optional_untrusted_text':'not evidence '*400}
    messages,e,size=a.packet(s,'Compare activity',previous,current['id'],True,search_context=context)
    assert current['id'] in {g['id'] for g in e['records']}
    assert size<=5600
    assert context['completed'][0]['returned_ids']==['x'*160]*3


def test_optional_prior_omission_does_not_authorize_its_citation():
    s,previous,current,prior,pointer=prepared()
    # A previously exposed exact value is too large to redisclose together with
    # the next required record. Original evidence is not shortened to fit.
    s.exposed[prior['id']]['target_path']='x'*3000
    s.records[prior['id']]['target_path']='x'*3000
    s.compact_allowed[prior['id']].add('/target_path')
    previous['observed']=[dict(evidence_ids=[prior['id']],field='/target_path',reported_value='x'*3000)]
    messages,e,size=a.packet(s,'Compare activity',previous,current['id'],True)
    body=json.loads(messages[1]['content'])
    assert body['controller']['prior_support_fields_omitted']==1
    assert current['id'] in {g['id'] for g in e['records']} and size<=5600
    s.disclose(e)
    bad=answer(e);bad['observed']=[dict(evidence_id=prior['id'],field='/target_path')]
    with pytest.raises(ValueError):s.render(bad)


def test_mandatory_evidence_cannot_fit_without_value_truncation():
    from forensic_assistant.investigation_ai.failure_diagnostics import PacketFailure
    s=State(Budget());s.compact_final=True;s.finalization_requested=True
    r=row('evtx',5)
    for key in ('timestamps','event_id','original_event_data','provider','channel'):r.pop(key,None)
    r['command_line']='sensitive-value '*1000
    s.ingest(envelope([r]));original=deepcopy(s.records)
    with pytest.raises(PacketFailure,match='PROMPT_BUDGET_EXHAUSTED'):
        a.packet(s,'Compare activity',{},r['id'],True)
    assert s.records==original and s.budget==Budget()


def test_missing_current_has_specific_code():
    from forensic_assistant.investigation_ai.failure_diagnostics import PacketFailure
    s,previous,current,_,_=prepared();s.records.pop(current['id'])
    with pytest.raises(PacketFailure,match='CURRENT_RECORD_NOT_DISCLOSED'):
        a.packet(s,'Compare activity',previous,current['id'],True)


@pytest.mark.parametrize('kind,expected',[
    ('budget','PROMPT_BUDGET_EXHAUSTED'),('current','CURRENT_RECORD_NOT_DISCLOSED'),
    ('validation','EVIDENCE_PACKET_VALIDATION_FAILED'),('internal','INTERNAL_FAILURE'),
    ('worker','WORKER_FAILURE'),('resource','RESOURCE_BUDGET_EXHAUSTED')])
def test_safe_failure_codes_partial_persistence_and_cleanup(tmp_path,monkeypatch,kind,expected):
    from forensic_assistant.investigation_ai.failure_diagnostics import PacketFailure,validate
    from forensic_assistant.investigation_ai.runner import WorkerError
    failure={'budget':PacketFailure('PROMPT_BUDGET_EXHAUSTED'),
             'current':PacketFailure('CURRENT_RECORD_NOT_DISCLOSED'),
             'validation':PacketFailure('EVIDENCE_PACKET_VALIDATION_FAILED'),
             'internal':ValueError('https://private.invalid/?token=DO-NOT-LOG'),
             'worker':WorkerError('DO-NOT-LOG'),
             'resource':ValueError('RESOURCE_BUDGET_EXHAUSTED')}[kind]
    result,client,calls,_=chain(tmp_path,monkeypatch,failure)
    assert result['termination']==expected and result['validated_batches']==1
    assert len(client.calls)==3 and calls[-1]=='check'
    diag=result['failure_diagnostic'];validate(diag)
    assert diag['phase']=='packet_preparation' and diag['operation']=='show_evidence'
    assert diag['retrieved_records']==8 and diag['prompt_byte_limit']==5600
    manifest,events=load(tmp_path/'runs',result['investigation_id'])
    stopped=next(e['data'] for e in events if e['kind']=='stopped')
    assert stopped['diagnostic']==diag and 'DO-NOT-LOG' not in json.dumps(stopped)
    assert a.reconstruct(tmp_path/'runs',result['investigation_id'])['findings']==result['findings']
    from forensic_assistant.investigation_ai.presentation import render
    assert expected in render(result) and 'DO-NOT-LOG' not in render(result)


def test_diagnostic_validation_rejects_unknown_text():
    from forensic_assistant.investigation_ai.failure_diagnostics import validate
    with pytest.raises(ValueError):validate({'code':'secret text'})


def test_allocation_receipt_is_bound_to_disclosed_counts():
    from forensic_assistant.investigation_ai.failure_diagnostics import validate_allocation
    s,previous,current,_,_=prepared()
    _,exposure,_=a.packet(s,'Compare activity',previous,current['id'],True)
    keys=('disclosed_records','compact_observations','compact_interpretations',
          'omitted_candidate_fields','omitted_candidate_records','omitted_candidate_interpretations',
          'prior_support_fields_omitted','optional_context_omitted')
    receipt={k:s.prompt_diagnostics[k] for k in keys}
    validate_allocation(receipt,exposure)
    receipt['compact_observations']+=1
    with pytest.raises(ValueError):validate_allocation(receipt,exposure)


def test_deterministic_allocation_and_unchanged_original_provenance():
    s,previous,current,_,_=prepared();other=deepcopy(s);before=deepcopy(s.records)
    first=a.packet(s,'Compare activity',previous,current['id'],True)
    second=a.packet(other,'Compare activity',previous,current['id'],True)
    assert first==second and s.records==before
    forged=deepcopy(first[1]);forged['records'][0]['observations'][0][2]='forged'
    with pytest.raises(ValueError):disclosure.validate(forged,s)

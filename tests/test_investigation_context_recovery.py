"""Bounded prompt selection and single duplicate correction, without provider calls."""
import copy
import json
from contextlib import closing
import pytest
from test_assessment_handoff import saved, approved, Worker
from test_v4_controller import Scripted, tool
from forensic_assistant import assessment_handoff as handoff
from forensic_assistant.assessment_store import AssessmentStore
from forensic_assistant.database.db import connect
from forensic_assistant.investigation_ai import controller, tools
from forensic_assistant.investigation_ai.state import State,Budget,fields
from forensic_assistant.investigation_ai.projection import compact,is_record_projection,merge
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.investigation_ai.runner import WorkerError


def sequence(saved):
    case,result=saved;p=approved(saved)
    evtx=next(e for e in result['records'] if e.startswith('EVTX'))
    browser=next(e for e in result['records'] if e.startswith('BROWSER'))
    return p,evtx,browser,[tool('show_evidence',{'evidence_id':evtx}),tool('show_evidence',{'evidence_id':browser}),tool('show_evidence',{'evidence_id':evtx})]


def test_two_successful_duplicate_then_grounded_partial(saved,tmp_path):
    case,_=saved;p,evtx,browser,actions=sequence(saved)
    def answer(messages):
        packet=json.loads(messages[1]['content']);records={r['id']:r for r in packet['UNTRUSTED FORENSIC EVIDENCE']['records']}
        assert evtx in records and browser in records
        field=next(path for path,_ in fields(records[evtx]) if path.startswith('/original_event_data/') and path.endswith('/value'))
        assert packet['controller']['last_result']['status']=='already completed'
        return {'action':'final','answer':{'observed':[{'evidence_id':evtx,'field':field},{'evidence_id':browser,'field':'/url'}],
            'relationships':[],'detections':[],'hypotheses':[],'unknowns':['Successful script execution remains unresolved.'],'answer_status':'partial'}}
    client=Scripted([*actions,answer]);approvals=[];workers=[]
    def make(config):w=Worker(config);workers.append(w);return w
    before=case.read_bytes()
    result=controller.run({'case_path':str(case),'_assessment_handoff':p},p['question'],tmp_path/'runs',
        client=client,approval=lambda *a:approvals.append(a) or True,worker_factory=make)
    assert result['termination']=='ANSWER_SUPPORTED' and result['answer_assessment']['status']=='PARTIAL'
    assert result['answer_origin']=='validated_model_proposal'
    assert len(approvals)==2 and workers[0].calls.count('show_evidence')==2
    assert result['state']['duplicate_recoveries']==1 and result['state']['answer_attempts']==1
    manifest,events=load(tmp_path/'runs',result['investigation_id'])
    assert manifest['tool_calls'][-1]['duplicate']['classification']=='completed'
    assert sum(e['kind']=='loop_rejected' for e in events)==1
    assert all(e['data']['diagnostics']['prompt_bytes']<=5600 for e in events if e['kind']=='exposure')
    assert case.read_bytes()==before


def test_second_duplicate_terminates_no_fabricated_answer(saved,tmp_path):
    case,_=saved;p,e,b,actions=sequence(saved);client=Scripted([*actions,actions[-1]])
    workers=[]
    def make(config):w=Worker(config);workers.append(w);return w
    result=controller.run({'case_path':str(case),'_assessment_handoff':p},p['question'],tmp_path/'runs',client=client,approval=lambda *a:True,worker_factory=make)
    assert result['termination']=='TOOL_LOOP' and len(client.calls)==4
    assert workers[0].calls.count('show_evidence')==2 and result['state']['duplicate_recoveries']==1
    assert result['answer_origin']=='deterministic_disclosed_observations_only'
    from forensic_assistant.investigation_ai.presentation import render
    assert 'No validated AI conclusion' in render(result)


@pytest.mark.parametrize('mode',['denied','failed'])
def test_denied_failed_never_retried(saved,tmp_path,mode):
    case,_=saved;p,e,b,actions=sequence(saved)
    class Broken(Worker):
        def call(self,name,*a,**kw):
            if name=='show_evidence':
                self.calls.append(name);raise WorkerError('Synthetic failure')
            return super().call(name,*a,**kw)
    workers=[]
    def make(config):w=(Broken if mode=='failed' else Worker)(config);workers.append(w);return w
    client=Scripted([actions[0],actions[0]])
    result=controller.run({'case_path':str(case),'_assessment_handoff':p},p['question'],tmp_path/'runs',client=client,approval=lambda *a:mode!='denied',worker_factory=make)
    assert len(client.calls)==1 and result['state']['duplicate_recoveries']==0
    assert workers[0].calls.count('show_evidence')==(0 if mode=='denied' else 1)
    assert result['termination']==('USER_REJECTED' if mode=='denied' else 'TOOL_FAILURE')


def test_current_detail_before_optional_history(saved):
    case,_=saved;p,e,b,actions=sequence(saved)
    p['historical']['editorial_summary']='historical '*500
    with closing(connect(case)) as db:
        initial=handoff.hydrate(db,p)
        first=tools.execute(db,'show_evidence',{'evidence_id':e},{'known_ids':[e]})
        second=tools.execute(db,'show_evidence',{'evidence_id':b},{'known_ids':[b]})
    state=State(Budget());state.handoff=p;state.scope=p['scope'];state.ingest(initial);state.ingest(first);state.ingest(second)
    messages,exposed,size=state.prompt(p['question'],state.applicable(False,[]),[])
    assert size<=5600
    records={r['id']:r for r in exposed['records']}
    assert e in records and b in records and 'original_event_data' in records[e] and 'url' in records[b]
    assert 'editorial_summary' not in json.loads(messages[1]['content'])['ASSESSMENT CONTEXT — NOT EVIDENCE']
    assert state.prompt_diagnostics['optional_context_bytes_omitted']>0
    for record in exposed['records']:assert is_record_projection(record,state.records[record['id']])
    state.disclose(exposed)
    assert all(value==dict(fields(state.records[e]))[path] for path,value in fields(state.exposed[e]))


def test_projection_preserves_offsets_flags_and_ledger():
    record={'id':'EVTX:'+'a'*64+':Offset:1','source_type':'evtx','truncated_fields':['upstream'],
            'original_event_data':[{'name':'Large','ordinal':0,'value':'x'*3000,'truncated':False},
                {'name':'Target Commandline','ordinal':4,'value':'synthetic.exe','truncated':False}]}
    projected=compact(record,420)
    assert projected['original_event_data'][0]=={}
    assert projected['original_event_data'][1]==record['original_event_data'][1]
    assert is_record_projection(projected,record)
    forged=copy.deepcopy(projected);forged['original_event_data'][1]['value']='invented'
    assert not is_record_projection(forged,record)
    forged=copy.deepcopy(projected);forged.pop('truncated_fields')
    assert not is_record_projection(forged,record)
    previous={'id':record['id'],'original_event_data':[record['original_event_data'][0]]}
    combined=merge(previous,projected)
    assert combined['original_event_data'][0]==record['original_event_data'][0]
    assert compact(record,1) is None


def test_coverage_statuses_are_distinct(saved):
    case,assessment=saved
    statuses=['match','no_match','unsupported','incomplete','failed','not_searched','unavailable']
    assessment['rows']=[{'artifact':'evtx' if s=='incomplete' else 'mft','status':s} for s in statuses]
    AssessmentStore(case).save_assessment(assessment)
    p=handoff.prepare(case,assessment['id'],'Inspect')
    assert p['incomplete_families']==['evtx']
    assert set(p['coverage_states'])==set(statuses)
    assert p['coverage_states']['no_match']==['mft'] and p['coverage_states']['unsupported']==['mft']
    assert 'Historical search coverage incomplete: evtx;' in ' '.join(p['limitations'])
    assert any('Historical routes unsupported: mft' in n for n in p['limitations'])


def test_insufficient_budget_fails_closed():
    state=State(Budget(prompt_bytes=1))
    with pytest.raises(ValueError,match='budget'):state.prompt('Question',['search_evidence'],[])
    assert not state.exposed


def test_projection_cannot_mix_page_identity_or_metadata():
    original={'id':'EVTX:'+'a'*64+':Offset:1','original_event_data':[{'ordinal':4,'name':'new','value':'new value'}]}
    forged=copy.deepcopy(original);forged['original_event_data'][0].pop('value')
    assert not is_record_projection(forged,original)
    old={'original_event_data':[{'ordinal':0,'name':'old','value':'old value','extra':'old'}]}
    merged=merge(old,original)
    assert merged['original_event_data'][0]==original['original_event_data'][0]


def test_projection_rejects_equal_but_different_json_types():
    assert not is_record_projection({'id':'x','event_id':True},{'id':'x','event_id':1})
    assert not is_record_projection({'id':'x','numbers':[True]},{'id':'x','numbers':[1]})
    assert not is_record_projection({'id':'x'},{'id':'x','source_context':None})

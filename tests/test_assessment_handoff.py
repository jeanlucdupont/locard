"""Synthetic assessment-to-investigation trust-boundary regressions; no live providers."""
import copy
import json
from contextlib import closing
import pytest
from forensic_assistant import assessment_handoff as h, assessment as a, assessment_cli
from forensic_assistant.assessment_store import AssessmentStore
from forensic_assistant.database.db import connect
from forensic_assistant.investigation_ai import controller, tools
from forensic_assistant.investigation_ai.state import State, Budget, encoded
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.retrieval.temporal_scope import validate_proposal
from test_assessment import accepted, arguments, factory
from test_evtx_content import add
from test_v4_controller import Scripted, tool
from test_briefing_cross_artifact import artifact

START='2026-09-30T00:00:00Z'
END='2026-09-30T23:59:59Z'


@pytest.fixture
def saved(tmp_path):
    case=tmp_path/'case.db'
    with closing(connect(case)) as db:
        add(db)
        for family,number in [('mft','Offset:1'),('prefetch','File'),('registry','KeyOffset:1'),('browser','download:1')]:
            artifact(db,family,number=number)
    accepted(case)
    with closing(connect(case)) as db:
        result=assessment_cli.run(arguments(case,'assess','--start',START,'--end',END,answers=['','y']),worker_factory=factory(db))
    return case,result


def approved(saved,question='What evidence supports execution?'):
    case,result=saved
    return h.authorize(h.prepare(case,result['id'],question),lambda _:True)


def test_selection_aliases_authorization_and_persistence(saved,tmp_path):
    case,result=saved;before=case.read_bytes()
    assert h.select(case)['id']==h.select(case,result['id'])['id']
    mapping=h.references(result)
    assert list(mapping.values())==sorted(result['records'])
    with pytest.raises(ValueError,match='Unknown'):h.prepare(case,result['id'],'Inspect E999')
    p=h.prepare(case,result['id'],'Inspect [E2]')
    assert p['hints'][0]['id']==mapping['E2']
    assert len({r['id'] for r in p['hints']})==len(p['hints'])
    assert h.authorize(p,lambda _:False) is None
    with pytest.raises(ValueError,match='authorization'):h.validate(p,case)
    p=h.authorize(p,lambda _:True);h.validate(p,case)
    p['scope']['end']=START
    with pytest.raises(ValueError,match='authorization'):h.validate(p,case)
    other=tmp_path/'other.db'
    with closing(connect(other)):pass
    with pytest.raises(ValueError):h.select(other)
    with pytest.raises(ValueError):h.validate(approved(saved),other)
    assert case.read_bytes()==before
    assert AssessmentStore(case).load(result['id'])==result


def test_changed_briefing_and_explicit_new_scope(saved):
    case,result=saved;accepted(case,('new.exe',))
    p=h.prepare(case,result['id'],'Compare E1',START,'2026-09-30T12:00:00Z')
    assert p['briefing_stale'] and p['briefing_revision']==result['plan']['revision']
    assert p['scope']['end'].startswith('2026-09-30T12:00:00')
    with pytest.raises(ValueError):validate_proposal(p['scope'],'timeline',{'start':START,'end':END})
    with pytest.raises(ValueError):h.prepare(case,result['id'],'Inspect',START,None)


def test_current_hydration_not_historical_fields(saved):
    case,result=saved;p=approved(saved)
    with closing(connect(case)) as db:
        before=db.total_changes
        data=h.hydrate(db,p)
        assert len(data['records'])==5
        assert all(set(r)<= {'id','kind','source_type'} for r in data['records'])
        assert all(o['status']=='timestamp_context_match_only' for o in data['plan']['assessment_revalidation'])
        assert db.total_changes==before
        eid=next(e for e in result['records'] if e.startswith('EVTX'))
        full=tools.execute(db,'show_evidence',{'evidence_id':eid},{'known_ids':[eid]})
        assert full['records'][0]['original_event_data'] and full['records'][0]['defender_asr']
        state=State(Budget());state.ingest(data);messages,exposure,size=state.prompt('Inspect',state.applicable(False,[]),[])
        state.disclose(exposure)
        answer={'observed':[{'evidence_id':eid,'field':'/original_event_data/0/value'}],'relationships':[], 'detections':[], 'hypotheses':[], 'unknowns':[]}
        with pytest.raises(ValueError):state.render(answer)
        db.execute("UPDATE evidence_timestamps SET meaning='changed' WHERE evidence_id=?",(eid,));db.commit()
        assert any(o['status']=='timestamp_context_changed' for o in h.hydrate(db,p)['plan']['assessment_revalidation'])
        missing=copy.deepcopy(p);missing['hints']=[{'ref':'E1','id':'EVTX:'+ 'f'*64+':Offset:0','projection_digest':'x'}]
        assert h.hydrate(db,missing)['plan']['assessment_revalidation'][0]['status']=='unavailable'
        p['scope']['end']='2026-09-30T01:00:00Z'
        assert all(o['status']=='outside_scope_or_undated' for o in h.hydrate(db,p)['plan']['assessment_revalidation'])


def test_handoff_prompt_bounded_and_saved_context_not_grounded(saved):
    case,result=saved;p=approved(saved)
    p['historical']['editorial_summary']='UNVERIFIED '*10000
    with closing(connect(case)) as db:data=h.hydrate(db,p)
    state=State(Budget());state.handoff=p;state.scope=p['scope'];state.ingest(data)
    messages,exposed,size=state.prompt(p['question'],state.applicable(False,[]),[])
    assert size<=5600 and len(encoded(messages).encode())<6200
    context=json.loads(messages[1]['content'])['ASSESSMENT CONTEXT — NOT EVIDENCE']
    assert context['omissions'] and 'editorial_summary' not in context
    assert context['references'] and 'Host links unverified' in context['coverage']
    state.disclose(exposed)
    assert all(set(r)<= {'id','kind','source_type'} for r in state.exposed.values())


class Worker:
    def __init__(self,config):
        self.config=config;self.db=connect(config['case_path']);self.calls=[]
    def call(self,name,args=None,**kwargs):
        self.calls.append(name)
        result=({'checked':True} if name=='check' else tools.initial(self.db,kwargs.get('question',''),self.config) if name=='initial' else
                tools.execute(self.db,name,args,{'known_ids':kwargs.get('known_ids',[])}))
        case=self.config['_assessment_handoff']['case']
        return dict(result=result,schema=5,database_changes=0,fingerprint=None,elapsed_seconds=0,
                    evidence_state={'contract':'sqlite-read-view-v1','view_id':'a'*32,'file_identity':{k:case[k] for k in ('device','inode')}})
    def close(self):self.db.close()


def test_controller_approvals_current_fields_transcript(saved,tmp_path):
    case,result=saved;p=approved(saved)
    eid=next(e for e in result['records'] if e.startswith('EVTX'))
    def final(messages):
        packet=json.loads(messages[1]['content']);records=packet['UNTRUSTED FORENSIC EVIDENCE']['records']
        record=next(r for r in records if r['id']==eid)
        assert 'original_event_data' in record
        return {'action':'final','answer':{'observed':[{'evidence_id':eid,'field':'/original_event_data/0/value'}],
            'relationships':[],'detections':[],'hypotheses':[],'unknowns':['Successful execution remains unresolved.'],
            'interpretations':record.get('interpretation_ids',[]),'answer_status':'partial'}}
    approvals=[];client=Scripted([tool('show_evidence',{'evidence_id':eid}),final])
    output=controller.run({'case_path':str(case),'_assessment_handoff':p},p['question'],tmp_path/'runs',client=client,
        approval=lambda proposal,seconds:approvals.append(proposal) or True,worker_factory=Worker)
    assert output['termination']=='ANSWER_SUPPORTED'
    assert len(approvals)==1 and output['state']['accepted_calls']==1
    manifest,events=load(tmp_path/'runs',output['investigation_id'])
    assert manifest['assessment_origin']['assessment_id']==result['id']
    assert manifest['temporal_scope']==p['scope'] and manifest['evidence_fingerprint'] is None
    assert max(output['metrics']['prompt_bytes'])<=5600
    assert output['findings']['observed'] and output['findings']['interpretations']
    initial=next(e['data']['result'] for e in events if e['kind']=='initial')
    assert all('original_event_data' not in r for r in initial['records'])
    denied=controller.run({'case_path':str(case),'_assessment_handoff':p},p['question'],tmp_path/'deny',
        client=Scripted([tool('show_evidence',{'evidence_id':eid})]),approval=lambda *a:False,worker_factory=Worker)
    assert denied['termination']=='USER_REJECTED' and denied['state']['accepted_calls']==0


def test_cli_decline_no_model_no_worker(saved,monkeypatch):
    from forensic_assistant import briefing_cli
    case,result=saved
    monkeypatch.setattr(h,'investigate',lambda *a,**k:pytest.fail('declined started investigation'))
    from forensic_assistant import assessment_handoff_cli
    value=assessment_handoff_cli.execute(case,result['id'],'Inspect E1',read=lambda _: 'n')
    assert 'cancelled' in value['message']
    assert 'cancelled' in briefing_cli.render(value)


def test_real_readonly_worker_and_scope_rejection(saved,tmp_path):
    case,result=saved;p=approved(saved)
    eid=next(e for e in result['records'] if e.startswith('EVTX'))
    before=case.read_bytes()
    invalid=tool('search_evidence',{'artifact':'evtx','start':'2026-09-29T00:00:00Z','end':END})
    approvals=[]
    output=controller.run({'case_path':str(case),'semantic_enabled':False,'_assessment_handoff':p},p['question'],tmp_path/'realruns',
        client=Scripted([invalid]*3),approval=lambda *args:approvals.append(args) or True)
    assert output['termination']=='TOO_MANY_REJECTIONS'
    assert not approvals and output['state']['accepted_calls']==0
    assert len(output['state']['retrieved_ids'])==5
    assert case.read_bytes()==before
    manifest,events=load(tmp_path/'realruns',output['investigation_id'])
    assert manifest['evidence_state']['file_identity']=={k:p['case'][k] for k in ('device','inode')}
    assert next(e for e in events if e['kind']=='initial')['data']['database_changes']==0


def test_historical_values_cannot_ground_final(saved,tmp_path):
    case,result=saved;p=approved(saved)
    eid=next(e for e in result['records'] if e.startswith('EVTX'))
    invalid={'action':'final','answer':{'observed':[{'evidence_id':eid,'field':'/original_event_data/0/value'}],
        'relationships':[],'detections':[],'hypotheses':[],'unknowns':[]}}
    out=controller.run({'case_path':str(case),'_assessment_handoff':p},p['question'],tmp_path/'noground',
        client=Scripted([invalid]*3),approval=lambda *a:True,worker_factory=Worker)
    assert out['termination']=='TOO_MANY_REJECTIONS' and not out['findings']['observed']
    assert out['state']['final_grounding_rejections']==3


def test_change_during_confirmation_and_bad_id(saved):
    case,result=saved;p=approved(saved)
    accepted(case,('different.exe',))
    with pytest.raises(ValueError,match='Briefing changed'):h.validate(p,case)
    bad=copy.deepcopy(result);bad['records']['A-not-an-evidence-id']={}
    with pytest.raises(ValueError,match='Invalid assessment evidence'):h.references(bad)
    with pytest.raises(ValueError):h.investigate(p,approval=None)


def test_prompt_worst_case_bound(saved):
    case,result=saved;p=approved(saved)
    p['question']='x'*1000
    p['hints']=[{'ref':f'E{i+1}','id':f'EVTX:{i:064x}:Offset:1'} for i in range(12)]
    state=State(Budget());state.handoff=p;state.scope=p['scope']
    state.handoff_revalidation=[{'ref':r['ref'],'status':'timestamp_context_match_only'} for r in p['hints']]
    messages,exposure,size=state.prompt(p['question'],state.applicable(False,[]),[])
    assert size<=5600 and not exposure['records']
    assert state.limits


def test_six_reference_detail_fits_and_coverage_is_explicit(saved):
    case,result=saved;p=approved(saved)
    p['incomplete_families']=['evtx']
    extra={'ref':'E6','id':'MFT:'+'e'*64+':Offset:6','projection_digest':'x'}
    p['hints'].append(extra)
    with closing(connect(case)) as db:
        data=h.hydrate(db,p)
        # Synthetic extra current identity represents a sixth, separately verified record.
        data['records'].append({'id':extra['id'],'source_type':'mft','kind':'mft_record'})
        data['returned_count']+=1
        eid=next(e for e in result['records'] if e.startswith('EVTX'))
        detail=tools.execute(db,'show_evidence',{'evidence_id':eid},{'known_ids':[eid]})
    state=State(Budget());state.handoff=p;state.scope=p['scope'];state.ingest(data)
    _,exposure,_=state.prompt(p['question'],state.applicable(False,[]),[]);state.disclose(exposure)
    assert len(state.exposed)==6
    state.ingest(detail)
    messages,exposure,size=state.prompt(p['question'],state.applicable(False,[]),[])
    assert size<=5600 and any('original_event_data' in r for r in exposure['records'])
    assert 'families: evtx' in messages[1]['content']

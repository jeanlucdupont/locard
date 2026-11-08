"""6.99 bounded multi-artifact investigation and deterministic narrative."""
import copy
import json
import pytest
from forensic_assistant.investigation_ai.state import State, Budget, fields
from forensic_assistant.investigation_ai import tools, controller
from forensic_assistant.investigation_ai.narrative import build
from forensic_assistant.investigation_ai.presentation import render
from forensic_assistant.investigation_ai.transcript import load
from test_assessment_handoff import saved, approved, Worker
from test_v4_controller import Scripted, tool


def envelope(records):
    return dict(records=records, relationships=[], detections=[], limitations=[], returned_count=len(records), truncated=False)


def test_detail_progress_not_identity_only_and_repeats_bounded():
    state=State(Budget()); eid='MFT:'+'a'*64+':Offset:1'
    state.ingest(envelope([dict(id=eid,source_type='mft',kind='file')]))
    record=dict(id=eid,source_type='mft',kind='file',filename='synthetic.zip')
    assert state.ingest(envelope([record]),operation='show_evidence')==0
    assert state.no_new==0 and state.progress['new_retained_fields']==1
    assert state.progress['newly_inspected_records']==1
    state.ingest(envelope([record]),operation='show_evidence')
    assert state.no_new==1 and state.progress['new_retained_fields']==0
    state.ingest(envelope([]),operation='search_evidence');state.ingest(envelope([record]))
    assert state.no_new==3
    state.disclose(envelope([record]))
    assert state.summary()['disclosed_field_count']>0
    assert state.summary()['inspected_artifact_families']==['mft']


def test_browser_chain_is_current_bounded_and_citable():
    raw=dict(id='BROWSER:'+'a'*64+':download:1',source_type='browser',artifact_type='browser_download',kind='download',
        detail=dict(url=None,referrer='https://referrer.invalid/',url_chain=[dict(chain_index=i,url='https://source.invalid/'+str(i)+'x'*240) for i in range(6)]),timestamps=[])
    record=tools.compact(raw)
    assert record['url'] is None and len(record['url_chain'])==4
    assert len(json.dumps(record['url_chain'], ensure_ascii=True).encode())<=1024
    assert record['url_chain'][0]['chain_index']==0
    assert len(record['url_chain'][0]['url'])==220 and 'url_chain' in record['truncated_fields']
    state=State(Budget());state.disclose(envelope([record]))
    answer=dict(observed=[dict(evidence_id=record['id'],field='/url_chain/0/url')],relationships=[],detections=[],hypotheses=[],unknowns=[])
    result=state.render(answer)
    assert result['observed'][0]['reported_value']==record['url_chain'][0]['url']
    assert result['observed'][0]['truncated_fields']
    answer['observed'][0]['field']='/url_chain/5/url'
    with pytest.raises(ValueError):state.render(answer)


def test_question_aware_candidates_and_four_family_approved_lookups(saved,tmp_path):
    case,assessment=saved;p=approved(saved)
    selected=[];sizes=[];approval=[]
    def choose(messages):
        packet=json.loads(messages[1]['content']); sizes.append(sum(len(m['content'].encode()) for m in messages))
        records=packet['UNTRUSTED FORENSIC EVIDENCE']['records']
        assert packet['controller']['objective']==p['question']
        options=packet['controller']['assessment_opportunities']
        assert 'question-relevant' in packet['controller']['assessment_instruction']
        # Fake model chooses relevant known families, not an automatic policy.
        row=next(r for i,r in enumerate(records) if options.get(str(i))=='uninspected' and r['source_type'] in ('evtx','browser','mft','prefetch'))
        selected.append(row['id'])
        return tool('show_evidence',{'evidence_id':row['id']})
    def final(messages):
        packet=json.loads(messages[1]['content'])
        assert not packet['controller'].get('final_only')
        records=packet['UNTRUSTED FORENSIC EVIDENCE']['records']
        refs=[]
        for row in records:
            available=[k for k,v in fields(row) if k not in ('/kind','/source_type','/artifact_type')]
            if available: refs.append(dict(evidence_id=row['id'],field=available[0]))
        return dict(action='final',answer=dict(observed=refs[:12],relationships=[],detections=[],hypotheses=[],unknowns=['Successful execution remains unresolved.'],answer_status='partial'))
    client=Scripted([choose]*4+[final]);before=case.read_bytes()
    result=controller.run({'case_path':str(case),'_assessment_handoff':p},p['question'],tmp_path/'runs',client=client,worker_factory=Worker,
                          approval=lambda *args:approval.append(args) or True)
    assert result['termination']=='ANSWER_SUPPORTED'
    assert len(approval)==4 and len(set(selected))==4
    assert set(result['state']['inspected_artifact_families'])=={'browser','evtx','mft','prefetch'}
    assert all(x['new_records']==0 and x['new_retained_fields']>0 for x in result['state']['investigation_path'][1:])
    assert max(result['metrics']['prompt_bytes'])<=5600
    assert case.read_bytes()==before
    _,events=load(tmp_path/'runs',result['investigation_id'])
    assert events[-1]['data']['narrative']['contract']=='grounded-narrative-v1'
    print('Multi-family prompt bytes:', result['metrics']['prompt_bytes'])


def test_denied_candidate_has_no_inspection_progress(saved,tmp_path):
    case,assessment=saved;p=approved(saved);eid=next(iter(assessment['records']))
    result=controller.run({'case_path':str(case),'_assessment_handoff':p},p['question'],tmp_path/'runs',
        client=Scripted([tool('show_evidence',{'evidence_id':eid})]),worker_factory=Worker,approval=lambda *args:False)
    assert result['termination']=='USER_REJECTED'
    assert result['state']['inspected_ids']==[]
    assert result['narrative']['records']==[]


def test_narrative_only_uses_accepted_values_and_preserves_detail():
    eid='BROWSER:'+'a'*64+':download:1'
    rows=[dict(evidence_ids=[eid],field=f,reported_value='synthetic.zip',qualifier='Reported field',truncated_fields=[]) for f in ('/target_path','/current_path')]
    findings=dict(observed=rows,interpretations=[],model_proposed_unknowns=['Whether the archive was opened remains unresolved.'])
    narrative=build(findings,{})
    assert len(narrative['records'][0]['sentences'])==1
    assert narrative['records'][0]['sentences'][0]['observations']==[0,1]
    result=dict(termination='ANSWER_SUPPORTED',question='Did it execute?',findings=findings,narrative=narrative,state={},answer_assessment={'status':'PARTIAL'})
    concise=render(result);detail=render(result,details=True)
    assert concise.count('synthetic.zip')==1 and detail.count('synthetic.zip')==2
    assert eid not in concise and eid in detail
    assert 'does not establish opening or execution' in concise
    assert 'What remains unresolved' in concise
    result['narrative']['records'][0]['sentences'][0]['text']='Unsupported script execution succeeded.'
    assert 'Unsupported script execution succeeded' not in render(result)
    for family,caution in [('MFT','not process execution'),('PREFETCH','not proof that those files executed')]:
        rows[0]['evidence_ids']=[family+':'+ 'b'*64+':Offset:1']
        assert caution in json.dumps(build(findings,{}))

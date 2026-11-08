"""Compact-disclosure trust boundary: synthetic records, fake providers only."""
import copy
import json
import pytest
from forensic_assistant.investigation_ai.state import State,Budget
from forensic_assistant.investigation_ai import disclosure,controller,tools
from forensic_assistant.investigation_ai.conclusions import interpretations
from forensic_assistant.retrieval.event_data import interpretation
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.investigation_ai.narrative import build
from test_v4_controller import Scripted,tool


def records():
    result=[]
    for i,family in enumerate(['browser','evtx','mft','mft','mft','prefetch']):
        suffix='download:1' if family=='browser' else 'File' if family=='prefetch' else 'Offset:'+str(i)
        r=dict(id=family.upper()+':'+str(i)*64+':'+suffix,source_type=family,kind='file',
            objects=['item'+str(i)+'.ps1','C:\\Evidence\\item'+str(i)+'.ps1'],
            timestamps=[dict(utc='2026-09-30T12:00:00Z',type='Recorded creation time',slot='created',meaning='recorded')],
            source_context={'basis':'analyst assertion','assertions':['untrusted metadata '*50]},truncated_fields=['warnings'])
        if i==2:r['objects']=['sample.zip',r'C:\sample.zip']
        if family=='browser':r.update(target_path='C:\\sample.zip',url_chain=[dict(chain_index=0,url='https://example.invalid/sample.zip')])
        if family=='prefetch':r['executable']='EXPLORER.EXE'
        if family=='evtx':
            r.pop('objects')
            r.update(provider='Microsoft-Windows-Windows Defender',channel='Microsoft-Windows-Windows Defender/Operational',event_id=1121,
                original_event_data=[dict(name='Target Commandline',ordinal=11,value='powershell.exe item4.ps1',truncated=False)])
            r['defender_asr']=interpretation(r);r['interpretation_ids']=list(interpretations(r))
        result.append(r)
    return result


def envelope(rows):
    return dict(tool='show_evidence',behavior='deterministic',records=rows,relationships=[],detections=[],limitations=[],returned_count=len(rows),truncated=False,semantic_candidates=[],label='UNTRUSTED FORENSIC EVIDENCE')


def state():
    s=State(Budget());s.compact_final=True;s.finalization_requested=True;s.steps=7
    for r in records():s.ingest(envelope([r]),operation='show_evidence')
    return s


def answer(packet):
    if packet.get("encoding"):packet=disclosure.decode(packet)
    return dict(observed=[dict(evidence_id=r['id'],field=i['field']['pointer']) for r in packet['records'] for i in r['observations']],
        interpretations=[i['id'] for r in packet['records'] for i in r['interpretations']], relationships=[],detections=[],hypotheses=[],
        unknowns=['Successful script execution and causation remain unresolved.'],answer_status='partial')


def test_six_records_coexist_exactly_and_no_metadata_authority():
    s=state();messages,packet,size=s.prompt('What supports the sequence and did the PowerShell script execute?',[],[])
    assert size<=5600 and len(packet['records'])==6
    assert json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']==packet
    assert size==sum(len(m['content'].encode('utf-8')) for m in messages)
    readable=disclosure.decode(packet)
    count=sum(len(r['observations']) for r in packet['records'])
    assert 10<=count<=12
    s.disclose(packet);result=s.render(answer(packet))
    assert len(result['observed'])==count and len(result['interpretations'])==1
    browser=next(r for r in readable['records'] if r['id'].startswith('BROWSER:'))
    assert {'/target_path','/url_chain/0/url'} <= {i['field']['pointer'] for i in browser['observations']}
    zip_record=next(r for r in readable['records'] if r['id'].startswith('MFT:2'))
    assert {'/objects/1','/timestamps/0/utc'} <= {i['field']['pointer'] for i in zip_record['observations']}
    assert 'does not establish successful' in result['interpretations'][0]['text']
    for r in result['observed']:assert r['truncated_fields']==['warnings']
    evtx=next(r for r in packet['records'] if r['id'].startswith('EVTX:'))
    bad=answer(packet);bad['observed']=[dict(evidence_id=evtx['id'],field='/provider')]
    with pytest.raises(ValueError):s.render(bad)
    assert len(build(result,s.summary())['coverage']['represented_record_ids'])==6
    print('six-record compact prompt bytes:',size)


@pytest.mark.parametrize('change',['value','label','pointer','provenance','truncation','semantic','origin','identity','interpretation','version'])
def test_forged_disclosures_rejected_before_mutation(change):
    s=state();_,wire,_=s.prompt('PowerShell execution sequence',[],[]);p=disclosure.decode(wire)
    group=p['records'][0];item=group['observations'][0]
    if change=='value':item['field']['value']='forged'
    elif change=='label':item['field']['label']='execution proved'
    elif change=='pointer':item['field']['pointer']='/hidden'
    elif change=='semantic':item['field']['semantic']={'meaning':'execution'}
    elif change=='provenance':group['sources'][item['origin']]['provenance']='0'*64
    elif change=='truncation':group['sources'][item['origin']]['truncated_fields']=[]
    elif change=='origin':item['origin']='historical'
    elif change=='identity':group['id']='E1'
    elif change=='interpretation':next(r for r in p['records'] if r['interpretations'])['interpretations'][0]['value']['text']='execution proved'
    else:p['contract']='future'
    before=copy.deepcopy(s.exposed)
    with pytest.raises(ValueError):s.disclose(disclosure.encode(p))
    assert s.exposed==before


def test_retained_fields_are_not_historical_assessment_facts():
    s=state();_,p,_=s.prompt('PowerShell execution sequence',[],[]);s.disclose(p)
    old=copy.deepcopy(s.exposed)
    for eid in s.records:s.records[eid]={'id':eid,'source_type':eid.split(':')[0].lower()}
    _,retained,_=s.prompt('PowerShell execution sequence',[],[])
    assert any(i['origin']=='retained' for r in disclosure.decode(retained)['records'] for i in r['observations'])
    s.disclose(retained);s.render(answer(retained))
    fresh=State(Budget());fresh.records=copy.deepcopy(s.records)
    with pytest.raises(ValueError):fresh.disclose(retained)


def test_pressure_reports_omission_without_claiming_irrelevance():
    s=state();s.budget=Budget(prompt_bytes=2500)
    _,p,size=s.prompt('What executed?',[],[]);assert size<=2500
    s.disclose(p);n=build(s.render(answer(p)),s.summary())
    assert n['coverage']['inspected_not_represented']
    assert n['coverage']['relevance_of_omissions'].startswith('Not evaluated')


def run_six(tmp_path, include_interpretations=True):
    rows=records();approvals=[]
    class Worker:
        def __init__(self,c):pass
        def close(self):pass
        def __enter__(self):return self
        def __exit__(self,*args):self.close()
        def call(self,name,args=None,**kw):
            selected=([{'id':r['id'],'source_type':r['source_type'],'kind':r['kind']} for r in rows] if name=='initial' else
                      [next(r for r in rows if r['id']==args['evidence_id'])] if name=='show_evidence' else [])
            return dict(result=envelope(selected),fingerprint='f'*64,database_changes=0,schema=5,elapsed_seconds=0,semantic_available=False)
    def final(messages):
        p=json.loads(messages[1]['content']);assert p['controller']['final_only']
        assert p['UNTRUSTED FORENSIC EVIDENCE']['contract']==disclosure.CONTRACT
        value=answer(p['UNTRUSTED FORENSIC EVIDENCE'])
        if not include_interpretations:value['interpretations']=[]
        return {'action':'final','answer':value}
    client=Scripted([tool('show_evidence',{'evidence_id':r['id']}) for r in rows]+[final])
    out=controller.run({},'What supports the sequence and did the PowerShell script execute?',tmp_path/'runs',client=client,worker_factory=Worker,approval=lambda *a:approvals.append(a) or True)
    assert out['termination']=='ANSWER_SUPPORTED' and len(approvals)==6 and len(client.calls)==7
    assert len(out['narrative']['coverage']['represented_record_ids'])==6
    m,events=load(tmp_path/'runs',out['investigation_id'])
    assert events[-1]['data']['findings']==out['findings']
    assert max(out['metrics']['prompt_bytes'])<=5600

    return out,Worker


def test_controller_six_approvals_final_only_and_transcript(tmp_path):
    run_six(tmp_path)


def test_replay_and_report_adapter_verify_compact_contract(tmp_path,monkeypatch):
    from forensic_assistant.investigation_ai import replay
    from forensic_assistant.reporting.transcripts import load as report_load
    from test_v5_security import rehash_transcript
    out,Worker=run_six(tmp_path,False)
    root=tmp_path/'runs';iid=out['investigation_id']
    adapter=report_load(root,iid)
    assert adapter['findings']==out['findings']
    monkeypatch.setattr(replay,'ForensicWorker',Worker)
    replayed=replay.replay({},root,iid)
    assert replayed['termination']=='REPLAY_MATCH'
    def forge(events):
        event=next(e for e in events if e['kind']=='exposure' and 'contract' in e['data']['content'])
        event['data']['content']['records'][0]['observations'][0][2]='forged'
        return events
    rehash_transcript(root/iid,forge)
    # A repaired hash chain is not evidence grounding.
    load(root,iid)
    with pytest.raises(ValueError,match='Compact observation'):
        report_load(root,iid)
    assert replay.replay({},root,iid)['termination']=='REPLAY_REFUSED'


def test_selected_findings_are_not_confused_with_inspection_coverage():
    s=state();_,p,_=s.prompt('Did the script execute?',[],[]);s.disclose(p)
    a=answer(p);a['observed']=a['observed'][:1];a['interpretations']=[]
    findings=s.render(a);coverage=build(findings,s.summary())['coverage']
    assert coverage['inspected_records']==6
    assert len(coverage['represented_record_ids'])==1
    assert len(coverage['inspected_not_represented'])==5
    assert coverage['prompt_observations_not_selected']
    assert coverage['disclosed_interpretations_not_selected']
    assert coverage['relevance_of_omissions'].startswith('Not evaluated')


def test_incomplete_search_coverage_reaches_final_model():
    s=state();s.content_search=dict(complete=False,examined=1000,skipped=5,next_cursor='unneeded-final-cursor')
    messages,_,size=s.prompt('What executed?',[],[])
    assert json.loads(messages[1]['content'])['controller']['evtx_content_search']==dict(complete=False,examined=1000,skipped=5)
    assert size<=5600


@pytest.mark.parametrize('change',['encoding','short_field','long_field','source_tuple'])
def test_malformed_wire_rejected_atomically(change):
    s=state();_,p,_=s.prompt('PowerShell sequence',[],[])
    if change=='encoding':p['encoding']='future'
    elif change=='short_field':p['records'][0]['observations'][0].pop()
    elif change=='long_field':p['records'][0]['observations'][0].append('extra')
    else:p['records'][0]['sources']['current'].pop()
    with pytest.raises(ValueError):s.disclose(p)
    assert not s.exposed


def test_historical_fields_are_not_current_request_authority():
    s=state();_,p,_=s.prompt('PowerShell sequence',[],[]);s.disclose(p)
    earlier=answer(p)
    retained=copy.deepcopy(p);retained['records']=retained['records'][:1]
    s.disclose(retained)
    absent=next(i for i in earlier['observed'] if i['evidence_id']!=retained['records'][0]['id'])
    a=answer(retained);a['observed']=[absent]
    assert s.field_visible(absent['evidence_id'],absent['field'])
    assert not s.field_visible(absent['evidence_id'],absent['field'],latest=True)
    with pytest.raises(ValueError):s.render(a)
    s.partial()


def test_original_event_data_truncation_survives_without_value_rewrite():
    s=state();record=next(r for r in s.records.values() if r['source_type']=='evtx')
    record['original_event_data'][0]['truncated']=True
    _,p,_=s.prompt('PowerShell sequence',[],[])
    s.disclose(p);finding=next(r for r in s.render(answer(p))['observed'] if r['field'].startswith('/original_event_data/'))
    assert finding['reported_value']==record['original_event_data'][0]['value']
    assert finding['recorded_field']==dict(name='Target Commandline',ordinal=11,truncated=True)


def test_hypotheses_cannot_cite_omitted_historical_record():
    s=state();_,p,_=s.prompt('PowerShell sequence',[],[]);s.disclose(p)
    omitted=p['records'][-1]['id'];p['records']=p['records'][:1];s.disclose(p)
    a=answer(p);a['hypotheses']=[dict(statement='Possible activity',evidence_ids=[omitted],alternatives=['Unrelated activity'])]
    with pytest.raises(ValueError,match='Hypothesis cites undisclosed evidence'):s.render(a)


def test_record_insertion_order_does_not_displace_earlier_findings():
    first=state();second=state();second.records=dict(reversed(list(second.records.items())))
    assert first.prompt('PowerShell sequence',[],[])[1]==second.prompt('PowerShell sequence',[],[])[1]

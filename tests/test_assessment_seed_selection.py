"""Neutral synthetic historical assessments; production selection/grant paths."""
from contextlib import closing
from collections import Counter
from types import SimpleNamespace
import copy
import pytest
from forensic_assistant import assessment_handoff as handoff, assessment_selection as selection, assessment_handoff_cli, activity
from forensic_assistant.assessment_store import AssessmentStore
from forensic_assistant.briefing_store import digest
from forensic_assistant.database.db import connect
from forensic_assistant.investigation_ai import autonomous
from forensic_assistant.ai import readiness,backend
from test_assessment import accepted

START='2020-01-01T00:00:00Z';END='2020-01-02T00:00:00Z'


@pytest.fixture
def saved(tmp_path):
    case=tmp_path/'case.db'
    with closing(connect(case)):pass
    revision=accepted(case,values=())
    store=AssessmentStore(case)
    plan=dict(case=store.identity,revision=revision['revision'],digest=revision['digest'],start=START,end=END,source_id='src-one',leads=[])
    records={}
    for family,count in [('browser',30),('evtx',4),('prefetch',4),('mft',4),('registry',4)]:
        for n in range(count):
            locator={'browser':'download','evtx':'Offset','mft':'Offset','registry':'KeyOffset','prefetch':'File'}[family]
            eid=f'{family.upper()}:'+f'{n:064x}'+':'+locator+('' if family=='prefetch' else ':1')
            records[eid]=dict(artifact=family,source_context={'source_ids':['src-one']},presentation={'artifact_type':'browser_download' if n%2 else 'browser_visit'},
                match={'timestamps':[dict(timestamp_utc='2020-01-01T12:00:00Z',slot='recorded',meaning='synthetic metadata')],'timestamps_truncated':True})
    value=dict(id='a'*32,kind='case_assessment',case=store.identity,created=START,status='COMPLETE_WITH_LIMITATIONS',plan=plan,
        authorization={'plan_digest':digest(plan)},records=records,timeline=[],rows=[dict(artifact=f,status='incomplete',limitations=['Synthetic bounded coverage']) for f in selection.FAMILIES])
    store.save_assessment(value)
    return case,store,value


def client(monkeypatch):
    monkeypatch.setattr(readiness,'status',lambda _: {'investigation_compatibility':'ready'})
    return SimpleNamespace(provider_name='openai',model_name='synthetic',config={'cloud_acknowledged':True})


def test_production_handoff_grant_and_six_lookup_coverage(saved,monkeypatch):
    case,store,value=saved;before=store.path.read_bytes()
    old=handoff.prepare(case,value['id'],'Compare artifact activity')
    assert all(h['id'].startswith('BROWSER:') for h in old['hints'])
    new=handoff.prepare(case,value['id'],'Correlate browser downloads, process execution, file changes and persistence',diverse=True)
    assert new==handoff.prepare(case,value['id'],new['question'],diverse=True)
    assert len(new['hints'])==12
    grant,hints=autonomous.prepare(new,value,client(monkeypatch),decompose=True,synthesize=True)
    assert grant['evidence_ids']==new['selection']['selected_ids']
    assert set(grant['families'])==set(selection.FAMILIES) and grant['source_ids']==['src-one']
    assert grant['limits']['tool_calls']==6 and grant['limits']['requests']==9
    pending=set(grant['evidence_ids']);inspected=[]
    for _ in range(6):
        eid=autonomous.choose(pending,hints,{},grant['selection'],inspected)
        pending.remove(eid);inspected.append(eid)
    assert {e.split(':')[0].lower() for e in inspected}==set(selection.FAMILIES)
    assert len({new['selection']['buckets'][e] for e in inspected})==6
    assert store.path.read_bytes()==before


@pytest.mark.parametrize('families',[['browser'],['mft','registry'],list(selection.FAMILIES)])
def test_missing_families_and_insufficient_evidence(saved,families):
    _,_,value=saved;value=copy.deepcopy(value)
    value['records']={e:r for e,r in value['records'].items() if r['artifact'] in families}
    refs,meta=selection.select(value,handoff.references(value),[],'Compare activity',{'start':START,'end':END})
    assert set(meta['selected_by_family'])==set(families)
    assert len(refs)<=12 and len(meta['selected_ids'])==len(set(meta['selected_ids']))
    value['records']=dict(list(value['records'].items())[:1])
    assert len(selection.select(value,handoff.references(value),[],'Compare activity',{'start':START,'end':END})[0])==1


def test_source_time_and_single_family_question(saved):
    _,_,value=saved;value=copy.deepcopy(value)
    ids=list(value['records'])
    value['records'][ids[0]]['source_context']['source_ids']=['src-other']
    value['records'][ids[1]]['match']['timestamps'][0]['timestamp_utc']=END
    value['records'][ids[2]]['match']['timestamps']=[]
    refs,meta=selection.select(value,handoff.references(value),[],'Inspect browser only',{'start':START,'end':END})
    assert not set(ids[:3])&set(meta['selected_ids'])
    assert set(meta['selected_by_family'])=={'browser'}
    assert meta['excluded']['source_not_eligible']==1 and meta['excluded']['no_retained_in_window_timestamp']==2
    with pytest.raises(ValueError):selection.select(value,handoff.references(value),['E1'],'Inspect browser only',{'start':START,'end':END})


def test_exact_reference_priority_no_duplicates_and_time_expansion(saved):
    case,_,value=saved
    p=handoff.prepare(case,value['id'],'Compare E1 and E1',diverse=True)
    assert p['hints'][0]['id']==handoff.references(value)['E1']
    assert len({r['id'] for r in p['hints']})==12
    with pytest.raises(ValueError,match='expand'):handoff.prepare(case,value['id'],'Compare','2019-12-31T23:00:00Z','2020-01-01T23:00:00Z',diverse=True)


def test_declined_cli_displays_scope_no_worker_or_provider(saved,monkeypatch,capsys):
    case,store,value=saved;before=store.path.read_bytes();events=[]
    monkeypatch.setattr(backend,'backend',lambda:client(monkeypatch))
    monkeypatch.setattr('forensic_assistant.investigation_ai.supervision.run',lambda *a,**k:pytest.fail('No execution after rejection'))
    monkeypatch.setattr(activity,'event',lambda *a,**k:events.append((a,k)))
    result=assessment_handoff_cli.execute(case,value['id'],'Correlate activity across artifacts',read=lambda _:'n',autonomous=True,decompose=True,synthesize=True)
    out=capsys.readouterr().out
    assert 'Selected seed records:' in out and 'registry' in out and 'ONLY the selected IDs' in out
    assert 'Synthetic bounded coverage' in out and 'cancelled' in result['message']
    assert set(result['selection']['selected_by_family'])==set(selection.FAMILIES)
    assert events[-1][0]==('INVESTIGATION_AUTHORIZATION','cancelled') and events[-1][1]['required']
    assert store.path.read_bytes()==before


def test_balanced_selection_and_json_scope(saved,monkeypatch):
    import json,time
    from forensic_assistant.investigation_ai import autonomous_policy
    case,_,value=saved;value=copy.deepcopy(value)
    kept={};counts=Counter()
    for eid,record in value['records'].items():
        if counts[record['artifact']]<4:kept[eid]=record;counts[record['artifact']]+=1
    value['records']=kept
    _,meta=selection.select(value,handoff.references(value),[],'Correlate artifacts',{'start':START,'end':END})
    assert set(meta['selected_by_family'])==set(selection.FAMILIES)
    p=handoff.prepare(case,'a'*32,'Compare artifacts',diverse=True)
    grant,_=autonomous.prepare(p,handoff.select(case,'a'*32),client(monkeypatch))
    assert json.loads(json.dumps(grant))==grant
    grant.update(issued=time.time(),expires=time.time()+299)
    autonomous_policy.operation(grant,str(case),'show_evidence',{'evidence_id':grant['evidence_ids'][0]})
    with pytest.raises(ValueError):autonomous_policy.operation(grant,str(case),'search_evidence',{})
    outside=next(e for e in handoff.select(case,'a'*32)['records'] if e not in grant['evidence_ids'])
    with pytest.raises(ValueError):autonomous_policy.operation(grant,str(case),'show_evidence',{'evidence_id':outside})

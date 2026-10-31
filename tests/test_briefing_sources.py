"""Exact source provenance and bounded contract-v2 interpretation; no model I/O."""
import json
import pytest
from forensic_assistant import briefing as b, briefing_cli
from forensic_assistant.briefing_sources import inventory, supports, UNIT_CHARS, MAX_UNITS
from forensic_assistant.ai.openai_schema import request_schema, response
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from test_briefing import Fake, item


@pytest.mark.parametrize('text',['Alpha','\ufeffAlpha','Alpha\nBeta','Alpha\r\nBeta',
    'Alpha\n\r\nBeta','é😀 Alpha','Alpha\n\nBeta','Alpha\r\n\r\nBeta',
    'Alpha\n\nAlpha','Alpha\n\n\n\nBeta','x'*(UNIT_CHARS*3+7)])
def test_exact_coverage_stability_and_edits(text):
    units,coverage=inventory({'original':text})
    assert coverage['complete'] and ''.join(u['text'] for u in units)==text
    assert len({u['id'] for u in units})==len(units)
    assert all(text[u['start']:u['end']]==u['text'] and len(u['text'])<=UNIT_CHARS for u in units)
    assert inventory({'original':text})[0]==units
    assert set(u['id'] for u in inventory({'original':text+'!'})[0]).isdisjoint(u['id'] for u in units)


def test_multiline_paragraph_and_count_limit():
    assert len(inventory({'original':'Alpha\r\nBeta'})[0])==1
    assert len(inventory({'original':'Alpha\nBeta'})[0])==1
    units,c=inventory({'original':'x\n\n'*(MAX_UNITS+10)})
    assert len(units)==MAX_UNITS and not c['complete'] and c['total_units']>MAX_UNITS


@pytest.mark.parametrize('text',['',' \t\r\n','\ufeff \n'])
def test_empty_input_rejected(text):
    with pytest.raises(ValueError):b.extract(text)


def test_correction_entities_and_wrong_attribution():
    p=b.extract('original.exe',['corrected.exe'])
    correction=next(u for u in p['source_units'] if u['source']=='correction:1')
    lead=next(r for r in p['leads'] if r['normalized']=='corrected.exe')
    proposal={**item('corrected.exe'),'source_ids':[correction['id']],'entity_ids':[lead['id']]}
    f=Fake({'items':[proposal]});b.interpret(p,f)
    assert p['ai_status']=='success' and p['inputs']['original']=='original.exe'
    payload=json.loads(f.calls[0][0][1]['content'])
    assert 'original' not in payload and any(u['source']=='correction:1' for u in payload['sources'])
    proposal['source_ids']=[p['source_units'][0]['id']]
    p=b.extract('original.exe',['corrected.exe']);b.interpret(p,Fake({'items':[proposal]}))
    assert p['ai_error']['rejected_items'][0]['rule']=='entity_outside_referenced_source'
    units=inventory({'original':'same','correction:1':'same','correction:2':'same'})[0]
    assert len({u['id'] for u in units})==3


def test_multi_source_questions_alternatives_and_explicit_paraphrase():
    text='A download was reported.\n\nPowerShell and WMI were reported.';p=b.extract(text)
    ids=[u['id'] for u in p['source_units']]
    values=[dict(category=c,text=t,source_ids=ids,basis='inferred',entity_ids=[],uncertainty='Not investigated') for c,t in [
        ('question','Is there evidence that WMI initiated PowerShell?'),
        ('hypothesis','The download may be related to the activity.'),
        ('alternative','The download may be unrelated to the activity.')]]
    values.append(dict(category='reported_activity',text='The analyst reports a download.',source_ids=[ids[0]],basis='explicit',entity_ids=[],uncertainty='Unverified'))
    b.interpret(p,Fake({'items':values}))
    assert p['ai_status']=='success' and len(p['ai_items'])==4
    assert p['ai_items'][-1]['basis']=='inferred' and p['ai_items'][-1]['model_basis']=='explicit'
    assert all(v['semantic_entailment']=='not_verified' for v in p['ai_items'])
    output=briefing_cli.render(p, details=True)
    assert ids[0] in output and 'not evidence' in output and 'alternative' in output
    assert 'discovery' not in p and 'handoff' not in p


@pytest.mark.parametrize('change,rule',[
    ({'source_ids':['EVTX:fake']},'unknown_source_id'),
    ({'entity_ids':['L-fake']},'unknown_entity_id'),
    ({'text':'invented.ps1 ran'},'unsupported_technical_literal'),
    ({'basis':'explicit'},'invalid_inference_classification')])
def test_invalid_references_and_classification(change,rule):
    p=b.extract('sample.exe');proposal={**item('sample.exe'),**change}
    b.interpret(p,Fake({'items':[item('sample.exe'),proposal]}))
    assert p['ai_status']=='partial' and p['ai_error']['rejected_items'][0]['rule']==rule


@pytest.mark.parametrize('ids',[[],['duplicate','duplicate']])
def test_source_reference_structural_constraints(ids):
    proposal={**item('sample.exe'),'source_ids':ids}
    with pytest.raises(ProviderFailure):response('openai',json.dumps({'items':[proposal]}),b.SCHEMA)
    p=b.extract('sample.exe');b.interpret(p,Fake({'items':[proposal]}))
    assert p['ai_status']=='failed' and p['ai_error']['category']=='structural_validation'


def test_partial_exposure_never_authorizes_unexposed_source():
    p=b.extract(('x'*200+'\n\n')*150)
    f=Fake({'items':[{**item('x'),'source_ids':[p['source_units'][-1]['id']]}]})
    b.interpret(p,f)
    assert len(f.calls)==1 and p['metrics']['ai_input_bytes']<=5600
    assert not p['ai_source_coverage']['complete']
    assert p['ai_error']['rejected_items'][0]['rule']=='unknown_source_id'


def test_split_occurrence_requires_complete_cited_coverage():
    text='x'*(UNIT_CHARS-3)+' sample.exe'
    p=b.extract(text);lead=next(v for v in p['leads'] if v['type']=='filename')
    assert supports(lead,p['source_units'])
    assert not supports(lead,p['source_units'][:1])


def test_contract_version_legacy_rejection_and_wire_shape():
    p=b.extract('sample.exe');assert p['interpretation_contract']==2 and p['format']==1
    legacy=dict(category='hypothesis',start=0,end=10,quote='sample.exe',text='sample.exe',basis='inferred',entity_ids=[],uncertainty='Unverified')
    b.interpret(p,Fake({'items':[legacy]}));assert p['ai_status']=='failed'
    wire=request_schema('openai',b.SCHEMA)
    assert 'uniqueItems' not in json.dumps(wire) and 'proposal' not in wire['properties']
    assert 'source_ids' in wire['properties']['items']['items']['required']

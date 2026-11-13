"""Predeclared selection expectations; mocks do not demonstrate AI reasoning."""
import copy
import json
import pytest
from forensic_assistant.investigation_ai import d2_cross as x, d2_execution as ex
from d2_generic_fixtures import row, context
from test_d2_preview import history
from test_d2_cross import rows
from test_d2_execution import config

PATH=r'C:\Evidence\receipt.bin'


def plan(records, question):
    h=x.History(history(context(records)[0]),question,config()['model'])
    return h,h.preview()


def fields(result):
    return result['packets'][0]['content']['supports'] if result['packets'] else []


CASES=[
 ('download_filesystem',rows()[:2], 'Compare the download and filesystem path.', {'path'}, 'comparison_inputs_present'),
 ('registry_process',[row('registry',1,objects=[r'HKCU\Run',r'C:\Apps\agent.exe']),row('evtx',2,process_name='agent.exe')], 'Compare Registry Run and process identity.', {'reference','name'}, 'comparison_inputs_present'),
 ('process_prefetch',[row('evtx',1,process_name='agent.exe'),row('prefetch',2,executable='AGENT.EXE')], 'Compare process and Prefetch executable.', {'name'}, 'comparison_inputs_present'),
 ('hashes',[row('evtx',1,original_event_data=[dict(name='SHA256',ordinal=0,value='a'*64,truncated=False)]),row('evtx',2,original_event_data=[dict(name='SHA256',ordinal=0,value='a'*64,truncated=False)])], 'Compare the recorded hashes.', {'hash'}, 'comparison_inputs_present'),
 ('different_paths',[row('browser',1,target_path=r'C:\One\same.exe'),row('mft',2,objects=[r'D:\Two\same.exe'])], 'Compare recorded paths.', {'path'}, 'comparison_inputs_present'),
 ('timestamp_only',[row('browser',1,timestamp_utc='2026-01-01T00:00:00Z'),row('mft',2,timestamp_utc='2026-01-01T00:00:02Z')], 'Compare the subsequent filesystem paths.', set(), 'comparison_inputs_missing'),
 ('unmapped',rows()[:2], 'Who intended to deceive the investigator?', set(), 'question_sufficiency_not_established'),
 ('no_relationship',[row('browser',1,target_path=r'C:\first.bin'),row('mft',2,objects=[r'D:\other.bin'])], 'Compare the file paths.', {'path'}, 'comparison_inputs_present'),
]


@pytest.mark.parametrize('name,records,question,required,status',CASES,ids=[v[0] for v in CASES])
def test_predeclared_requirements(name,records,question,required,status):
    h,result=plan(records,question)
    assert result['context_sufficiency']['status']==status
    selected={result['selection']['field_roles'][result['packets'][0]['content']['clauses'][s['clause_ref']]] for s in fields(result)}
    if name=='hashes':
        assert result['status']=='insufficient_artifact_coverage'
        assert sum(result['selection']['field_roles'][k]=='hash' for k,v in result['selection']['decisions'].items() if v=='selected')==2
    else: assert required<=selected
    assert result==h.preview()
    if result['packets']:
        p=ex.Prepared(h,result['packets'][0],config(),dict(exploratory=True),profile=x.VERSION)
        assert len(p.body)<=16384
        if name in ('hashes','different_paths','no_relationship'):
            assert not any(r['predicate']=='exact_recorded_path' for r in p.packet['content']['relationships'])


@pytest.mark.parametrize('source',['different_host','ambiguous_source'])
def test_identity_context_not_collapsed(source):
    records=rows()[:2]
    records[1]['source_context']['hostname']='other-node'
    if source=='ambiguous_source':records[1]['source_context']['source_ids']=['synthetic-source','other-source']
    ctx,_=context(records)
    ctx.manifest['authorization']['source_ids']=['synthetic-source','other-source']
    h=x.History(history(ctx),'Compare the download and filesystem paths.',config()['model'])
    result=h.preview()
    body=result['packets'][0]['content']
    assert len(body['records'])==2
    assert 'other-node' in x.wire.J(body['sources'])
    assert 'no object identity' in result['context_sufficiency']['meaning'].lower()


def test_large_high_lexical_noise_cannot_displace_comparison():
    records=rows()[:2]+[row('registry',9,command_line='download filesystem compare '*70)]
    h,result=plan(records,'Compare the download and filesystem path.')
    body=result['packets'][0]['content']
    assert any(s['field']['pointer']=='/target_path' for s in body['supports'])
    assert any(s['field']['pointer']=='/objects/0' for s in body['supports'])
    assert result['context_sufficiency']['status']=='comparison_inputs_present'


def test_complete_large_pair_vs_smaller_useful_pair():
    huge='C:\\'+('directory\\'*130)+'same.bin'
    records=[row('browser',1,target_path=huge),row('mft',2,objects=[huge]),
             row('browser',3,target_path=PATH),row('mft',4,objects=[PATH])]
    h,result=plan(records,'Compare the recorded file paths.')
    primary=next(b for b in result['selection']['bundles'] if b['reason']=='selected_primary')
    chosen=[next(c for c in h._ctx.factual['clauses'] if c['id']==uid) for uid in primary['units'] if uid in result['selection']['field_roles']]
    assert any(c['supports'][0]['field']['value']==PATH for c in chosen)
    assert result['context_sufficiency']['status']=='comparison_inputs_present'


def test_missing_and_omitted_are_distinct():
    h=history(context(rows()[:2])[0])
    # Remove actual authorization, not just a ranking score: restoration must fail closed.
    h._ctx.manifest['authorization']['evidence_ids']=[]
    h._seal=h._digest()  # Internal synthetic trust fixture, never a public import path.
    trusted=x.History(h,'Compare the download and filesystem path.',config()['model'])
    with pytest.raises(ValueError,match='scope or epoch'):trusted.preview()


def test_unavailable_projection_does_not_reappear():
    h=history(context(rows()[:2])[0]);h._ctx.state.records.clear();h._seal=h._digest()
    result=x.History(h,'Compare the file paths.',config()['model']).preview()
    assert result['selection']['omitted_counts']['support_unavailable']
    assert not result['packets']


def test_single_family_question_not_padded():
    h,result=plan(rows(),'Show only browser download information.')
    assert result['status']=='insufficient_artifact_coverage'
    assert result['families']==['browser']
    assert 'outside_explicit_family_question' in result['selection']['omitted_counts']


def test_byte_costs_measured_and_unknown_question_honest():
    h,result=plan(rows(),'Who caused this incident?')
    assert result['context_sufficiency']['status']=='question_sufficiency_not_established'
    assert all(b['cost_bytes'] is None or type(b['cost_bytes']) is int for b in result['selection']['bundles'])
    assert result['selection']['bundles']
    p=ex.Prepared(h,result['packets'][0],config(),dict(exploratory=True),profile=x.VERSION)
    view=p.preview();text=x.render_preview(view)
    assert 'question_sufficiency_not_established' in text
    assert len(text)<4000 and 'canonical_packet' not in text


def test_time_context_not_execution_or_synchronized_order():
    records=rows()[:2];records[1]['timestamps'][0]['utc']='2026-10-12T08:00:00'
    _,result=plan(records,'Compare the subsequent filesystem path and download.')
    assert result['context_sufficiency']['status']=='comparison_inputs_present'
    assert any('timezone' in q for q in result['packets'][0]['content']['qualifications'])
    assert all(r['predicate']!='recorded_time_before' for r in result['packets'][0]['content']['relationships'])


def test_generic_semantics_not_arbitrary_text():
    _,result=plan([row('browser',1,command_line=PATH),row('evtx',2,command_line=PATH)],'Compare file paths.')
    assert result['context_sufficiency']['status']=='comparison_inputs_missing'
    assert set(result['selection']['field_roles'].values())=={'context'}



def test_safe_byte_fit_is_not_investigative_admission(monkeypatch,tmp_path):
    from forensic_assistant.investigation_ai import d2
    records=[row('browser',1,timestamp_utc='2026-01-01T00:00:00Z'),row('mft',2,timestamp_utc='2026-01-01T00:00:02Z')]
    h=history(context(records)[0]);monkeypatch.setattr(d2,'open_history',lambda *a:h)
    value=x.preview(tmp_path,'a'*32,'Compare filesystem paths.',config())
    assert value['fits'] and not value['investigative_admission']
    assert value['context_sufficiency']['status']=='comparison_inputs_missing'
    with pytest.raises(ValueError,match='CONTEXT_INSUFFICIENT'):
        x.prepare(tmp_path,'a'*32,'Compare filesystem paths.',config())


def test_omitted_role_distinguished_from_unavailable(monkeypatch):
    # Fault-inject a stricter local planning ceiling; never enlarge the policy.
    # Both original fields are eligible, but no complete context can be admitted.
    monkeypatch.setattr(x,'LIMIT',2000)
    _,result=plan(rows()[:2],'Compare file paths.')
    suff=result['context_sufficiency']
    assert suff['status']=='comparison_inputs_missing'
    assert suff['available_but_omitted_roles']==['identifying_fields_from_two_distinct_records']
    assert suff['unavailable_roles']==[]
    assert not result['packets']



def test_reference_pair_is_not_process_context():
    records=[row('registry',1,objects=['Run entry A']),row('mft',2,objects=[r'C:\\entry.bin'])]
    _,result=plan(records,'Compare Registry and process activity.')
    # A reference/path pair permits a structural identity-context comparison,
    # but two bare references cannot stand in for process identity.
    records=[row('registry',1,objects=['Run entry A']),row('prefetch',2,objects=['Referenced data'])]
    _,result=plan(records,'Compare Registry and process activity.')
    assert result['context_sufficiency']['status']=='comparison_inputs_missing'

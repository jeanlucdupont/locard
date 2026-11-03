"""6.85 synthetic providers; no live model, protected case or forensic writes."""
import copy
import json
import pytest
from forensic_assistant import briefing as b,briefing_canonical as c
from forensic_assistant.briefing_completion import summary_diagnostic,unknown_label
from forensic_assistant.briefing_store import content,FIELDS
from test_briefing import Fake
from test_briefing_semantics import candidate
from test_briefing_completeness import NARRATIVE
from test_briefing_canonical import entry
from test_briefing_persistence import store,args


def interpret(text,kind='person',literal='Callie Wade',description='User Callie Wade',**extra):
    p=b.extract(text);v=candidate(p,kind,literal,**extra);v['description']=description
    b.interpret(p,Fake({'items':[],'candidates':[v]}))
    return p


def test_ordinary_sentence_person_description_collision_fixed():
    p=interpret('Callie Wade attempted to print a PDF worksheet.',category='person')
    assert p['ai_status']=='success'
    assert p['ai_candidates'][0]['literal']=='Callie Wade'
    assert not [v for v in p['leads'] if v['type']=='username']
    assert c.build(p)['document']['categories']['person'][0]['value']=='Callie Wade'


@pytest.mark.parametrize('description',['Account Callie Wade','Account cwade','User Jane Doe','Host invented-999'])
def test_person_does_not_authorize_account_or_other_identifiers(description):
    p=interpret('Callie Wade attempted to print a worksheet.',description=description)
    assert p['ai_candidates'][0]['literal']=='Callie Wade'
    flags=p['ai_candidates'][0]['narrative_review']
    assert flags and flags[0]['rule']=='possible_identifier_mismatch'
    assert not [v for v in p['leads'] if v['type'] in ('username','hostname')]
    assert description not in json.dumps(flags)


def test_unsupported_person_and_source_stay_rejected():
    p=interpret('A worksheet was opened.')
    assert p['ai_error']['rejected_items'][0]['literal_support']=='unsupported'
    p=b.extract('Callie Wade attempted to print.');v=candidate(p,'person','Callie Wade',category='account');v['source_ids']=['unknown-source']
    b.interpret(p,Fake({'items':[],'candidates':[v]}))
    assert p['ai_error']['rejected_items'][0]['rule']=='unknown_source_id'
    assert p['ai_error']['rejected_items'][0]['source_references']=='invalid'


def test_accounts_unknowns_and_technical_terms():
    p=interpret(r'Account LAB\cwade was reported.',kind='account',literal=r'LAB\cwade',description='Reported identifier',category='account')
    assert p['ai_candidates'][0]['technical_validation']=='passed'
    p=interpret('Callie Wade reported that the account is unknown.',kind='account',literal='account is unknown',description='Unknown account',category='account',status='unknown')
    doc=c.build(p)['document'];assert doc['categories']['account'][0]['value']==''
    p=interpret('Reported per-user TypeLib hijack.',kind='hostname',literal='per-user',description='Reported identifier')
    assert p['ai_error']['rejected_items'][0]['technical_validation']=='failed'


@pytest.mark.parametrize('summary,expected',[
    ('ABSENT','not_generated'),('', 'explicitly_empty'),({},'explicitly_empty'),
    ({'text':'','source_ids':['x'],'uncertainty':'Unknown'},'explicitly_empty'),
    ({'status':'not_provided'},'invalid_structure')])
def test_missing_empty_and_invalid_summaries(summary,expected):
    p=b.extract('sample.ps1');response={'items':[]}
    if summary!='ABSENT':response['summary']=summary
    b.interpret(p,Fake(response));result=c.build(p)
    assert result['original_provenance']['review_diagnostics']['summary']['state']==expected
    assert result['original_provenance']['classification_origins']['summary']=='deterministic_synthesis'
    assert 'sample.ps1' in result['document']['summary']['text']
    assert 'not an AI conclusion' in c.render(result)


@pytest.mark.parametrize('text,source,state',[
    ('Reported sample.ps1','unknown','failed_source_validation'),
    ('invented.exe executed','valid','accepted'),
    ('Event ID 1121 proves execution','valid','accepted')])
def test_summary_rejections_never_leak_into_fallback(text,source,state):
    p=b.extract('Reported sample.ps1 and Event ID 1121.')
    b.interpret(p,Fake({'items':[],'summary':{'text':text,'source_ids':[p['source_units'][0]['id']] if source=='valid' else ['unknown'], 'uncertainty':'Unverified'}}))
    result=c.build(p)
    assert result['original_provenance']['review_diagnostics']['summary']['state']==state
    if source=='valid':
        assert p['proposed_summary']['narrative_review']
        assert text in result['document']['summary']['text']
    else:assert result['original_provenance']['summary_editorial']['source_validation']['status']=='unresolved_references'
    assert not any('invented.exe' in str(v) for v in p['leads'])


def test_good_summary_person_support_and_no_fallback():
    p=b.extract('Callie Wade attempted to print on BWP-8292456.')
    v=candidate(p,'person','Callie Wade');v['description']='User Callie Wade'
    b.interpret(p,Fake({'items':[],'candidates':[v],'summary':{'text':'Callie Wade reported a printing attempt on BWP-8292456.','source_ids':[p['source_units'][0]['id']], 'uncertainty':'Unverified'}}))
    assert p['summary_diagnostic']['state']=='accepted',p.get('ai_error')
    result=c.build(p);assert result['original_provenance']['classification_origins']['summary']=='ai_summary'
    del p['proposed_summary']
    assert summary_diagnostic(p)['state']=='lost_before_assembly'


def test_structural_candidate_failure_does_not_blame_valid_summary():
    p=b.extract('Callie Wade attempted to print.');v=candidate(p,'person','Callie Wade');v['source_ids']=[]
    b.interpret(p,Fake({'items':[],'candidates':[v],'summary':{'text':'Reported printing attempt.','source_ids':[p['source_units'][0]['id']], 'uncertainty':'Unverified'}}))
    assert p['summary_diagnostic']['state']=='response_invalid_structure'
    assert p['ai_error']['rejected_items'][0]['stage']=='structured_validation'
    assert p['ai_error']['rejected_items'][0]['source_references']=='not_evaluated'


def test_unknown_subjects_not_guessed_and_origin_not_missing():
    for statement,label in [('Timezone is unknown.','Timezone'),('Account is unknown.','Account'),('Details unclear.','Unspecified information')]:
        item=entry(statement,'unknown','unknown')
        assert unknown_label(item)==label
        doc=c.empty();doc['categories']['when']=[item]
        assert 'Unknown: Unknown' not in c.render({'document':doc})
    p=interpret('example.org',kind='domain',literal='example.org',description='Reported domain',category='origin')
    result=c.build(p);text=c.render(result)
    assert 'Related information represented under Origin; duplication is not required.' in text


def test_fallback_bounds_polarity_conflict_and_no_causal_inference():
    doc=c.empty();doc['categories']['activity']=[entry('A'*900,'activity'),entry('B'*900,'activity','conflicting')]
    doc['categories']['activity'][0]['polarity']='negated'
    from forensic_assistant.briefing_completion import synthesize
    fallback=synthesize(doc,c.CATEGORIES)
    assert len(fallback['document']['text'])<=1200 and len(fallback['document']['statement'])<=2000
    assert '[provided; negated]' in fallback['document']['text']
    assert 'Included 1 of 2' in fallback['document']['text']
    assert 'No sequence or causation inferred' in fallback['document']['text']
    assert fallback['references']['entries']==['activity:0']
    assert synthesize(c.empty(),c.CATEGORIES) is None


def test_saved_narrative_fallback_acceptance_and_history(store):
    from forensic_assistant import briefing_cli as cli
    before=store.case.read_bytes()
    original=store.save(content(dict.fromkeys(FIELDS,''),NARRATIVE),None)['revisions'][0]
    a=args(store,'--analyze','--deterministic');a._confirm=lambda _:'accept'
    packet=cli.run(a);canonical=packet['canonical']
    assert 'Original analyst narrative retained' in c.render(canonical)
    assert canonical['original_provenance']['classification_origins']['summary']=='deterministic_synthesis'
    state=store.load();assert state['revisions'][0]==original
    assert state['revisions'][-1]['content']['narrative']==NARRATIVE
    assert store.case.read_bytes()==before
    assert len(state['revisions'])==2


def test_historical_rejected_summary_not_replaced():
    doc=c.empty();doc['categories']['files']=[entry()]
    doc['summary']={'text':'','statement':'','status':'rejected'}
    p=b.extract('sample.ps1');p['accepted_canonical']=doc
    assert c.build(p)['document']['summary']==doc['summary']


def test_summary_response_limit_and_parse_diagnostics():
    p=b.extract('sample.ps1');fake=Fake({})
    fake.complete=lambda *a:'x'*16385
    b.interpret(p,fake)
    assert p['ai_error']['rule']=='response_size_limit'
    assert summary_diagnostic(p)['state']=='response_unavailable'

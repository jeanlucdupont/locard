"""6.82 fake-provider semantic extraction; synthetic statements, no live calls."""
import json
import pytest
from forensic_assistant import briefing as b
from forensic_assistant.briefing_semantics import technical
from forensic_assistant.briefing_report import render
from forensic_assistant.ai.openai_schema import request_schema,response
from test_briefing import Fake, START, END


def candidate(packet,kind,literal,**extra):
    return dict(type=kind,literal=literal,source_ids=[u['id'] for u in packet['source_units']],
                description='Unverified analyst reference',polarity='reported',
                uncertainty='Requires evidence review',**extra)


def analyze(text,kind,literal):
    packet=b.extract(text);fake=Fake({'items':[],'candidates':[candidate(packet,kind,literal)]})
    b.interpret(packet,fake)
    assert len(fake.calls)==1
    return packet


@pytest.mark.parametrize('kind,literal',[
 ('person','Callie Wade'),('account',r'CONTOSO\cwade'),('hostname','BWP-8292456'),
 ('filename','free printable five crowns score sheet pdf.zip'),
 ('filename','qon[1].wsc'),('windows_path',r'C:\ProgramData\baje.ps1'),
 ('domain','example.org'),('ipv4','192.0.2.1'),('ipv6','2001:db8::1'),
 ('hash','a'*64),('date','September 30, 2026'),('ambiguous_time','9:30 AM'),
 ('timezone','CST'),('timestamp','2026-09-30T09:30:00Z'),('event_id','1121'),
 ('activity','PowerShell through WMI'),('alert','Defender block'),
 ('origin','downloaded using Edge'),('objective','establish whether execution occurred'),
 ('unknown','timezone unknown'),('relationship','shortcut might have launched PowerShell')])
def test_source_supported_typed_candidates(kind,literal):
    p=analyze('Analyst reported "'+literal+'".',kind,literal)
    assert p['ai_status']=='success'
    c=p['ai_candidates'][0]
    assert c['literal']==literal and c['semantic_entailment']=='not_verified'
    for o in c['occurrences']:assert p['inputs'][o['source']][o['start']:o['end']]==literal
    assert c['origin']=='ai_semantic_classification'
    if kind in ('person','activity','objective','unknown','relationship','origin','alert'):
        assert 'lead_id' not in c


@pytest.mark.parametrize('kind,value',[('hostname','invented-host'),('filename','invented.exe'),('ipv4','203.0.113.9')])
def test_invented_values_rejected(kind,value):
    p=analyze('No concrete indicator supplied.',kind,value)
    assert p['ai_candidates']==[] and p['ai_status']=='failed'
    assert p['ai_error']['rejected_items'][0]['rule']=='unsupported_candidate_literal'
    assert not p.get('discovery')


@pytest.mark.parametrize('kind,value',[('ipv4','999.1.2.3'),('ipv6','9:30'),('hash','abc'),
 ('hostname','per-user'),('domain','bad..org'),('windows_path','not a path'),
 ('filename','bad/name.zip'),('date','2026-99-30'),('ambiguous_time','29:99'),('event_id','999999')])
def test_invalid_source_literal_rejected(kind,value):
    p=analyze(value,kind,value)
    assert not p['ai_candidates'] and p['ai_error']['rejected_items'][0]['rule']=='invalid_technical_value'


def test_no_speculative_people_or_bare_hosts_without_ai():
    p=b.extract('Callie Wade tried to print. BWP-8292456 used a per-user type-library follow-on mechanism.')
    assert not [l for l in p['leads'] if l['type'] in ('username','hostname')]
    assert p['semantic_coverage']=='limited_deterministic_technical_only'
    assert 'reduced semantic coverage' in render(p)


def test_exact_value_not_model_normalization_and_no_offsets():
    p=b.extract('Sample.PS1')
    c=candidate(p,'filename','Sample.PS1');c['start']=0
    b.interpret(p,Fake({'items':[],'candidates':[c]}))
    assert p['ai_status']=='failed' and not p['ai_candidates']
    p=analyze('Sample.PS1','filename','Sample.PS1')
    assert p['ai_candidates'][0]['normalized']=='sample.ps1'


def test_contiguous_units_but_not_disjoint_sources():
    text='x'*250+'long file name.zip';p=b.extract(text)
    # Prefix needs a token boundary.
    text='x'*249+' '+text[250:];p=b.extract(text)
    c=candidate(p,'filename','long file name.zip')
    b.interpret(p,Fake({'items':[],'candidates':[c]}))
    assert p['ai_candidates'][0]['occurrences'][0]['start']==250
    p=b.extract('long file', [' name.zip']);c=candidate(p,'filename','long file name.zip')
    b.interpret(p,Fake({'items':[],'candidates':[c]}))
    assert not p['ai_candidates']


def test_unknown_sources_duplicates_conflicts_and_search_gate():
    p=b.extract('host-x.\nNot host-x.')
    first=candidate(p,'hostname','host-x')
    second={**first,'polarity':'negated'}
    third={**first,'source_ids':['S-invented']}
    b.interpret(p,Fake({'items':[],'candidates':[first,second,third]}))
    assert p['ai_status']=='partial' and len(p['ai_candidates'])==2
    assert p['ai_error']['rejected_items'][0]['rule']=='unknown_source_id'
    assert all(b.query_for(l,'evtx',START,END) is None for l in p['leads'] if l['type']=='hostname')


def test_candidate_does_not_authorize_retrieval():
    p=analyze('Reported "host-x"','hostname','host-x')
    lead=p['leads'][-1]
    assert b.query_for(lead,'evtx',START,END)['hostname']=='host-x'
    assert 'discovery' not in p
    with pytest.raises(ValueError,match='Approve'):b.discover(p,'unused',[],'evtx',START,END)
    with pytest.raises(ValueError,match='Unknown approved'):b.discover(p,'unused',['L-forged'],'evtx',START,END)


def test_provider_failure_preserves_technical_fallback():
    class Broken:
        provider_name='local'
        def complete(self,*args):raise TimeoutError()
    p=b.extract('sample.ps1');before=json.dumps(p['leads'])
    b.interpret(p,Broken())
    assert json.dumps(p['leads'])==before and not p['ai_candidates']
    assert p['ai_error']['category']=='provider_transport'


def test_openai_optional_candidates_decode_and_canonical_unique():
    wire=request_schema('openai',b.SCHEMA)
    assert 'uniqueItems' not in json.dumps(wire)
    assert json.loads(response('openai',json.dumps({'items':[],'candidates':None,'summary':None}),b.SCHEMA))=={'items':[]}
    p=b.extract('sample.ps1');c=candidate(p,'filename','sample.ps1')
    from forensic_assistant.ai.provider_diagnostics import ProviderFailure
    with pytest.raises(ProviderFailure):response('openai',json.dumps({'items':[],'candidates':[c,c]}),b.SCHEMA)


def test_partial_filename_in_quote_is_rejected():
    p=analyze('Reported "long file name.zip"','filename','name.zip')
    assert not p['ai_candidates']
    assert p['ai_error']['rejected_items'][0]['rule']=='incomplete_candidate_literal'


def test_generic_hypothesis_need_not_be_verbatim():
    from test_briefing import item
    text='A suspicious shortcut was reported.';p=b.extract(text)
    i=item(text);i['text']='Persistence is a possibility to investigate.'
    b.interpret(p,Fake({'items':[i],'candidates':[]}))
    assert p['ai_items'] and p['ai_status']=='success'


def test_interview_regression_one_response_no_case_data():
    # Synthetic recreation of the supplied categories, not a copied case file.
    text=('Callie Wade tried to print on September 30, 2026 around 9:30 AM. '
          'Computer BWP-8292456. A download from unitednetsolutions.org using Edge '
          'was called "free printable five crowns score sheet pdf.zip". '
          'A shortcut "free printable five crowns score sheet pdf.lnk" and qon[1].wsc '
          'were reported with a per-user COM type-library hijack and follow-on activity. '
          'Reported path C:\\ProgramData\\baje.ps1. Defender ASR block. '
          'We want to determine whether execution and persistence occurred. Timezone unknown.')
    p=b.extract(text)
    requested=[('person','Callie Wade'),('hostname','BWP-8292456'),
               ('filename','free printable five crowns score sheet pdf.zip'),
               ('filename','free printable five crowns score sheet pdf.lnk'),
               ('filename','qon[1].wsc'),('windows_path',r'C:\ProgramData\baje.ps1'),
               ('date','September 30, 2026'),('ambiguous_time','9:30 AM'),
               ('origin','download from unitednetsolutions.org using Edge'),
               ('alert','Defender ASR block'),
               ('objective','determine whether execution and persistence occurred'),
               ('unknown','Timezone unknown')]
    result={'items':[],'candidates':[candidate(p,k,v) for k,v in requested]}
    fake=Fake(result);b.interpret(p,fake)
    assert len(fake.calls)==1 and p['ai_status']=='success'
    assert len(p['ai_candidates'])==len(requested)
    assert not {l['normalized'] for l in p['leads']}&{'per-user','type-library','follow-on','tried to','COM type'}
    assert 'People' in render(p) and 'Unresolved' in render(p)
    assert 'S-O-' not in render(p)
    assert p['metrics']['ai_output_bytes']<16384
    assert p['metrics']['ai_input_bytes']<=5600
    assert p['ai_source_coverage']['complete']
    assert 'discovery' not in p


def test_duplicate_classification_merges_provenance_and_conflict_stays():
    p=b.extract('sample.ps1', ['sample.ps1'])
    a=candidate(p,'filename','sample.ps1');a['source_ids']=[p['source_units'][0]['id']]
    other={**a,'source_ids':[p['source_units'][1]['id']],'description':'Another unverified report'}
    b.interpret(p,Fake({'items':[],'candidates':[a,other]}))
    assert len(p['ai_candidates'])==1 and len(p['ai_candidates'][0]['occurrences'])==2
    assert len(p['ai_candidates'][0]['source_ids'])==2


def test_long_structurally_valid_response_respects_existing_output_bound():
    # No silent slicing to fit a budget: a local response above 16 KiB fails.
    p=b.extract('x'*500)
    candidates=[{**candidate(p,'activity','x'*500),'description':str(i)+'a'*297,'uncertainty':'u'*300} for i in range(24)]
    raw=json.dumps({'items':[],'candidates':candidates})
    assert len(raw.encode())>16384
    b.interpret(p,Fake({'items':[],'candidates':candidates}))
    assert p['ai_status']=='failed' and p['ai_error']['category']=='response_parsing'
    assert not p['ai_candidates']


def test_saved_revision_kept_and_no_model_after_each_answer():
    from test_briefing_interview import run,finish
    result,fake,metrics=run(['An analyst narrative.','done','save'],[finish()])
    assert len(fake.calls)==1
    assert 'candidates' not in fake.calls[0][1]['properties']
    assert result['interviews'][0]['turns'][0]['answer']=='An analyst narrative.'

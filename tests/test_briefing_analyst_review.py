"""6.86 amended contract: AI proposes, analyst decides, evidence verifies."""
import copy
import json
import pytest
from forensic_assistant import briefing as b,briefing_canonical as c
from forensic_assistant.briefing_store import FIELDS,content,sources
from test_briefing import Fake,START,END
from test_briefing_semantics import candidate
from test_briefing_persistence import store,args

SOURCE='Callie Wade tried to print a PDF worksheet.\n\nThe computer was a Dell laptop named BWP-8292456.'


@pytest.mark.parametrize('kind,literal,description',[
 ('person','Callie Wade','Reported person who attempted printing.'),
 ('person','Callie Wade','User Callie Wade'),
 ('hostname','BWP-8292456','Reported name of the Dell laptop involved in the incident.'),
 ('hostname','BWP-8292456','Reported hostname of the system used by Callie Wade.'),
 ('hostname','BWP-8292456','The affected computer is BWP-8292456.')])
def test_explanatory_paraphrases_keep_exact_values(kind,literal,description):
 p=b.extract(SOURCE);v=candidate(p,kind,literal);v['description']=description
 b.interpret(p,Fake({'items':[],'candidates':[v]}))
 assert p['ai_status']=='success'
 assert p['ai_candidates'][0]['literal']==literal
 assert p['ai_candidates'][0]['semantic_entailment']=='not_verified'
 for occurrence in p['ai_candidates'][0]['occurrences']:
  assert p['inputs'][occurrence['source']][occurrence['start']:occurrence['end']]==literal


@pytest.mark.parametrize('kind,literal',[
 ('person','Jane Invented'),('hostname','invented-999'),('filename','invented.exe'),
 ('windows_path',r'C:\invented\payload.exe'),('ipv4','203.0.113.9'),
 ('ipv6','2001:db8::99'),('domain','invented.example'),('hash','f'*64),
 ('registry_path',r'HKCU\Software\Invented'),('event_id','9999'),
 ('timestamp','2026-09-30T09:30:01Z'),('account',r'LAB\cwade')])
def test_unsupported_concrete_values_visible_but_quarantined(kind,literal):
 p=b.extract('An analyst described printing.');v=candidate(p,kind,literal)
 b.interpret(p,Fake({'items':[],'candidates':[v]}))
 assert not p['ai_candidates']
 assert not p['leads']
 assert p['candidate_review'][0]['search_eligible'] is False
 result=c.build(p);assert literal in c.render(result)
 assert 'Excluded suggestion' in c.render(result)
 assert all(not items for items in result['document']['categories'].values())
 assert 'discovery' not in p


def test_description_and_summary_identifiers_never_become_search_inputs(store):
 p=b.extract(SOURCE);v=candidate(p,'person','Callie Wade',category='account')
 v['description']='Authenticated account LAB\\cwade on invented-999 executed malware.exe.'
 summary='Host invented-999 executed malware.exe and caused the compromise.'
 b.interpret(p,Fake({'items':[],'candidates':[v],'summary':{'text':summary,
  'source_ids':[u['id'] for u in p['source_units']],'uncertainty':'Unverified draft'}}))
 assert p['ai_candidates'][0]['category']=='account'  # category cannot change type
 assert p['ai_candidates'][0]['type']=='person'
 assert p['ai_candidates'][0]['narrative_review']
 assert p['proposed_summary']['narrative_review']
 result=c.build(p);assert 'malware.exe' in c.render(result)
 accepted=c.review(result,lambda _:'accept')
 state=store.save({**content(dict.fromkeys(FIELDS,''),SOURCE),'canonical':accepted},None)
 new=b.extract_inputs(sources(state['revisions'][-1]))
 for packet in (p,new):
  assert not any(any(x in str(lead) for x in ('malware.exe','invented-999','cwade')) for lead in packet['leads'])
 assert accepted['verification']=='UNVERIFIED ANALYST INPUT'
 assert accepted['original_provenance']['classification_origins']['account:0']=='ai_classification'


def test_summary_multisource_synthesis_and_invalid_source_separate():
 p=b.extract(SOURCE);summary={'text':'Callie Wade reportedly attempted printing. The reported laptop is BWP-8292456; the relationship remains unverified.',
  'source_ids':[u['id'] for u in p['source_units']],'uncertainty':'Analyst review required'}
 b.interpret(p,Fake({'items':[],'summary':summary}))
 assert p['summary_diagnostic']['state']=='accepted'
 assert p['proposed_summary']['text']==summary['text']
 p=b.extract(SOURCE);summary['source_ids']=['invented-ref']
 b.interpret(p,Fake({'items':[],'summary':summary}))
 assert p['summary_diagnostic']['state']=='failed_source_validation'
 assert 'proposed_summary' not in p
 assert p['summary_review']['search_eligible'] is False
 assert 'Excluded AI summary' in c.render(c.build(p))


def test_category_move_reject_and_revision_preserve_original(store):
 original=store.save(content(dict.fromkeys(FIELDS,''),'Defender blocked activity.'),None)['revisions'][0]
 p=b.extract('Defender blocked activity.');v=candidate(p,'alert','Defender blocked activity',category='response')
 b.interpret(p,Fake({'items':[],'candidates':[v]}));proposal=c.build(p)
 assert proposal['document']['categories']['response']
 choices=iter(['move','response','1','alerts','reject','alerts','1','reject-summary','accept'])
 accepted=c.review(proposal,lambda _:next(choices))
 assert not accepted['document']['categories']['alerts']
 assert 'alerts:0' not in accepted['original_provenance']['references']
 assert 'alerts:0' not in accepted['original_provenance']['classification_origins']
 value=copy.deepcopy(original['content']);value['canonical']=accepted
 state=store.save(value,original['digest']);assert state['revisions'][0]==original
 assert state['revisions'][-1]['content']['narrative']=='Defender blocked activity.'


def test_excluded_values_cannot_enter_accepted_sources_and_can_be_dismissed(store):
 p=b.extract('A printing report.');v=candidate(p,'hostname','invented-999')
 b.interpret(p,Fake({'items':[],'candidates':[v]}));proposal=c.build(p)
 accepted=c.review(proposal,lambda _:'accept')
 assert accepted['original_provenance']['excluded_suggestions'][0]['search_eligible'] is False
 state=store.save({**content(dict.fromkeys(FIELDS,''),'A printing report.'),'canonical':accepted},None)
 assert not sources(state['revisions'][-1])
 choices=iter(['reject','excluded','1','accept'])
 dismissed=c.review(proposal,lambda _:next(choices))
 assert dismissed['original_provenance']['excluded_suggestions'][0]['dismissed']
 assert 'Excluded suggestion' not in c.render({**dismissed,'accepted':True})


def test_fallback_readable_clauses_without_inferred_relationship():
 p=b.extract(SOURCE);values=[candidate(p,'person','Callie Wade'),
  candidate(p,'hostname','BWP-8292456'),candidate(p,'activity','tried to print a PDF worksheet',category='user_experience')]
 b.interpret(p,Fake({'items':[],'candidates':values}))
 proposal=c.build(p);text=proposal['document']['summary']['text']
 assert 'The briefing names: "Callie Wade"' in text
 assert 'The reported user experience is:' in text
 assert 'No sequence or causation inferred' in text
 assert len(text)<=1200
 assert 'search' not in proposal

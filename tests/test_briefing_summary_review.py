"""6.88 editorial approval is neither provenance validation nor evidence authority."""
import copy
import json
import pytest
from forensic_assistant import briefing as b,briefing_canonical as c,briefing_cli as cli
from forensic_assistant.briefing_store import content,FIELDS,sources
from forensic_assistant.briefing_summary_review import export_document,import_document,exchange_schema
from test_briefing import Fake
from test_briefing_semantics import candidate
from test_briefing_persistence import store,args


def make(refs='valid',text='Reported printing activity; outcome unverified.'):
 p=b.extract('An analyst reported printing activity.')
 summary={'text':text,'uncertainty':'Analyst review required'}
 if refs=='valid':summary['source_ids']=[p['source_units'][0]['id']]
 elif refs!='missing':summary['source_ids']=refs
 b.interpret(p,Fake({'items':[],'summary':summary}))
 return p,c.build(p)


def read(values):
 iterator=iter(values)
 return lambda _:next(iterator)


@pytest.mark.parametrize('refs,status',[
 ('valid','validated_references'),(['made-up-id'],'unresolved_references'),
 ('missing','missing_references'),([],'missing_references')])
def test_draft_priority_and_reference_status(refs,status):
 p,proposal=make(refs)
 assert proposal['document']['summary']['text'].startswith('Reported printing')
 review=proposal['original_provenance']['summary_editorial']
 assert review['source_validation']['status']==status
 assert review['decision']=='pending'
 assert proposal['original_provenance']['classification_origins']['summary']=='ai_summary'
 if status!='validated_references':
  assert 'source_ids' not in proposal['original_provenance']['references']['summary']
  assert 'not fully validated' in c.render(proposal)
 else:assert p['proposed_summary']['source_ids']==[p['source_units'][0]['id']]


def test_known_but_unexposed_reference_is_distinguished():
 p=b.extract('Printing activity. '+('extra context '*2000))
 sid=p['source_units'][-1]['id']
 b.interpret(p,Fake({'items':[],'summary':{'text':'Unverified draft.', 'uncertainty':'Unknown outcome','source_ids':[sid]}}))
 assert p['summary_editorial']['source_validation']['references']==[{'id':sid,'status':'not_exposed'}]
 assert not p['ai_source_coverage']['complete']


@pytest.mark.parametrize('refs',[None,'wrong-type',[5],['duplicate','duplicate']])
def test_malformed_reference_structure_remains_rejected(refs):
 p,_=make(refs)
 assert p['ai_error']['category']=='structural_validation'
 assert not p.get('summary_editorial')


def test_unresolved_requires_ack_and_decline_has_no_acceptance(store):
 _,proposal=make(['made-up-id'])
 assert c.review(proposal,read(['accept','n','finish'])) is None
 assert store.load() is None
 accepted=c.review(proposal,read(['accept-summary','y','accept']))
 review=accepted['original_provenance']['summary_editorial']
 assert review['decision']=='accepted' and review['acknowledged_unvalidated']
 assert review['source_validation']['references'][0]['status']=='unknown_source_id'
 assert accepted['document']['summary']['status']=='accepted'
 assert accepted['verification']=='UNVERIFIED ANALYST INPUT'
 assert 'source_ids' not in accepted['original_provenance']['references']['summary']
 assert proposal['original_provenance']['summary_editorial']['decision']=='pending'


def test_valid_draft_accepts_without_provenance_ack():
 _,proposal=make()
 accepted=c.review(proposal,read(['accept']))
 assert accepted['original_provenance']['summary_editorial']['decision']=='accepted'
 assert not accepted['original_provenance']['summary_editorial']['acknowledged_unvalidated']


def test_correction_preserves_original_draft_reference_failure_and_history(store):
 raw=store.case.read_bytes();original=content(dict.fromkeys(FIELDS,''),'Original analyst narrative')
 first=store.save(original,None)['revisions'][0]
 _,proposal=make(['bad-ref'])
 accepted=c.review(proposal,read(['correct','summary','Corrected analyst account.','accept','y']))
 review=accepted['original_provenance']['summary_editorial']
 assert review['original_draft']['text']=='Reported printing activity; outcome unverified.'
 assert review['edited_text']=='Corrected analyst account.'
 assert review['source_validation']['status']=='unresolved_references'
 assert accepted['original_provenance']['classification_origins']['summary']=='analyst_summary'
 state=store.save({**original,'canonical':accepted},first['digest'])
 assert state['revisions'][0]==first
 assert state['revisions'][-1]['content']['narrative']=='Original analyst narrative'
 assert store.case.read_bytes()==raw


@pytest.mark.parametrize('choice,decision,status',[
 ('reject-summary','rejected','rejected'),('omit-summary','omitted','not_provided')])
def test_reject_or_continue_without_summary_retains_draft(choice,decision,status):
 _,proposal=make(['bad-ref'])
 accepted=c.review(proposal,read([choice,'accept']))
 assert accepted['document']['summary']['status']==status
 assert accepted['original_provenance']['summary_editorial']['decision']==decision
 assert accepted['original_provenance']['summary_editorial']['original_draft']['source_ids']==['bad-ref']


def test_summary_invented_identifiers_never_supply_sources_or_searches(store):
 p,proposal=make(['bad-ref'],'Invented host phantom-999 executed invented.exe.')
 accepted=c.review(proposal,read(['accept','y']))
 state=store.save({**content(dict.fromkeys(FIELDS,''),'Printing report.'),'canonical':accepted},None)
 assert not sources(state['revisions'][-1])
 assert not p['leads'] and 'discovery' not in p
 result=cli.run(args(store,'--analyze','--deterministic'))
 assert result['kind']=='saved_briefing'
 assert 'forensic_verification' in accepted['original_provenance']['summary_editorial']


def test_add_missing_objective_with_summary_approval():
 _,proposal=make(['bad-ref'])
 accepted=c.review(proposal,read(['add','objectives','provided','objective','Determine delivery.','accept','y']))
 assert accepted['document']['categories']['objectives'][0]['value']=='Determine delivery.'
 assert accepted['original_provenance']['classification_origins']['objectives:0']=='analyst_addition'


def test_v2_portable_review_metadata_cannot_certify_imported_provenance():
 _,proposal=make()
 accepted=c.review(proposal,read(['accept']))
 exported=export_document(accepted['document'],accepted['original_provenance'])
 assert exported['format']==2
 assert exported['summary_review']['source_status']=='validated_references'
 c.validate_document(exported,exchange_schema())
 document,metadata=import_document(exported)
 assert document==accepted['document']
 review=metadata['summary_editorial']
 assert review['source_validation']['status']=='not_validated_import'
 assert not review['acknowledged_unvalidated']
 assert review['imported_source_status']=='validated_references'
 assert review['source_validation']['references']==[]


def test_v2_import_requires_fresh_ack_even_if_file_claims_prior_ack(store,tmp_path):
 _,proposal=make(['bad-ref']);accepted=c.review(proposal,read(['accept','y']))
 exported=export_document(accepted['document'],accepted['original_provenance'])
 path=tmp_path/'review.json';path.write_text(json.dumps(exported),encoding='utf-8')
 a=args(store,'--import-json',str(path));a._confirm=read(['y','n'])
 cli.run(a);assert store.load() is None
 a._confirm=read(['y','y']);cli.run(a)
 review=store.load()['revisions'][-1]['content']['canonical']['original_provenance']['summary_editorial']
 assert review['source_validation']['status']=='not_validated_import'
 assert review['imported_source_status']=='unresolved_references'
 assert review['acknowledged_unvalidated']


def test_legacy_json_and_saved_envelopes_unchanged():
 document=c.empty();envelope=c.envelope(document)
 assert c.check_envelope(envelope)==envelope
 assert export_document(document,{})==document
 assert import_document(document)==(document,{})


def test_openai_missing_summary_refs_decode_to_review_only():
 from forensic_assistant.ai.openai_schema import response
 p=b.extract('Printing report.')
 wire={'items':[],'candidates':None,'summary':{'text':'A printing report.','uncertainty':'Unverified','source_ids':None}}
 decoded=response('openai',json.dumps(wire),b.SCHEMA)
 fake=Fake({});fake.complete=lambda *a:decoded
 b.interpret(p,fake)
 assert p['summary_editorial']['source_validation']['status']=='missing_references'
 assert 'proposed_summary' not in p


def test_provider_failure_does_not_create_editorial_approval():
 class Broken:
  provider_name='local'
  def complete(self,*a):raise TimeoutError()
 p=b.extract('Printing report.');b.interpret(p,Broken())
 assert p['ai_error']['category']=='provider_transport'
 assert not p.get('summary_editorial')



def test_v2_file_exchange_roundtrip_preserves_limitation(store,tmp_path):
 _,proposal=make(['bad-ref']);accepted=c.review(proposal,read(['accept','y']))
 first=store.save({**content(dict.fromkeys(FIELDS,''),'Original narrative'),'canonical':accepted},None)['revisions'][0]
 output=tmp_path/'review-export.json';cli.run(args(store,'--export-json',str(output)))
 wire=json.loads(output.read_text(encoding='utf-8'))
 assert wire['format']==2 and wire['summary_review']['source_status']=='unresolved_references'
 a=args(store,'--import-json',str(output));a._confirm=read(['y','y']);cli.run(a)
 state=store.load();assert state['revisions'][0]==first
 review=state['revisions'][-1]['content']['canonical']['original_provenance']['summary_editorial']
 assert review['source_validation']['status']=='not_validated_import'
 assert review['imported_source_status']=='unresolved_references'
 assert not sources(state['revisions'][-1])



def test_approved_summary_presentation_keeps_limit_without_failure_message():
 from forensic_assistant.briefing_report import render
 p,proposal=make(['bad-ref']);accepted=c.review(proposal,read(['accept','y']))
 p['canonical']={**accepted,'accepted':True}
 text=render(p)
 assert 'Analyst-approved briefing summary' in text
 assert 'editorial approval does not validate references' in text
 assert 'AI interpretation failed:' not in text
 assert 'bad-ref' not in text

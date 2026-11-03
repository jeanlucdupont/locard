"""6.87 bounded presentation checks, fake providers only."""
import copy
import json
import pytest
from forensic_assistant import briefing as b,briefing_canonical as c,briefing_cli as cli
from forensic_assistant.briefing_store import content,FIELDS
from test_briefing import Fake
from test_briefing_semantics import candidate
from test_briefing_canonical import entry
from test_briefing_persistence import store,args


def summary_packet(text):
 p=b.extract('Analyst reported a printing attempt. Timezone unknown.')
 b.interpret(p,Fake({'items':[],'summary':{'text':text,'source_ids':[u['id'] for u in p['source_units']],'uncertainty':'Reported only; outcome unverified.'}}))
 return p


def test_boundary_draft_preserved_flagged_and_editable(store):
 text='Reported printing attempt. '+('x'*(700-len('Reported printing attempt. ')-8))+' and the'
 assert len(text.encode())==700
 p=summary_packet(text);proposal=c.build(p)
 assert p['proposed_summary']['text']==text
 assert p['summary_diagnostic']['completeness']=='possible_length_boundary_cutoff'
 rendered=c.render(proposal)
 assert 'Possibly incomplete AI draft at the summary length limit' in rendered
 assert text in rendered and '\nUncertainty:' in rendered
 original=store.save(content(dict.fromkeys(FIELDS,''),'Original analyst text'),None)['revisions'][0]
 accepted=c.review(proposal,lambda _:'accept')
 new=copy.deepcopy(original['content']);new['canonical']=accepted
 state=store.save(new,original['digest'])
 assert state['revisions'][0]==original
 assert accepted['document']['summary']['text']==text+'\nUncertainty: Reported only; outcome unverified.'
 choices=iter(['correct','summary','A shorter, qualified analyst draft.','accept'])
 corrected=c.review(proposal,lambda _:next(choices))
 assert corrected['document']['summary']['text']=='A shorter, qualified analyst draft.'
 assert 'Possibly incomplete AI draft' not in c.render(corrected)


@pytest.mark.parametrize('text',[
 'A reported printing attempt. The outcome remains unknown.',
 'x'*699+'.',
 'Reported path C:\\new\\notes.ps1.\nUncertainty remains.',
 r'Reported path C:\new\notes.ps1; literal \n is retained.'])
def test_complete_or_short_summary_unchanged(text):
 p=summary_packet(text)
 assert p['proposed_summary']['text']==text
 assert 'completeness' not in p['summary_diagnostic']
 assert text in c.render(c.build(p))


def test_over_limit_summary_omitted_not_clipped():
 p=summary_packet('x'*701)
 assert 'proposed_summary' not in p
 assert p['summary_diagnostic']['state']=='omitted_over_limit'
 assert p['summary_diagnostic']['rule']=='summary_size_limit'
 assert 'x'*700 not in c.render(c.build(p))
 assert p['inputs']['original']=='Analyst reported a printing attempt. Timezone unknown.'


@pytest.mark.parametrize('kind,literal,description',[
 ('person','Callie Wade','Reported user; not an authenticated account identity. Account identity is not supplied.'),
 ('hostname','BWP-8292456','Reported name of the Dell laptop. Device identity is not independently verified.')])
def test_weak_lexical_flags_details_only(kind,literal,description):
 p=b.extract('Callie Wade tried printing on BWP-8292456.')
 v=candidate(p,kind,literal);v['description']=description
 b.interpret(p,Fake({'items':[],'candidates':[v]}));proposal=c.build(p)
 assert p['ai_candidates'][0]['literal']==literal
 assert all(f.get('visibility')=='details' for f in p['ai_candidates'][0]['narrative_review'])
 assert 'Explanation review: possible_identifier_mismatch' not in c.render(proposal)
 assert 'possible_identifier_mismatch' in cli.render_details(p)
 assert 'discovery' not in p


@pytest.mark.parametrize('description',[
 'Host invented-999','Account LAB\\invented','username: intruder',
 'Reported invented.exe','Address 203.0.113.123','Domain invented.example',
 'Path C:\\invented\\payload.exe'])
def test_concrete_concerns_visible_but_no_search_leads(description):
 p=b.extract('Callie Wade tried printing.');v=candidate(p,'person','Callie Wade');v['description']=description
 b.interpret(p,Fake({'items':[],'candidates':[v]}));proposal=c.build(p)
 assert 'Explanation review: possible_identifier_mismatch' in c.render(proposal)
 assert not p['leads']
 assert p['ai_candidates'][0]['literal']=='Callie Wade'


def test_time_phrase_explained_without_changing_value_or_timezone():
 source='It happened around 9:30\nin the morning. Timezone unknown.'
 p=b.extract(source);v=candidate(p,'ambiguous_time','around 9:30\nin the morning',category='when')
 b.interpret(p,Fake({'items':[],'candidates':[v]}));proposal=c.build(p)
 before=json.dumps(p,sort_keys=True);rendered=c.render(proposal)
 assert 'its numeric time is already listed' in rendered
 assert 'invalid_technical_value' not in rendered
 assert 'AM/PM and timezone are not inferred' in rendered
 assert p['candidate_review'][0]['candidate']['literal']==v['literal']
 assert p['candidate_review'][0]['search_eligible'] is False
 assert p['candidate_review'][0]['diagnostic']['rule']=='invalid_technical_value'
 assert json.dumps(p,sort_keys=True)==before
 assert all(v.get('type')!='timestamp' for v in p['leads'])


def test_unsupported_time_not_presented_as_supported():
 p=b.extract('No time supplied.');v=candidate(p,'ambiguous_time','around 9:30 in the morning')
 b.interpret(p,Fake({'items':[],'candidates':[v]}))
 text=c.render(c.build(p));assert 'unsupported_candidate_literal' in text
 assert 'Source-supported time phrase' not in text


def test_summary_coverage_neutral_with_specific_literal_notice():
 doc=c.empty();doc['categories']['user_experience']=[entry('tried to print a worksheet','activity')]
 doc['categories']['objectives']=[entry('establish arrival and execution','objective')]
 doc['categories']['systems']=[entry('HOST-42','hostname')]
 doc['summary']={'text':'The analyst reports a printing attempt and wants to determine delivery and execution.', 'statement':'Source retained','status':'proposed'}
 text=c.render({'document':doc})
 assert 'check coverage of User experience' not in text
 assert 'check coverage of Investigation objectives' not in text
 assert 'semantic completeness is for the analyst to decide' in text
 assert 'possible omission of Systems' in text

"""6.81 synthetic extraction/readiness and exact answer-retention regressions."""
import pytest
from forensic_assistant import briefing as b, briefing_interview as interview
from test_briefing_interview import current, run, finish
from test_briefing_information import session
from test_briefing_persistence import store

START='2026-09-30T00:00:00Z'
END='2026-10-01T00:00:00Z'


def rows(text,kind):return [r for r in b.extract(text,semantic_hints=True)['leads'] if r['type']==kind]


@pytest.mark.parametrize('text,name',[
 ('Callie Wade tried to print a PDF.','Callie Wade'),
 ('The user Callie Wade reported an alert.','Callie Wade'),
 ('Anna Lopez received an alert.','Anna Lopez'),
 (r'Account CONTOSO\cwade was involved.',r'CONTOSO\cwade'),
 ('Username: analyst@example.org','analyst@example.org'),
 ('User: Alice','Alice')])
def test_positive_user_exact_spans(text,name):
    lead=rows(text,'username')[0]
    assert lead['normalized']==name
    assert lead['classification']==('exact' if '@' in name or '\\' in name else 'contextual')
    occurrence=lead['occurrences'][0]
    assert text[occurrence['start']:occurrence['end']]==name
    assert 'not an authenticated' in lead['uncertainty']
    assert b.query_for(lead,'evtx',START,END) is None


@pytest.mark.parametrize('text',[
 'a per-user COM type-library hijack','the user tried to print',
 'COM type library registration','per-user type-library follow-on',
 'user interaction occurred','Microsoft Defender reported an alert',
 'command-line process-creation read-only UTF-8 SHA-256'])
def test_prose_not_entities(text):
    assert not rows(text,'username') and not rows(text,'hostname')


@pytest.mark.parametrize('text,host',[
 ('BWP-8292456','bwp-8292456'),('FILE-SRV-01','file-srv-01'),
 ('workstation-7','workstation-7'),('Hostname: atlas.','atlas'),
 ('The computer was blue-bird.','blue-bird'),
 ('Host: atlas.example.org','atlas.example.org')])
def test_hosts(text,host):
    lead=rows(text,'hostname')[0]
    assert lead['normalized']==host
    assert b.query_for(lead,'evtx',START,END)['hostname']==host
    occurrence=lead['occurrences'][0]
    assert text[occurrence['start']:occurrence['end']]==occurrence['original']


@pytest.mark.parametrize('bad',['per-user','type-library','follow-on','foo..bar','-host','host-','999'])
def test_forged_bad_host_cannot_become_discovery(bad):
    lead=rows('Hostname: atlas','hostname')[0]
    lead['normalized']=bad;lead['occurrences'][0]['original']=bad
    assert b.query_for(lead,'evtx',START,END) is None


def test_unlabelled_ambiguous_host_not_exact_search():
    assert not rows('blue-bird','hostname')
    lead=rows('Hostname: atlas','hostname')[0];lead.pop('hostname_basis')
    assert b.query_for(lead,'evtx',START,END) is None


def test_reported_origin_objective_and_latest_response():
    s=session(('incident','Tell me what happened?',
               'Callie Wade downloaded a document from example.org using Edge. Defender showed an alert.'),
              ('alerts','What alert?',
               'We want to establish how it arrived, whether it executed and whether persistence exists.'))
    info=interview.information(current(),s)
    assert info['topics']['alerts']['state']=='supplied_hint'
    assert info['semantic_assessment']=='not_performed_by_deterministic_readiness'
    assert 'discovery' in info['search_anchor_gaps']
    assert 'objective' in info['search_anchor_gaps']
    assert s['turns'][1]['answer'].startswith('We want to establish')
    s['turns'][1]['answer']='The analyst is away.'
    assert 'objective' in interview.information(current(),s)['search_anchor_gaps']


def test_superseded_origin_not_reused():
    s=session(('incident','What happened?','Downloaded a document from example.org.'),
              ('incident','Correction','The origin is unknown.'))
    s['turns'][1]['supersedes']=1
    assert 'discovery' in interview.information(current(),s)['search_anchor_gaps']


@pytest.mark.parametrize('length',[399,400,401,2048])
def test_unicode_long_answer_exact_roundtrip(store,capsys,length):
    text='é'*length
    result,_,_=run([text,'done','full','save'],[finish()])
    assert result['interviews'][0]['turns'][0]['answer']==text
    store.save(result,None)
    assert store.load()['revisions'][-1]['content']==result
    output=capsys.readouterr().out
    assert text in output
    if length>400:assert '[shortened; type full to review]' in output


def test_over_bound_answer_rejected_not_truncated(capsys):
    result,_,_=run(['é'*2049,'Accepted complete response.','done','save'],[finish()])
    assert result['interviews'][0]['turns'][0]['answer']=='Accepted complete response.'
    assert 'Answer exceeds briefing bounds' in capsys.readouterr().out


def test_question_context_types_only_complete_analyst_answer():
    inputs={'answer':'atlas'}
    assert not b.extract_inputs(inputs)['leads']
    packet=b.extract_inputs(inputs,questions={'answer':"What is the computer's name?"})
    lead=packet['leads'][0]
    assert lead['normalized']=='atlas' and lead['occurrences'][0]['original']=='atlas'
    assert b.query_for(lead,'evtx',START,END)['hostname']=='atlas'
    for answer in ['per-user','unknown','it','the computer was broken','atlas; DROP TABLE x']:
        packet=b.extract_inputs({'answer':answer},questions={'answer':"What is the computer's name?"})
        assert not [r for r in packet['leads'] if r['type']=='hostname']
    packet=b.extract_inputs(inputs,questions={'answer':'Was invented-host the computer name?'})
    assert not packet['leads']


def test_question_context_persisted_sources(store):
    from forensic_assistant.briefing_store import sources
    from forensic_assistant.briefing_entities import source_questions
    c=current();c['interviews']=[session(('systems',"What is the computer's name?",'atlas'))]
    store.save(c,None);revision=store.load()['revisions'][-1]
    packet=b.extract_inputs(sources(revision),questions=source_questions(revision['content']))
    assert any(r['type']=='hostname' and r['normalized']=='atlas' for r in packet['leads'])


def test_terminal_window_does_not_shorten_accepted_text():
    import io
    from forensic_assistant.interactive.console import edit
    text='\u00e9'*500+' complete ending'
    assert edit([*text,'\r'],output=io.StringIO())==text
    with pytest.raises(ValueError,match='command discarded'):
        edit([*text,'\r'],output=io.StringIO(),limit=len(text)-1)

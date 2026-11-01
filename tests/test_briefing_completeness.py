"""6.84 synthetic reconstructions, not captured model output or live-quality tests."""
import copy
import json
import pytest
from forensic_assistant import briefing as b, briefing_canonical as c
from forensic_assistant.briefing_review import assess, CATEGORY_DEFINITIONS
from forensic_assistant.briefing_store import content, FIELDS
from test_briefing import Fake
from test_briefing_semantics import candidate
from test_briefing_canonical import entry
from test_briefing_persistence import store, args

# Reconstructed from the acceptance prompt's facts, not a verbatim case transcript.
NARRATIVE = (
    'Callie Wade attempted to print a PDF game worksheet on a Dell laptop BWP-8292456. '
    'September 30, 2026, approximately 09:30; timezone unknown. '
    'Reported download of free printable five crowns score sheet pdf.zip from unitednetsolutions.org using Microsoft Edge. '
    'Reported per-user COM TypeLib registry hijack; C:\\ProgramData\\baje.ps1, WMI launch and blocked by Defender. '
    'Reported Windows Script Component qon[1].wsc. Objectives: establish delivery, execution, and subsequent activity.'
)


def analyze(text, specs, summary=None):
    packet=b.extract(text)
    values=[candidate(packet, kind, literal, category=category, status=status)
            for kind,literal,category,status in specs]
    response={'items':[], 'candidates':values}
    if summary:response['summary']={'text':summary,'source_ids':[u['id'] for u in packet['source_units']], 'uncertainty':'Reported, not verified'}
    fake=Fake(response);b.interpret(packet,fake)
    assert len(fake.calls)==1
    return packet,c.build(packet)


def test_acceptance_reconstruction_and_proposed_category_retention():
    specs=[('person','Callie Wade','person','provided'),('hostname','BWP-8292456','systems','provided'),
        ('activity','attempted to print a PDF game worksheet','user_experience','provided'),
        ('timezone','timezone unknown','when','unknown'),
        ('alert','blocked by Defender','response','provided'),
        ('origin','download of free printable five crowns score sheet pdf.zip from unitednetsolutions.org using Microsoft Edge','origin','provided'),
        ('objective','establish delivery, execution, and subsequent activity','objectives','provided')]
    packet,result=analyze(NARRATIVE,specs,'Reported activity remains unverified.')
    assert packet['ai_status']=='success',packet.get('ai_error')
    assert packet['ai_source_coverage']['complete']
    doc=result['document'];assert doc['categories']['response'][0]['value']=='blocked by Defender'
    assert not doc['categories']['alerts']
    assert doc['categories']['origin'] and doc['categories']['user_experience']
    assert packet['inputs']['original']==NARRATIVE
    text=c.render(result)
    assert 'Timezone: Unknown' in text and '\\nUncertainty:' not in text
    assert 'Summary review: possible omission of Person.' in text
    assert 'Summary review: possible omission of Systems.' in text
    assert result['original_provenance']['review_diagnostics']['normalizations']==[]
    assert not packet.get('discovery')


@pytest.mark.parametrize('kind,literal,category',[
    ('alert','Defender blocked activity','alerts'),
    ('activity','SOC isolated laptop','response'),
    ('activity','user opened a document','user_actions'),
    ('domain','example.org','websites'),
    ('origin','download from email','origin')])
def test_correct_categories_preserved_without_invented_entries(kind,literal,category):
    packet,result=analyze(literal,[(kind,literal,category,'provided')])
    assert result['document']['categories'][category][0]['value']==literal
    assert result['original_provenance']['review_diagnostics']['normalizations']==[]
    if category=='websites':assert not result['document']['categories']['origin']
    if category=='response':assert not result['document']['categories']['alerts']


def test_ambiguous_product_activity_flagged_not_inferred():
    _,result=analyze('blocked by Defender',[('activity','blocked by Defender','response','provided')])
    assessment=assess(result['document'])
    assert not result['document']['categories']['alerts']
    assert assessment['categories']['alerts']['state']=='possible_classification_gap'


def test_rejected_candidate_and_sparse_coverage_are_distinct():
    packet,result=analyze('A sparse report.', [('alert','invented action','alerts','provided')])
    assert not packet['ai_candidates']
    report=assess(result['document'],result['original_provenance']['review_diagnostics'])
    assert report['categories']['alerts']['state']=='validation_rejected'
    assert report['categories']['alerts']['rejection_rules']==['unsupported_candidate_literal']
    assert report['categories']['person']['state']=='coverage_unknown'
    assert not result['document']['categories']['when']
    assert 'Candidate rejected during validation' in c.render(result)


def test_unknown_vs_absent_and_multiline_escaping():
    text='September 30, 2026, around 09:30.\nThe timezone is unknown.\n\nMore context.'
    packet,result=analyze(text,[('timezone','timezone is unknown','when','unknown')])
    rendered=c.render(result)
    assert 'Timezone: Unknown' in rendered and 'More context' not in rendered
    unknown=[v for v in result['document']['categories']['when'] if v['kind']=='timezone'][0]
    assert unknown['value']=='' and 'timezone is unknown' in unknown['statement']
    assert any(v['kind']=='date' for v in result['document']['categories']['when'])
    assert any(v['kind']=='ambiguous_time' and v['status']=='approximate' for v in result['document']['categories']['when'])
    doc=c.empty();path=r'C:\new\notes.ps1'
    doc['categories']['files']=[entry(path,'windows_path')]
    doc['summary']={'status':'proposed','text':'One line\nUncertainty: literal '+r'\n and '+path,'statement':'Source'}
    rendered=c.render({'document':doc})
    assert 'One line\nUncertainty:' in rendered
    assert r'literal \n and C:\new\notes.ps1' in rendered
    assert packet['inputs']['original']==text


def test_move_acceptance_preserves_derived_origin_and_revision(store):
    evidence_before=store.case.read_bytes()
    _,proposal=analyze('Reported action.', [('activity','Reported action','response','provided')])
    original=store.save(content(dict.fromkeys(FIELDS,''),'Original narrative'),None)['revisions'][0]
    choices=iter(['move','response','1','alerts','accept'])
    accepted=c.review(proposal,lambda _:next(choices))
    assert accepted['document']['categories']['alerts'][0]==proposal['document']['categories']['response'][0]
    metadata=accepted['original_provenance']
    assert metadata['classification_origins']['alerts:0']=='ai_classification'
    assert 'response:0' not in metadata['references']
    assert metadata['references']['alerts:0']==proposal['original_provenance']['references']['response:0']
    assert metadata['acceptance']=='accepted_for_use_not_verified'
    value=copy.deepcopy(original['content']);value['canonical']=accepted
    state=store.save(value,original['digest'])
    assert len(state['revisions'])==2 and state['revisions'][0]==original
    assert value['narrative']=='Original narrative'
    from forensic_assistant import briefing_cli as cli,briefing_workflow as workflow
    result=cli.run(args(store,'--analyze','--deterministic'))
    assert result['canonical']['original_provenance']['classification_origins']['alerts:0']=='ai_classification'
    assert 'ai_classification' in workflow.render(workflow.view(state))
    assert 'Accepted for use' in workflow.render(workflow.view(state))
    assert store.case.read_bytes()==evidence_before


def test_correction_changes_origin_without_forging_original_reference():
    _,proposal=analyze('Reported action.', [('activity','Reported action','response','provided')])
    choices=iter(['correct','response','1','provided','activity','Analyst correction','accept'])
    accepted=c.review(proposal,lambda _:next(choices))
    assert accepted['original_provenance']['classification_origins']['response:0']=='analyst_correction'
    assert 'response:0' not in accepted['original_provenance']['references']
    assert proposal['document']['categories']['response'][0]['value']=='Reported action'


def test_legacy_document_no_reinterpretation_and_definitions_complete():
    doc=c.empty();doc['categories']['response']=[entry('Defender block','alert')]
    envelope=c.envelope(doc);assert c.check_envelope(envelope)==envelope
    assert envelope['document']==doc and not envelope['original_provenance']
    packet=b.extract('Original report');packet['accepted_canonical']=doc
    result=c.build(packet)
    assert result['document']['categories']['response']==doc['categories']['response']
    assert not result['document']['categories']['alerts']
    assert set(CATEGORY_DEFINITIONS)==set(c.CATEGORIES)
    assert len(b.SYSTEM.encode())<=3296


@pytest.mark.parametrize('status,state',[
    ('unknown','explicit_unknown'),('not_provided','explicit_not_provided'),
    ('not_applicable','explicit_not_applicable')])
def test_explicit_missing_statuses_not_confused_with_extraction_gap(status,state):
    doc=c.empty();doc['categories']['when']=[entry('Analyst explicitly reports this status','timezone',status)]
    assert assess(doc)['categories']['when']['state']==state
    assert assess(doc)['categories']['person']['state']=='coverage_unknown'


def test_move_reindexes_references_and_keeps_input_immutable():
    from forensic_assistant.briefing_review import move_metadata
    metadata={'references':{'response:0':{'source_ids':['first']},'response:1':{'source_ids':['second']}},
              'classification_origins':{'response:0':'ai_classification','response:1':'analyst_addition'}}
    move_metadata(metadata,'response',0,'alerts',0)
    assert metadata['references']=={'response:0':{'source_ids':['second']},'alerts:0':{'source_ids':['first']}}
    assert metadata['classification_origins']=={'response:0':'analyst_addition','alerts:0':'ai_classification'}


def test_complete_summary_no_exact_entity_omission_warning():
    _,proposal=analyze('Callie Wade reported a laptop BWP-8292456.',
        [('person','Callie Wade','person','provided'),('hostname','BWP-8292456','systems','provided')],
        'Callie Wade reported a laptop BWP-8292456.')
    assert not [v for v in assess(proposal['document'])['summary_checks'] if v['rule']=='possible_summary_entity_omission']

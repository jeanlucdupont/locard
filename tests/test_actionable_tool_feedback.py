"""Scripted recovery is not real-model comprehension acceptance."""
import json
import pytest
from forensic_assistant.conversational_ai.tool_feedback import tool_feedback,SCALAR
from forensic_assistant.conversational_ai.operation_diagnostics import failure_detail,operation_trace
from forensic_assistant.conversational_ai.contracts import arguments,authorize,FAMILIES,catalog
from forensic_assistant.conversational_ai.service import Session,Paused
from forensic_assistant.conversational_ai.provider import ScriptedProvider
from test_conversational_ai import reply,call,last,setup


def test_synthetic_scalar_and_note_recovery(tmp_path,monkeypatch):
    from scripts.diagnose_investigative_memory import synthetic_case
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    path,sid,before=synthetic_case(tmp_path);seen={}
    def inspect(messages):
        seen['eid']=last(messages)['records'][0]['evidence_id']
        return reply(calls=[call('show_evidence',dict(evidence_id=seen['eid'],limit=40))])
    def bad_verify(messages):
        field=next(f for f in last(messages)['fields'] if f['field']=='/command_line')
        assert not field['truncated'] and not field['redacted']
        seen['value']=field['value']
        return reply(calls=[call('verify_observation',dict(evidence_id=seen['eid'],field='/command_line',value_json=json.dumps({'value':field['value'],'truncated':False,'redacted':False}),timestamp_meaning='SystemTime'))])
    def correct_verify(messages):
        value=last(messages)
        assert value['correction']==SCALAR and value['worker_reached'] and not value['result_accepted']
        assert seen['value'] not in value['correction']
        return reply(calls=[call('verify_observation',dict(evidence_id=seen['eid'],field='/command_line',value_json=json.dumps(seen['value'])))])
    def bad_note(messages):
        assert last(messages)['verified'] and last(messages)['timestamp_meaning'] is None
        return reply(calls=[call('note',dict(kind='open_question',status='active',text='What remains unknown?',supersedes=''))])
    def correct_note(messages):
        value=last(messages)
        assert value['parameter']=='request.supersedes' and 'Omit supersedes' in value['correction']
        assert not value['worker_reached']
        return reply(calls=[call('note',dict(kind='open_question',status='active',text='What remains unknown?'))])
    def memory(messages):
        assert last(messages)['note_id'] and last(messages)['unverified']
        return reply(calls=[call('memory',dict(kind='notes'))])
    provider=ScriptedProvider([reply(calls=[call('search_evidence',dict(artifact='evtx',limit=1))]),inspect,bad_verify,correct_verify,bad_note,correct_note,memory,reply('Synthetic assessment, not a model-quality claim.')])
    grant=authorize(path,[sid],'2020-01-01T00:00:00Z','2020-01-02T00:00:00Z',FAMILIES,'openai','scripted')
    session=Session(grant,provider,lambda _:True)
    try:result=session.submit('Synthetic inspection')
    finally:session.close()
    import hashlib
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before
    assert len(result['verified_observations'])==1 and session.worker.process.poll() is not None
    trace=operation_trace(session.journal.path)['operations']
    assert trace[2]['subsequent_operations'][0]['execution_outcome']=='succeeded'
    assert trace[4]['subsequent_operations'][0]['tool']=='note'
    assert trace[4]['feedback_sent_request'] is not None


def test_repeated_constraint_not_identical_arguments(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    def attempt(n):
        def step(messages):
            if n:assert 'Omit supersedes' in last(messages)['correction']
            return reply(calls=[call('note',dict(kind='open_question',status='active',text=f'Question {n}',supersedes=''))])
        return step
    path,provider,scope=setup(tmp_path,[attempt(i) for i in range(3)])
    session=Session(scope,provider,lambda _:True)
    try:
        with pytest.raises(Paused,match='REPEATED_TOOL_FAILURE'):session.submit('Synthetic')
    finally:session.close('REPEATED_TOOL_FAILURE')
    rows=operation_trace(session.journal.path)['operations']
    assert [r['exact_repeat'] for r in rows]==[False]*3
    assert [r['same_validation_error_recurred'] for r in rows]==[False,True,True]
    assert rows[-1]['feedback_sent_request'] is None and len(provider.calls)==3


@pytest.mark.parametrize('tool,args,expected',[
 ('note',{'kind':'open_question','status':'active'},'Supply all required'),
 ('memory',{'kind':'state','injected_secret':'x'},'Remove parameters'),
 ('memory',{'kind':'bogus'},'enumeration'),
 ('memory',{'kind':'state','limit':'2'},'JSON type'),
 ('memory',{'kind':'state','offset':-1},'numeric bounds'),
 ('memory',{'kind':'state','query':'x'},'evidence_id only'),
 ('note',{'kind':'open_question','status':'active','text':''},'nonempty text'),
 ('note',{'kind':'open_question','status':'active','text':'x','alternatives':['x']*11},'item limits'),
])
def test_safe_canonical_guidance(tool,args,expected):
    with pytest.raises(ValueError) as caught:arguments(tool,args)
    feedback=tool_feedback(tool,args,dict(code='TOOL_REJECTED',stage='argument_validation',validation_detail=failure_detail(caught.value)),False,True)
    assert expected in feedback['correction']
    assert 'injected_secret' not in json.dumps(feedback)
    if args.get('text')=='':assert 'Omit' not in feedback['correction']


def test_scope_and_arbitrary_exception_text_withheld():
    private='SECRET SQL private evidence'
    unknown=tool_feedback('show_evidence',{},dict(code='TOOL_REJECTED',stage=private,validation_detail={'rule':private,'validation_path':private,'constraint':private}),False,True)
    assert private not in json.dumps(unknown) and 'correction' not in unknown
    safe=tool_feedback('show_evidence',{},dict(code='TOOL_REJECTED',stage='query',validation_detail={'rule':'Evidence outside approved source/time scope'}),True,True)
    assert 'Do not broaden authorization' in safe['correction']
    fatal=tool_feedback('show_evidence',{},dict(code='EVIDENCE_INTEGRITY',stage='integrity'),None,False)
    assert 'Stop' in fatal['correction'] and not fatal['read_view_available']


def test_schema_unchanged_and_descriptions_compact():
    from forensic_assistant.conversational_ai.local_schema import generation_catalog
    tools=catalog();assert len(tools)==10
    import copy
    before=copy.deepcopy(tools);generation_catalog(tools);assert tools==before
    assert sum(len(t['function']['description'].encode()) for t in tools)<5000

@pytest.mark.parametrize('mode',['truncated','redacted','undisclosed','timestamp','malformed_json'])
def test_feedback_does_not_create_verification_authority(tmp_path,monkeypatch,mode):
    from forensic_assistant.conversational_ai.tools import Tools
    path,_,scope=setup(tmp_path,[])
    record=dict(id='synthetic',source_type='evtx',context={'source_ids':scope['source_ids']},command_line='example.exe',timestamp_utc='2026-09-30T12:00:00.000000000Z')
    adapter=Tools(None,scope)
    # Synthetic original hydration; production field-disclosure and verification rules.
    monkeypatch.setattr(adapter,'original',lambda eid:record)
    if mode=='truncated':record['command_line']='x'*1100
    if mode=='redacted':monkeypatch.setattr('forensic_assistant.ai.backend.redact',lambda text:'[redacted]' if text=='example.exe' else text)
    if mode!='undisclosed':adapter.page(record,limit=40)
    args=dict(evidence_id='synthetic',field='/command_line',value_json=json.dumps(record['command_line']))
    if mode=='timestamp':args.update(field='/timestamp_utc',value_json=json.dumps(record['timestamp_utc']),timestamp_meaning='Successful execution')
    if mode=='malformed_json':args['value_json']='{broken'
    with pytest.raises(ValueError) as caught:adapter.execute('verify_observation',args)
    prior=dict(adapter.disclosed)
    value=tool_feedback('verify_observation',args,dict(code='TOOL_REJECTED',stage='query',validation_detail=failure_detail(caught.value)),True,True)
    assert value['result_accepted'] is False and adapter.disclosed==prior
    with pytest.raises(ValueError):adapter.execute('verify_observation',args)


def test_unknown_evidence_feedback_discloses_nothing(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    def review(messages):
        feedback=last(messages)
        assert 'previously returned' in feedback['correction']
        assert 'private-unretrieved-eid' not in json.dumps(feedback)
        assert not feedback['worker_reached']
        return reply('No conclusion.')
    path,provider,scope=setup(tmp_path,[reply(calls=[call('show_evidence',{'evidence_id':'private-unretrieved-eid'})]),review])
    session=Session(scope,provider,lambda _:True)
    try:session.submit('Synthetic')
    finally:session.close()

@pytest.mark.parametrize('rule',['Invalid pagination bounds','Invalid EVTX continuation for this search scope','Invalid object continuation for this scope'])
def test_continuation_feedback(rule):
    value=tool_feedback('search_evidence',{},dict(code='TOOL_REJECTED',stage='query',validation_detail=failure_detail(ValueError(rule))),True,True)
    assert 'correction' in value and not value['result_accepted']


def test_required_scope_choice_not_omitted():
    args={'artifact':'evtx','source_id':''}
    with pytest.raises(ValueError) as caught:arguments('search_evidence',args)
    value=tool_feedback('search_evidence',args,dict(code='TOOL_REJECTED',stage='argument_validation',validation_detail=failure_detail(caught.value)),False,True)
    assert 'Do not omit required source choices' in value['correction']

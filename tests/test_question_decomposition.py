"""S4-A synthetic/mock-only mapping, grant, persistence and budget controls."""
from copy import deepcopy
import json
import pytest

from forensic_assistant.investigation_ai import decomposition as d, autonomous as a
from forensic_assistant.investigation_ai import autonomous_policy as p, question_assessment as q
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.ai import openai_schema
from test_synthesis_relationships import clause, temporal
from test_autonomous_stage_a import setup


def objective(question, kind='event_identifier', literal='1121', name='event_id', **changes):
    bindings = [] if literal is None else [dict(name=name, span=dict(start=question.index(literal),
                                                                  end=question.index(literal)+len(literal)))]
    return dict(local_ref='Q1', question_span=dict(start=0, end=len(question)),
                proposition_type=kind, polarity='affirmative', arguments=bindings, unresolved=[],
                objective_relation='direct_objective', limitations=[], **changes)


def proposal(*items):
    return dict(contract=d.CONTRACT, objectives=list(items), unrepresented_spans=[], limitations=[])


def configure(tmp_path, question='Was event 1121 recorded, and did the script execute?', count=3):
    config, worker, client, seen, closed = setup(tmp_path, count=count)
    grant = config['_stage_a']
    grant.update(contract=p.S4_CONTRACT, allocations=deepcopy(p.S4_ALLOCATION), objective=question)
    grant['limits']['requests'] = 7
    original = next(client.actions)
    client.actions = iter([proposal(objective(question))] + [original]*6)
    return config, worker, client, seen, closed


def run(tmp_path, config, worker, client):
    return a.run(config, config['_stage_a']['objective'], tmp_path/'runs', client=client, worker_factory=worker)


def test_typed_rules_match_grammar_without_language_roundtrip(monkeypatch):
    state = temporal(clause(1121, family='evtx', pointer='/event_id'))
    expected = q._assess('Is event ID 1121 present in the inspected EVTX records?', 'a'*32, state)
    monkeypatch.setattr(q, '_map', lambda _: pytest.fail('Typed path parsed English'))
    result = q.assess_typed('Open question', 'a'*32, state, [
        dict(text='event 1121', type='event_identifier', arguments={'event_id':1121})])
    assert result['propositions'][0]['direct_clauses'] == expected['propositions'][0]['direct_clauses']
    assert result['propositions'][0]['status'] == 'SUPPORTED_WITHIN_SCOPE'
    assert 'status' not in result


@pytest.mark.parametrize('kind,args', [('invented',{}), ('event_identifier',{'event_id':True}),
    ('event_identifier',{'event_id':1121,'extra':1}), ('recorded_order',{'left':'invented','right':'other'})])
def test_typed_invalid_arguments(kind,args):
    with pytest.raises(ValueError): q.validate_typed(kind,args)


def test_compound_unresolved_and_scoped_support():
    question='Did event 1121 occur, and did the script execute?'
    first=objective(question)
    second=objective(question,'execution_outcome',None)
    second.update(local_ref='Q2',unresolved=[{'name':'value','role':'the script'}])
    value=proposal(first,second)
    mapping=d.parse(json.dumps(value),question)
    result=d.assess(question,'b'*32,temporal(clause(1121,family='evtx',pointer='/event_id')),
                    {'status':'accepted','mapping':mapping})
    assert result['original_assessment']['status']=='NOT_ASSESSABLE'
    assert result['scoped_objectives'][0]['assessment']['status']=='SUPPORTED_WITHIN_SCOPE'
    assert result['scoped_objectives'][1]['assessment'] is None
    assert result['original_question_fully_answered'] is False
    assert mapping['source_span_coverage']['semantic_completeness']=='not_certified'
    assert 'unresolved roles' in d.render(result)


@pytest.mark.parametrize('polarity',['negative','uncertain'])
def test_negation_never_becomes_positive_answer(polarity):
    question='Was event 1121 not recorded?'
    item=objective(question);item['polarity']=polarity
    assert d.validate(proposal(item),question)['objectives'][0]['eligible'] is False


def test_full_span_omission_cannot_certify_original():
    question='Was event 1121 recorded, and who caused the incident?'
    mapping=d.validate(proposal(objective(question)),question)
    assert mapping['source_span_coverage']['covered_codepoints']==len(question)
    assert mapping['intent_fidelity']=='provisional'
    assert mapping['source_span_coverage']['semantic_completeness']=='not_certified'


def test_unsupported_general_question_and_uncovered_spans():
    question='What happened and why?'
    item=objective(question,'unsupported_objective',None)
    item['question_span']['end']=13
    result=d.validate(proposal(item),question)
    assert not result['objectives'][0]['eligible']
    assert result['source_span_coverage']['uncovered_spans']==[{'start':13,'end':len(question)}]


@pytest.mark.parametrize('mutation', ['literal','span','outside','duplicate','contradiction','candidate','clause','roles'])
def test_atomic_invalid_source_structure(mutation):
    question='First: event 1121. Then what?'
    value=proposal(objective(question));item=value['objectives'][0]
    if mutation=='literal':item['arguments'][0]['value']='invented.exe'
    elif mutation=='span':item['arguments'][0]['span']['end']=999
    elif mutation=='outside':item['question_span']={'start':0,'end':5}
    elif mutation in ('duplicate','contradiction'):
        other=deepcopy(item)
        if mutation=='contradiction':other.update(local_ref='Q2',polarity='negative')
        value['objectives'].append(other)
    elif mutation=='candidate':item['candidate_refs']=['invented']
    elif mutation=='clause':
        item['proposition_type']='recorded_field_equals';item['arguments'][0]['name']='clause_id'
        item['unresolved']=[{'name':'value','role':'unknown'}]
    else:item['unresolved']=[{'name':'event_id','role':'duplicate'}]
    with pytest.raises(ValueError):d.validate(value,question)


def test_unicode_codepoints_and_utf8_constraints():
    question='🦉 Événement 1121 enregistré?'
    item=objective(question)
    assert d.validate(proposal(item),question)['objectives'][0]['arguments']=={'event_id':1121}
    item['limitations']=['é'*81]
    with pytest.raises(ValueError,match='string length'):d.validate(proposal(item),question)


@pytest.mark.parametrize('raw',['{','{}','{"objectives":[],"objectives":[]}','[1]', 'x'*8193])
def test_invalid_truncated_json(raw):
    with pytest.raises(ValueError):d.parse(raw,'event 1121')


def test_openai_exact_adapter_uniqueness_and_serialization():
    question='Was event 1121 recorded? Did file.exe execute? Was the file downloaded? What happened?'
    items=[objective(question)]
    for ref,kind,name,literal in [('Q2','execution_outcome','value','file.exe'),
                                 ('Q3','browser_download','value','file.exe')]:
        item=objective(question,kind,literal,name);item['local_ref']=ref;items.append(item)
    item=objective(question,'unsupported_objective',None);item['local_ref']='Q4';items.append(item)
    value=proposal(*items)
    wire=openai_schema.request_schema('openai',d.SCHEMA)
    assert 'uniqueItems' not in json.dumps(wire)
    assert d.SCHEMA['properties']['objectives']['uniqueItems']
    raw=json.dumps(value)
    assert d.parse(openai_schema.response('openai',raw,d.SCHEMA),question)
    assert sum(len(m['content'].encode()) for m in d.messages(question))<=5600
    # Serialized response bound; token ceilings are independently enforced below.
    assert len(raw.encode())<4096
    value['objectives'].append(deepcopy(value['objectives'][0]))
    with pytest.raises(Exception):openai_schema.response('openai',json.dumps(value),d.SCHEMA)
    assert openai_schema.request_schema('anthropic',d.SCHEMA) is d.SCHEMA


def test_new_grant_six_analysis_one_decomposition_and_replay(tmp_path):
    config,worker,client,seen,closed=configure(tmp_path,count=6)
    result=run(tmp_path,config,worker,client)
    assert result['validated_batches']==6 and len(client.calls)==7 and closed
    assert result['metrics']['analysis_requests']==6
    assert result['metrics']['decomposition_requests']==1
    assert result['metrics']['organization_requests']==0
    assert result['metrics']['ai_requests']==7
    assert result['metrics']['usage_unknown']==7
    assert len([v for v in seen if v[0]=='show_evidence'])==6
    assert set(json.loads(client.calls[0][1]['content']))=={'question'}
    rebuilt=d.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert rebuilt==result['question_decomposition']
    manifest,events=load(tmp_path/'runs',result['investigation_id'])
    assert manifest['engine']==d.ENGINE
    assert [e['kind'] for e in events].count('decomposition_request')==1
    assert [e['kind'] for e in events].count('analysis_request')==6
    assert result['state']['steps']<=8


@pytest.mark.parametrize('failure',['provider','validation','truncated','cancel'])
def test_failed_decomposition_no_retry_and_partial_results(tmp_path,failure):
    config,worker,client,seen,closed=configure(tmp_path)
    normal=list(client.actions)[1:]
    def bad(_):
        if failure=='provider':raise ValueError('synthetic transport failure')
        if failure=='cancel':raise KeyboardInterrupt()
        return {'invented':'value'}
    if failure=='truncated':
        original=client.complete
        def complete(messages,schema):
            if schema==d.SCHEMA:
                client.calls.append(messages);return '{'
            return original(messages,schema)
        client.complete=complete;client.actions=iter(normal)
    else:client.actions=iter([bad]+normal)
    result=run(tmp_path,config,worker,client)
    assert closed and result['metrics']['decomposition_requests']==1
    if failure!='cancel':
        assert result['validated_batches']==3
        assert result['question_decomposition']['decomposition_status']=='rejected'
        assert d.reconstruct(tmp_path/'runs',result['investigation_id'])==result['question_decomposition']
    else:
        assert not result['validated_batches']
        assert d.reconstruct(tmp_path/'runs',result['investigation_id'])==result['question_decomposition']


@pytest.mark.parametrize('change',['total','analysis','organization','old','expiry'])
def test_grant_cannot_borrow_or_expand(tmp_path,change):
    config,*_=configure(tmp_path);grant=config['_stage_a']
    if change=='old':grant['contract']=p.CONTRACT
    elif change=='expiry':grant['issued']-=301;grant['expires']-=301
    else:grant['allocations'][change]+=1
    with pytest.raises(ValueError):p.validate(grant,config['case_path'])


def test_resource_reserve_skips_dispatch(tmp_path,monkeypatch):
    config,worker,client,seen,closed=configure(tmp_path)
    import time
    config['_stage_a_deadline']=time.monotonic()+10
    result=run(tmp_path,config,worker,client)
    assert not client.calls
    assert result['termination']=='RESOURCE_BUDGET_EXHAUSTED'
    assert result['metrics']['ai_requests']==0


def test_journal_failure_never_accepts_mapping(tmp_path,monkeypatch):
    config,worker,client,seen,closed=configure(tmp_path)
    original=a.Transcript.append
    def fail(self,kind,data,**kwargs):
        if kind=='decomposition_decision':raise OSError('synthetic durable write failure')
        return original(self,kind,data,**kwargs)
    monkeypatch.setattr(a.Transcript,'append',fail)
    result=run(tmp_path,config,worker,client)
    assert result['question_decomposition']['mapping'] is None
    assert result['termination']=='OPERATION_FAILURE'
    assert len(client.calls)==1 and closed
    assert d.reconstruct(tmp_path/'runs',result['investigation_id'])==result['question_decomposition']


def test_prior_factual_batches_survive_later_analysis_failure(tmp_path):
    config,worker,client,seen,closed=configure(tmp_path)
    actions=list(client.actions)
    def fail(_):raise ValueError('synthetic failure')
    client.actions=iter(actions[:2]+[fail])
    result=run(tmp_path,config,worker,client)
    assert result['validated_batches']==1
    assert result['question_decomposition']['original_assessment']['metrics']['contextual_supports']>0
    assert d.reconstruct(tmp_path/'runs',result['investigation_id'])==result['question_decomposition']


def test_cli_requires_explicit_new_opt_in():
    from forensic_assistant.cli import build_parser
    from forensic_assistant.briefing_cli import run
    parser=build_parser()
    args=parser.parse_args(['briefing','--investigate','--decompose'])
    with pytest.raises(ValueError,match='requires'):run(args)
    args=parser.parse_args(['briefing','--investigate','--autonomous','--decompose'])
    assert args.decompose and args.autonomous


def test_openai_transport_preserves_output_and_no_hidden_retries(monkeypatch):
    from forensic_assistant.ai.cloud_worker import request_kwargs
    from test_openai_investigation_schema import strict_shape
    monkeypatch.setenv('OPENAI_API_KEY','synthetic-test-key')
    packet=d.messages('Was event 1121 recorded?')
    kwargs=request_kwargs(dict(provider='openai',model='synthetic',messages=packet,schema=d.SCHEMA,timeout=30))
    strict_shape(kwargs['response_format']['json_schema']['schema'])
    assert kwargs['messages']==packet
    assert kwargs['max_tokens']==1024 and kwargs['num_retries']==0
    assert kwargs['timeout']==30 and kwargs['stream'] is False
    assert not any(k in kwargs for k in ('tools','tool_choice'))


def test_timeout_charged_without_retry(tmp_path):
    config,worker,client,seen,closed=configure(tmp_path)
    calls=list(client.actions)
    def timeout(_):
        assert 0 < client.timeout <= 30
        raise TimeoutError('synthetic timeout')
    client.actions=iter([timeout]+calls[1:])
    result=run(tmp_path,config,worker,client)
    assert len(client.calls)==4 and result['validated_batches']==3
    assert result['metrics']['decomposition_requests']==1
    assert not hasattr(client,'timeout')


def test_no_request_when_request_journal_fails(tmp_path,monkeypatch):
    config,worker,client,_,_=configure(tmp_path)
    original=a.Transcript.append
    def append(self,kind,data,**kwargs):
        if kind=='decomposition_request':raise OSError('synthetic journal failure')
        return original(self,kind,data,**kwargs)
    monkeypatch.setattr(a.Transcript,'append',append)
    result=run(tmp_path,config,worker,client)
    assert client.calls==[] and result['metrics']['ai_requests']==0
    assert result['question_decomposition']['mapping'] is None


@pytest.mark.parametrize('target',['mapping','manifest','counter','scope','unapproved_result'])
def test_reconstruction_checks_beyond_hash_integrity(tmp_path,target):
    config,worker,client,_,_=configure(tmp_path)
    result=run(tmp_path,config,worker,client)
    manifest,events=load(tmp_path/'runs',result['investigation_id'])
    if target=='mapping':
        next(e for e in events if e['kind']=='decomposition_decision')['data']['mapping']['intent_fidelity']='certified'
    elif target=='manifest':
        next(e for e in events if e['kind']=='decomposition_request')['data']['candidate_refs']=['invented']
    elif target=='counter':
        next(e for e in events if e['kind']=='terminal')['data']['metrics']['analysis_requests']=1
    elif target=='scope':
        next(e for e in events if e['kind']=='result')['data']['response']['result']['records'][0]['source_context']['source_ids']=['other']
    else:events=[e for e in events if e['kind']!='authorized_operation']
    with pytest.raises(ValueError):d.validate_journal(manifest,events)


def test_provider_free_reconstruction_no_report_permission(tmp_path,monkeypatch):
    config,worker,client,_,_=configure(tmp_path)
    result=run(tmp_path,config,worker,client)
    root=tmp_path/'runs';identity=result['investigation_id']
    before={p:p.read_bytes() for p in root.rglob('*') if p.is_file()}
    monkeypatch.setattr(client,'complete',lambda *a:pytest.fail('provider call during reconstruction'))
    assert d.reconstruct(root,identity)==d.reconstruct(root,identity)
    assert before=={p:p.read_bytes() for p in before}
    from forensic_assistant.reporting.transcripts import load as report_load
    with pytest.raises(ValueError,match='Incremental report import'):report_load(root,identity)


def test_unrelated_case_literals_and_control_characters():
    question='Did C:\\benign\\budget.csv download? What about \x1b[31m café?'
    item=objective(question,'browser_download',r'C:\benign\budget.csv','value')
    mapping=d.validate(proposal(item),question)
    state=temporal(clause(r'C:\benign\budget.csv',family='browser',pointer='/target_path'))
    result=d.assess(question,'a'*32,state,{'status':'accepted','mapping':mapping})
    assert result['scoped_objectives'][0]['assessment']['status']=='SUPPORTED_WITHIN_SCOPE'
    assert '\x1b' not in d.render(result)
    assert result['original_assessment']['status']=='NOT_ASSESSABLE'


def test_large_unicode_question_rejected_before_dispatch():
    with pytest.raises(ValueError,match='BUDGET_EXHAUSTED'):d.messages('🦉'*1000)


def test_provider_structural_failure_keeps_sanitized_rule(tmp_path):
    from forensic_assistant.ai.response_contract import validate
    config,worker,client,_,_=configure(tmp_path)
    actions=list(client.actions)
    def failed(_):
        validate('{"contract":"question-decomposition-proposal-v1","objectives":[],"unrepresented_spans":[],"limitations":[]}',d.SCHEMA)
    client.actions=iter([failed]+actions[1:])
    result=run(tmp_path,config,worker,client)
    detail=result['question_decomposition']['diagnostics']
    assert detail['provider_category']=='structured_validation_failed'
    assert detail['provider_validation']['errors'][0]['canonical_path']=='$.objectives'
    assert detail['provider_validation']['errors'][0]['validator_keyword']=='minItems'
    assert detail['response_available'] is False
    assert result['validated_batches']==3


def test_s4_worker_cannot_substitute_another_approved_record(tmp_path):
    config,worker,client,_,_=configure(tmp_path)
    class WrongRecord(worker):
        def call(self,name,args=None,**kwargs):
            if name=='show_evidence':
                args={'evidence_id':next(i for i in config['_stage_a']['evidence_ids'] if i!=args['evidence_id'])}
            return super().call(name,args,**kwargs)
    result=run(tmp_path,config,WrongRecord,client)
    assert result['termination']=='ADDITIONAL_SCOPE_REQUIRED'
    assert len(client.calls)==1 and result['validated_batches']==0
    assert d.reconstruct(tmp_path/'runs',result['investigation_id'])==result['question_decomposition']


def hanging_decomposition_child(connection,gate,request):
    """Synthetic controller blocked in provider code, no provider or case access."""
    import time
    gate.wait()
    connection.send_bytes(b'{"kind":"startup_complete"}')
    connection.send_bytes(b'{"kind":"status","phase":"decomposition"}')
    time.sleep(60)


def test_supervisor_bounds_hung_decomposition_process(tmp_path,monkeypatch):
    import time
    from forensic_assistant.investigation_ai import supervision
    from forensic_assistant.investigation_ai.state import Budget
    from forensic_assistant.llm.client import LocalClient
    config,_,_,_,_=configure(tmp_path)
    monkeypatch.setattr(supervision,'_child',hanging_decomposition_child)
    started=time.monotonic()
    # 16s synthetic global allowance leaves at most 1s before the 15s reserve.
    result=supervision.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=LocalClient(),budget=Budget(seconds=16))
    assert result['termination']=='DECOMPOSITION_TIMEOUT'
    assert time.monotonic()-started < 1+supervision.CLEANUP_SECONDS+3
    assert result['startup_diagnostic']['cleanup_confirmed']
    assert result['engine']==d.ENGINE and not result['findings']
    from forensic_assistant.investigation_ai.presentation import termination_label
    assert 'decomposition exceeded its deadline' in termination_label(result)

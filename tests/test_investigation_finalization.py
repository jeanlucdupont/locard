"""Synthetic reproduction of the validated 6.94 no-new-ID cutoff; no providers."""
import json
import pytest
from test_assessment_handoff import saved, approved, Worker, START, END
from test_v4_controller import Scripted, tool
from forensic_assistant.investigation_ai import controller
from forensic_assistant.investigation_ai.state import State, Budget
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.llm.client import LLMError


def answer(messages):
    packet = json.loads(messages[1]['content'])
    assert packet['controller']['final_only']
    assert packet['controller']['tools'] == []
    data=packet['UNTRUSTED FORENSIC EVIDENCE']
    assert packet['controller']['evtx_content_search']['skipped'] == 13
    if data.get('encoding'):
        from forensic_assistant.investigation_ai.disclosure import decode
        data=decode(data)
    record=next(r for r in data['records'] if r['id'].startswith('EVTX:'))
    if data.get('contract'):
        pointer=next(i['field']['pointer'] for i in record['observations'] if i['field']['semantic'].get('name')=='Target Commandline')
        derived=[i['id'] for i in record['interpretations']]
    else:
        index=next(i for i,v in enumerate(record['original_event_data']) if v.get('name')=='Target Commandline')
        pointer=f'/original_event_data/{index}/value';derived=record['interpretation_ids']
    return {'action':'final','answer':{'observed':[{'evidence_id':record['id'],'field':pointer}],
        'relationships':[],'detections':[],'hypotheses':[],'interpretations':derived,'answer_status':'partial',
        'unknowns':['Successful execution remains unresolved; search coverage is incomplete.']}}


def run_sequence(saved, tmp_path, last=answer, budget=None):
    case, assessment = saved
    p = approved(saved)
    eid = next(e for e in assessment['records'] if e.startswith('EVTX'))
    actions = [tool('show_evidence', {'evidence_id': eid})]
    for extra in ({}, {'event_id': 4103}, {'event_id': 4104}):
        actions.append(tool('search_evidence', dict(artifact='evtx', evtx_text='baje.ps1',
            hostname='synthetic-host', start=START, end=END, limit=20, **extra)))
    class EmptySearch(Worker):
        def call(self, name, args=None, **kw):
            response = super().call(name, args, **kw)
            if name == 'search_evidence':
                skipped = 13 if args.get('event_id') else 0
                response['result'].update(records=[], returned_count=0, truncated=True,
                    content_search=dict(complete=False, continued=False, examined=218 if skipped else 1000,
                        skipped=skipped, next_cursor='synthetic-cursor'),
                    limitations=['Coverage incomplete; no absence conclusion.'])
            return response
    workers, approvals = [], []
    def make(config):
        worker = EmptySearch(config); workers.append(worker); return worker
    client = Scripted([*actions, last])
    before = case.read_bytes()
    result = controller.run({'case_path': str(case), '_assessment_handoff': p}, p['question'],
        tmp_path/'runs', client=client, worker_factory=make,
        approval=lambda *args: approvals.append(args) or True, budget=budget or Budget())
    assert case.read_bytes() == before
    assert len(approvals) == 4
    assert workers[0].calls == ['initial', 'show_evidence', 'search_evidence', 'search_evidence', 'search_evidence', 'check']
    assert result['state']['accepted_calls'] == 4
    assert max(result['metrics']['prompt_bytes']) <= 5600
    return result, client


def test_live_shape_finalizes_once(saved, tmp_path):
    result, client = run_sequence(saved, tmp_path)
    assert result['termination'] == 'ANSWER_SUPPORTED'
    assert result['state']['answer_attempts'] == 1
    assert result['answer_assessment']['status'] == 'PARTIAL'
    assert result['answer_origin'] == 'validated_model_proposal'
    assert len(client.calls) == 5
    manifest, events = load(tmp_path/'runs', result['investigation_id'])
    assert len(manifest['tool_calls']) == 4
    assert sum(e['kind'] == 'validated_final' for e in events) == 1
    assert 'does not establish successful target execution' in result['findings']['interpretations'][0]['text']
    assert len(json.loads(client.calls[-1][1]['content'])['UNTRUSTED FORENSIC EVIDENCE']['records']) == 1


@pytest.mark.parametrize('mode', ['unsupported', 'tool', 'malformed', 'refusal', 'transport'])
def test_finalization_failure_is_bounded(saved, tmp_path, mode):
    def fail(messages):
        if mode == 'transport':
            raise LLMError('Synthetic provider failure')
        if mode == 'tool':
            return tool('search_evidence', {'process': 'different.exe'})
        if mode == 'malformed':
            return {'action': 'final', 'answer': {}}
        value = answer(messages)
        if mode == 'unsupported':
            value['answer']['observed'][0]['field'] = '/undisclosed_execution'
        else:
            value['answer'].update(observed=[], interpretations=[], answer_status='unresolved')
        return value
    result, client = run_sequence(saved, tmp_path, fail)
    assert len(client.calls) == 5
    assert result['termination'] == ('MODEL_FAILURE' if mode == 'transport' else
        'INSUFFICIENT_EVIDENCE' if mode == 'refusal' else 'FINALIZATION_FAILED')
    if mode != 'refusal':
        assert result['answer_origin'] == 'deterministic_disclosed_observations_only'
        assert any(r.get('recorded_field', {}).get('name') == 'Target Commandline' for r in result['findings']['observed'])
        assert result['findings']['interpretations']


def test_no_extra_step_budget(saved, tmp_path):
    result, client = run_sequence(saved, tmp_path, budget=Budget(steps=4))
    assert result['termination'] == 'NO_NEW_EVIDENCE'
    assert len(client.calls) == 4 and not result['state']['finalization_requested']
    assert any('remaining budget' in s for s in result['limitations'])


def test_fallback_only_disclosed_fields_and_legacy():
    state = State(Budget())
    eid = 'EVTX:' + 'a'*64 + ':Offset:1'
    state.records[eid] = dict(id=eid, event_id=1121, command_line='never disclosed')
    state.disclose(dict(records=[dict(id=eid, timestamp_utc='2026-09-30T00:00:00Z')], relationships=[], detections=[]))
    result = state.partial()
    assert len(result['observed']) == 1 and result['observed'][0]['field'] == '/timestamp_utc'
    assert not result['interpretations']
    assert 'interpretations' not in state.partial(legacy=True)
    assert state.partial(legacy=True)['observed'] == result['observed']


def test_final_only_schema_and_long_completed_summaries():
    from forensic_assistant.investigation_ai import contracts
    from forensic_assistant.ai import openai_schema, anthropic_strategy
    schema = contracts.schema([])
    assert len(schema['oneOf']) == 1
    assert schema['oneOf'][0]['properties']['action']['enum'] == ['final']
    assert openai_schema.request_schema('openai', schema)
    assert anthropic_strategy.wire_schemas(schema)
    with pytest.raises(ValueError, match='not applicable'):
        contracts.request(json.dumps(tool('search_evidence', {'process':'x.exe'})), [])
    state = State(Budget())
    state.completed_calls = {str(i): {'tool':'search_evidence', 'query':{'evtx_text':'\\u2603'*256},
                                    'returned':0, 'coverage':{'complete':False}} for i in range(6)}
    messages, _, size = state.prompt('Inspect', ['search_evidence'], [])
    assert size <= 5600 and state.prompt_diagnostics['completed_summaries_omitted'] > 0
    assert json.loads(messages[1]['content'])['controller']['completed_summaries_omitted'] > 0

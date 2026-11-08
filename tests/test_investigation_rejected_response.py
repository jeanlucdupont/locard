"""Persistent bounded rejection diagnostics, using synthetic responses only."""
import json
import pytest
from test_assessment_handoff import saved
from test_investigation_finalization import run_sequence, answer
from forensic_assistant.investigation_ai.transcript import load, digest
from forensic_assistant.investigation_ai.rejection import rejected_response
from forensic_assistant.investigation_ai.state import State, Budget, GroundingReferenceError


@pytest.mark.parametrize('mode', ['field', 'identity', 'derived', 'structure', 'execution', 'causality'])
def test_rejected_final_persisted_before_termination(saved, tmp_path, mode):
    original = []
    def invalid(messages):
        value = answer(messages)
        row = value['answer']['observed'][0]
        if mode == 'identity':
            row['evidence_id'] = 'EVTX:' + 'f'*64 + ':Offset:999'
        elif mode == 'structure':
            value['answer'].pop('unknowns')
        elif mode == 'execution':
            row['successful_execution'] = True
        elif mode == 'causality':
            row['caused_download'] = True
        else:
            row['field'] = '/defender_asr/action' if mode == 'derived' else '/undisclosed'
        original.append(json.dumps(value))
        return value
    result, client = run_sequence(saved, tmp_path, invalid)
    assert result['termination'] == 'FINALIZATION_FAILED' and len(client.calls) == 5
    manifest, events = load(tmp_path/'runs', result['investigation_id'])
    event = next(e for e in events if e['kind'] == 'rejected')
    capture = event['data']['rejected_response']
    assert json.loads(capture['text']) == json.loads(original[0])
    assert not capture['truncated'] and not capture['redacted']
    assert capture['disclosure']['exposure_event_step'] == 5
    assert events[-1]['kind'] == 'terminal' and event['sequence'] < events[-1]['sequence']
    detail = capture['reference_failure']
    if mode in ('field', 'identity', 'derived'):
        assert detail['code'] == ('unknown_evidence_id' if mode == 'identity' else 'non_observation_field' if mode == 'derived' else 'undisclosed_field')
        assert detail['validation_path'] == 'answer.observed[0]'
        assert not detail['field_disclosed']
        assert not detail['observation_eligible']
        assert detail['visible_in_exposure_ledger'] == (mode == 'derived')
        assert detail['visible_in_latest_prompt'] == (mode == 'derived')
        assert detail['evidence_disclosed'] == (mode != 'identity')
    else:
        assert not detail and event['data']['diagnostic']['category'] == 'MALFORMED_PROPOSAL'
        if mode == 'structure':
            assert capture['structural_failure']['missing_fields'] == ['unknowns']
    assert result['findings']['interpretations']
    assert any('Target Commandline' == r.get('recorded_field',{}).get('name') for r in result['findings']['observed'])
    from forensic_assistant.investigation_ai.presentation import render
    assert capture['text'] not in render(result)


def test_capture_bounded_redacted_and_unvalidated(monkeypatch):
    monkeypatch.setenv('SYNTHETIC_API_KEY', 'synthetic-sensitive-secret')
    state = State(Budget())
    raw = 'synthetic-sensitive-secret' + '\u2603'*40000
    capture = rejected_response(raw, ValueError('malformed'), state)
    assert capture['truncated'] and capture['redacted']
    assert 'synthetic-sensitive-secret' not in capture['text']
    assert len(json.dumps(capture, ensure_ascii=True).encode()) < 40000
    assert 'NOT EVIDENCE' in capture['classification']


def test_disclosed_field_and_unknown_id_are_distinct():
    state = State(Budget())
    eid = 'EVTX:' + 'a'*64 + ':Offset:1'
    state.disclose(dict(records=[dict(id=eid,event_id=1121)], relationships=[], detections=[]))
    value = dict(observed=[dict(evidence_id=eid,field='/event_id')], relationships=[], detections=[], hypotheses=[], unknowns=[])
    assert state.render(value)['observed'][0]['reported_value'] == 1121
    value['observed'][0]['field'] = '/command_line'
    with pytest.raises(GroundingReferenceError) as failure:
        state.render(value)
    assert failure.value.reference_detail['code'] == 'undisclosed_field'
    value['observed'][0]['evidence_id'] = 'unknown'
    with pytest.raises(GroundingReferenceError) as failure:
        state.render(value)
    assert failure.value.reference_detail['code'] == 'unknown_evidence_id'


def test_structural_path_includes_item_index():
    from forensic_assistant.investigation_ai.contracts import request
    from forensic_assistant.investigation_ai.rejection import diagnostic
    value = dict(action='final',answer=dict(observed=[dict(evidence_id='a',field=5)],relationships=[],detections=[],hypotheses=[],unknowns=[]))
    with pytest.raises(ValueError) as failure:
        request(json.dumps(value), [])
    result = diagnostic('a'*32, 4, None, value, 'proposal_validation', failure.value)
    assert result['reason'] == 'request.answer.observed[0].field: wrong type'


def test_unsupported_interpretation_has_exact_diagnostic():
    state = State(Budget())
    with pytest.raises(GroundingReferenceError) as failure:
        state.render(dict(observed=[],relationships=[],detections=[],hypotheses=[],unknowns=[],interpretations=['INT:unknown']))
    detail = rejected_response('{}', failure.value, state)['reference_failure']
    assert detail == dict(code='unsupported_interpretation', validation_path='answer.interpretations[0]', interpretation_id='INT:unknown')


def test_final_context_is_evidence_first(saved, tmp_path):
    result, client = run_sequence(saved, tmp_path)
    packet = json.loads(client.calls[-1][1]['content'])
    assert 'ASSESSMENT CONTEXT — NOT EVIDENCE' not in packet
    assert packet['controller']['objective'] == 'What evidence supports execution?'
    assert packet['controller']['final_only'] and not packet['controller']['tools']
    assert not packet['controller']['evtx_content_search']['complete']
    assert result['answer_origin'] == 'validated_model_proposal'

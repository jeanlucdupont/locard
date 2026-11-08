"""Hypothesis contract boundaries; synthetic providers and forensic records only."""
import copy
import json

import pytest

from forensic_assistant.ai import openai_schema
from forensic_assistant.ai.response_contract import validator
from forensic_assistant.investigation_ai import contracts
from forensic_assistant.investigation_ai.presentation import render
from forensic_assistant.investigation_ai.transcript import load
from test_assessment_handoff import saved
from test_compact_disclosure import state, answer
from test_investigation_finalization import run_sequence, answer as final_answer


def proposal(statement):
    s = state()
    _, packet, _ = s.prompt('PowerShell sequence', [], [])
    s.disclose(packet)
    value = answer(packet)
    value['hypotheses'] = [dict(statement=statement,
        evidence_ids=[value['observed'][0]['evidence_id']],
        alternatives=['The recorded activities could be unrelated.'])]
    return s, dict(action='final', answer=value)


@pytest.mark.parametrize('statement', ['a', 'a'*400, '\u00e9'*200, 'Possible script activity; execution remains unverified.'])
def test_valid_hypotheses_pass_unchanged(statement):
    s, value = proposal(statement)
    translated = openai_schema.response('openai', json.dumps({'proposal': value}), contracts.schema([]))
    parsed = contracts.request(translated, [])
    result = s.render(parsed['answer'])
    assert result['hypotheses'][0]['statement'] == statement
    assert result['hypotheses'][0]['classification'] == 'HYPOTHESIS'
    assert 'UNVERIFIED' in result['hypotheses'][0]['verification']


@pytest.mark.parametrize('statement', ['', ' \t\n', 'a'*401, 'a'*399+'\u2014', 'a\x00b', None, {}, 1])
def test_invalid_statement_rejected_not_repaired(statement):
    _, value = proposal(statement)
    original = copy.deepcopy(value)
    with pytest.raises(ValueError) as failure:
        contracts.request(json.dumps(value), [])
    assert value == original
    detail = failure.value.validation_detail
    assert detail['validation_path'] == 'request.answer.hypotheses[0].statement'
    if isinstance(statement, str):
        assert detail['characters'] == len(statement)
        assert detail['utf8_bytes'] == len(statement.encode())
        assert detail['maximum_utf8_bytes'] == 400
        assert detail['blank'] == (not statement.strip())
        assert detail['contains_nul'] == ('\x00' in statement)


def test_exact_live_failure_shape_and_wire_instructions():
    # Same shape as the live rejection, without copying the forensic statement.
    statement = 'a'*399+'\u2014'
    _, value = proposal(statement)
    canonical = contracts.schema([])
    wire = openai_schema.request_schema('openai', canonical)
    assert not list(validator(wire).iter_errors({'proposal':value}))
    translated = openai_schema.response('openai', json.dumps({'proposal':value}), canonical)
    assert json.loads(translated) == value
    with pytest.raises(ValueError) as failure:
        contracts.request(translated, [])
    assert failure.value.validation_detail['utf8_bytes'] == 402
    schema = wire['properties']['proposal']['anyOf'][0]['properties']['answer']['properties']['hypotheses']['items']
    assert '400 UTF-8 bytes, not 400 characters' in schema['properties']['statement']['description']
    assert '200 UTF-8 bytes' in schema['properties']['alternatives']['items']['description']
    assert schema['properties']['statement']['maxLength'] == 400


@pytest.mark.parametrize('mutation', ['citation','interpretation','alternatives'])
def test_valid_text_does_not_bypass_grounding(mutation):
    s, value = proposal('Possible activity, not proof of execution.')
    a = value['answer']
    if mutation == 'citation':a['hypotheses'][0]['evidence_ids']=['MFT:'+'f'*64+':Offset:999']
    elif mutation == 'interpretation':a['interpretations']=['invented-interpretation']
    else:a['hypotheses'][0]['alternatives']=[]
    contracts.request(json.dumps(value), [])
    with pytest.raises(ValueError):s.render(a)


@pytest.mark.parametrize('valid', [True,False])
def test_final_only_controller_validation_to_presentation(saved, tmp_path, valid):
    def respond(messages):
        value = final_answer(messages)
        value['answer']['hypotheses']=[dict(
            statement='Possible script activity; execution remains unverified.' if valid else 'a'*399+'\u2014',
            evidence_ids=[value['answer']['observed'][0]['evidence_id']],
            alternatives=['The activities may be unrelated.'])]
        return value
    result, client = run_sequence(saved,tmp_path,respond)
    assert len(client.calls)==5  # No new retry or lookup.
    manifest,events=load(tmp_path/'runs',result['investigation_id'])
    if valid:
        assert result['termination']=='ANSWER_SUPPORTED'
        assert result['findings']['hypotheses'][0]['statement'] == 'Possible script activity; execution remains unverified.'
        assert events[-1]['data']['findings']['hypotheses'] == result['findings']['hypotheses']
        human = render(result)
        assert 'Investigation result' in human and 'PARTIAL' in human
        assert result['findings']['interpretations'][0]['text'] in human
        assert 'Successful execution remains unresolved' in human
        assert result['findings']['interpretations']
        assert any(e['kind']=='validated_final' for e in events)
    else:
        assert result['termination']=='FINALIZATION_FAILED'
        assert not result['findings']['hypotheses']
        rejection=next(e for e in events if e['kind']=='rejected')['data']['rejected_response']
        assert rejection['structural_failure']['utf8_bytes']==402
        assert rejection['structural_failure']['characters']==400
        assert not any(e['kind']=='validated_final' for e in events)


def test_missing_statement_is_not_silently_omitted():
    _, value = proposal('Possible activity.')
    del value['answer']['hypotheses'][0]['statement']
    with pytest.raises(ValueError) as failure:
        contracts.request(json.dumps(value), [])
    assert failure.value.validation_detail['missing_fields'] == ['statement']
    value['answer']['hypotheses'] = []
    assert contracts.request(json.dumps(value), []) == value


@pytest.mark.parametrize('alternative,valid', [('a'*200,True), ('\u00e9'*100,True), ('a'*201,False), ('\u00e9'*101,False), (' ',False)])
def test_alternative_byte_boundaries(alternative,valid):
    s,value=proposal('Possible activity.')
    value['answer']['hypotheses'][0]['alternatives']=[alternative]
    if valid:
        parsed=contracts.request(json.dumps(value),[])
        assert s.render(parsed['answer'])['hypotheses'][0]['alternatives']==[alternative]
    else:
        with pytest.raises(ValueError) as failure:contracts.request(json.dumps(value),[])
        assert failure.value.validation_detail['maximum_utf8_bytes']==200
        assert failure.value.validation_detail['validation_path']=='request.answer.hypotheses[0].alternatives[0]'

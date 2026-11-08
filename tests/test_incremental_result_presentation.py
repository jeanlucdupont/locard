"""Stage A presentation is not a new conclusion or grounding contract."""
from copy import deepcopy
import pytest
from forensic_assistant.investigation_ai import autonomous
from forensic_assistant.investigation_ai.presentation import render, termination_label
from forensic_assistant.investigation_ai.transcript import load
from test_autonomous_stage_a import setup


@pytest.fixture
def result(tmp_path):
    config,worker,client,seen,closed=setup(tmp_path,count=6)
    value=autonomous.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert len(client.calls)==6 and value['validated_batches']==6
    assert len(value['state']['current_prompt_ids'])==2
    assert len(value['narrative']['coverage']['represented_record_ids'])==6
    return value


def test_six_accumulated_records_are_not_replaced_by_last_packet(result,tmp_path):
    before=deepcopy(result)
    human=render(result)
    assert human.startswith('Partial investigation findings')
    assert 'No supported conclusion was produced.' not in human
    assert 'No separate final synthesis was requested.' in human
    assert 'last analysis-batch prompt: 2; represented in accumulated findings: 6' in human
    assert 'citations do not prove causality or execution' in human
    assert 'does not establish successful' in human  # Preserved ASR qualification.
    assert result==before and result['answer_assessment']['status']=='PARTIAL'
    assert result['termination']=='AUTHORIZED_PLAN_EXHAUSTED'
    details=render(result,details=True)
    for eid in result['narrative']['coverage']['represented_record_ids']:assert eid in details
    _,events=load(tmp_path/'runs',result['investigation_id'])
    assert events[-1]['data']['findings']==before['findings']
    assert autonomous.reconstruct(tmp_path/'runs',result['investigation_id'])['findings']==before['findings']


@pytest.mark.parametrize('stop',['PROVIDER_FAILURE','VALIDATION_FAILURE','ANALYST_CANCELLED','MAX_SECONDS','CLEANUP_LIMITATION'])
def test_partial_facts_do_not_hide_stop_reason(result,stop):
    result['termination']=stop
    human=render(result)
    assert 'Partial investigation findings' in human
    assert termination_label(result) in human
    assert 'no global conclusion is asserted' in human
    assert 'No supported conclusion was produced.' not in human


def test_hypotheses_alone_do_not_become_factual_support(result):
    # Presentation-only synthetic fixture; not a bypass of model validation.
    result['findings']={
        'hypotheses':[{'statement':'Synthetic possibility, not an established fact.',
                       'alternatives':['An unrelated explanation remains possible.'],
                       'evidence_ids':[result['state']['inspected_ids'][0]]}]}
    human=render(result)
    assert human.startswith('Investigation incomplete')
    assert 'No validated factual findings were accumulated' in human
    assert 'Model-proposed hypotheses' in human and 'unverified' in human
    assert 'Accumulated validated findings:' not in human


def test_empty_stage_a_keeps_no_findings_warning():
    value={'engine':autonomous.ENGINE,'termination':'STARTUP_TIMEOUT','findings':{},'state':{}}
    human=render(value)
    assert human.startswith('Investigation incomplete')
    assert 'No validated observations or deterministic interpretations were accumulated.' in human
    assert 'Investigation startup timed out' in human


def test_legacy_conclusion_presentation_is_unchanged(result):
    result.pop('engine')
    result['termination']='REJECTION_LIMIT'
    human=render(result)
    assert human.startswith('Investigation incomplete')
    assert 'No supported conclusion was produced.' in human
    assert 'in final prompt: 2' in human
    assert 'Incremental result' not in human
    result['termination']='ANSWER_SUPPORTED'
    assert render(result).startswith('Investigation result')
    assert 'No supported conclusion was produced.' not in render(result)

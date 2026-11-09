"""Provider-free byte boundaries, partial findings, and honest diagnostics."""
import json
import time
from copy import deepcopy

import pytest

from forensic_assistant.ai import openai_schema
from forensic_assistant.ai.response_contract import validate
from forensic_assistant.investigation_ai import contracts as c
from forensic_assistant.investigation_ai import synthesis_consumer as b
from forensic_assistant.investigation_ai import autonomous as a
from forensic_assistant.investigation_ai.completion_diagnostics import observed
from forensic_assistant.investigation_ai.presentation import render
from forensic_assistant.investigation_ai.transcript import load
from test_synthesis_consumer import setup, reply, packet_context


@pytest.mark.parametrize('value,valid', [
    ('a'*200, True), ('a'*201, False), ('é'*100, True), ('é'*101, False),
    ('界'*66+'aa', True), ('界'*67, False), ('🦉'*50, True), ('🦉'*51, False),
    ('e\u0301'*66+'aa', True), ('e\u0301'*67, False), ('a'*197+'界'*3, False),
])
@pytest.mark.parametrize('escaped', [False, True])
def test_utf8_boundary(value, valid, escaped):
    raw=json.dumps(value,ensure_ascii=escaped)
    if len(value)<=200:
        assert validate(raw,c.string(200))==value  # JSON Schema characters only.
    if valid:
        c.validate(json.loads(raw),c.string(200))
    else:
        with pytest.raises(ValueError,match='invalid string length/content'):
            c.validate(json.loads(raw),c.string(200))


def test_exact_failure_and_wire_guidance():
    answer=dict(observed=[],relationships=[],detections=[],hypotheses=[],unknowns=['one','two','a'*197+'界'*3])
    value=dict(action='final',answer={**answer,'interpretations':[],'answer_status':'unresolved'})
    schema=c.schema([]);before=deepcopy(schema)
    translated=openai_schema.response('openai',json.dumps({'proposal':value}),schema)
    with pytest.raises(ValueError,match=r'unknowns\[2\]') as caught:
        c.request(translated,[])
    assert caught.value.validation_detail['characters']==200
    assert caught.value.validation_detail['utf8_bytes']==206
    wire=openai_schema.request_schema('openai',schema)
    unknown=wire['properties']['proposal']['anyOf'][0]['properties']['answer']['properties']['unknowns']['items']
    assert unknown['maxLength']==200 and 'cannot guarantee' in unknown['description']
    assert schema==before and openai_schema.request_schema('anthropic',schema) is schema


def test_partial_analysis_no_retry_or_promoted_rejected_record(tmp_path):
    config,worker,client,seen,closed=setup(tmp_path)
    actions=list(client.actions)
    def invalid(messages):
        result=actions[2](messages)
        result['answer']['unknowns']=['one','two','a'*197+'界'*3]
        return result
    client.actions=iter([actions[0],actions[1],invalid,reply,reply])
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert len(client.calls)==5 and result['validated_batches']==1 and closed
    assert result['termination']=='VALIDATION_FAILURE'
    assert result['synthesis']['status']=='completed_bounded'
    coverage=result['analysis_coverage']
    assert coverage['analysis_error_limited'] and coverage['completed_lookups']==2
    assert coverage['rejected_responses']==1 and coverage['authorized_references']==6
    human=render(result)
    assert 'Analysis-error-limited synthesis' in human and 'accepted partial findings only' in human
    assert 'attempted: 2; accepted: 2' in human
    assert 'does not imply completed evidence examination' in human
    cleanup_result={**result,'termination':'CLEANUP_LIMITATION'}
    assert 'Analysis stopped: AI batch failed validation' in render(cleanup_result)
    manifest,events=load(tmp_path/'runs',result['investigation_id'])
    records=[e['data']['arguments']['evidence_id'] for e in events if e['kind']=='authorized_operation']
    for e in events:
        if e['kind']=='synthesis_prepared':
            assert {s['evidence_id'] for s in e['data']['packet']['content']['supports']}=={records[0]}
    assert b.reconstruct(tmp_path/'runs',result['investigation_id'])==result['synthesis']
    diagnostics=[e for e in events if e['kind']=='analysis_response_diagnostic']
    assert len(diagnostics)==2 and diagnostics[-1]['data']['completion_status']=='unavailable'
    assert result['controller_diagnostic']['parent_cleanup_confirmation']=='unavailable_in_child_journal'


@pytest.mark.parametrize('label',['Download context','Incomplete but'])
def test_short_or_incomplete_prose_remains_unverified_unmodified(label):
    ctx,packet=packet_context()
    ctx.manifest['synthesis_guidance']='concise-v1'
    packet=b.materialize(ctx)['packets'][0]
    assert 'target 60 characters' in packet['messages'][0]['content']
    assert packet['content_bytes']<=5600
    value=reply(packet['messages']);value['items'][0]['payload']['label']=label
    decision=b.decision(json.dumps(value),packet,ctx,[])
    assert decision['status']=='accepted'
    result=b.initial();result['accepted']=decision['units']
    assert label in b.render(result) and 'unverified' in b.render(result)
    assert decision['proposal']==value


def test_bounded_diagnostics_do_not_invent_provider_or_parent_observations():
    class Client: last_metadata={'finish_reason':'stop','secret':'never copy','elapsed_seconds':999999}
    result=observed(Client(),time.monotonic())
    assert result['finish_reason']=='stop' and 'secret' not in result
    assert result['elapsed_seconds']<1 and result['parent_cleanup_confirmation']=='not_observed_here'
    Client.last_metadata={'finish_reason':'sensitive arbitrary provider text'}
    assert observed(Client(),time.monotonic())['completion_status']=='unavailable'


def test_provider_completion_survives_without_changing_other_provider_shape():
    from forensic_assistant.ai.cloud_worker import complete
    from test_response_envelope import SDK, envelope
    for route in ('openai','anthropic'):
        result=complete({'custom_llm_provider':route,'max_tokens':1024},SDK(envelope('stop')))
        assert result['text']=='{"items":[]}' and result['usage']=={}
        assert ('finish_reason' in result)==(route=='openai')


def test_incomplete_provider_output_is_still_rejected():
    from forensic_assistant.ai.cloud_worker import complete
    from forensic_assistant.ai.provider_diagnostics import ProviderFailure
    from test_response_envelope import SDK, envelope
    with pytest.raises(ProviderFailure) as caught:
        complete({'custom_llm_provider':'openai','max_tokens':1024},SDK(envelope('length')))
    assert caught.value.category=='output_truncated'


def test_complete_question_preserved_and_all_analysis_string_limits_described():
    ctx,packet=packet_context()
    value=reply(packet['messages'])
    value['items'][0].update(kind='question',payload={'text':'Which additional evidence could distinguish the alternatives?'})
    accepted=b.decision(json.dumps(value),packet,ctx,[])
    assert accepted['status']=='accepted' and accepted['proposal']==value
    def check(node):
        if node.get('type')=='string' and 'maxLength' in node:
            assert str(node['maxLength'])+' UTF-8 bytes' in node['description']
        for child in node.get('properties',{}).values():check(child)
        if 'items' in node:check(node['items'])
        for kind in ('oneOf','anyOf'):
            for child in node.get(kind,[]):check(child)
    check(openai_schema.request_schema('openai',c.schema(list(c.TOOLS))))

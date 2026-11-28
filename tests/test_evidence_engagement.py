"""Synthetic 6.191 engagement and availability acceptance; no provider requests."""
import hashlib,json
import pytest
from test_investigative_progress import session_for,notices
from test_conversational_ai import reply,call,last
from forensic_assistant.conversational_ai.service import Paused
from forensic_assistant.conversational_ai.operation_diagnostics import operation_trace
from forensic_assistant.conversational_ai.workspace import reconstruct,events,encoded


def overview(kind='event_distribution',**kwargs):
    return reply(calls=[call('activity_overview',dict(kind=kind,**kwargs))])


def inspect(messages):
    return reply(calls=[call('show_evidence',dict(evidence_id=last(messages)['records'][0]['evidence_id'],limit=3))])


@pytest.mark.parametrize('intent',['narrow','inventory'])
def test_aggregate_is_not_examination_and_inventory_can_finish(tmp_path,intent):
    session,path,before=session_for(tmp_path,[overview(),reply('Scoped inventory only.')])
    try:
        result=session.submit('Inventory',intent=intent)
        e=session.workspace.engagement()
        assert e['counts']['registered_ids']==1 and e['counts']['aggregate_operations']==1
        assert e['counts']['original_fields']==e['counts']['fields_possibly_disclosed']==e['counts']['inspection_operations']==0
        assert len(e['unexamined_ids'])==1 and e['next_tools']==['show_evidence']
        assert session.workspace.context()['engagement']==e
        assert not result['completion_assessment']['recovery_eligible']
        assert result['completion_assessment']['records_retrieved']==0
    finally:session.close()
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before
    assert reconstruct(session.journal.path,tmp_path/'a')==reconstruct(session.journal.path,tmp_path/'b')


@pytest.mark.parametrize('recover',[True,False])
def test_aggregate_final_challenge_without_repetition(tmp_path,recover):
    def challenged(messages):
        c=notices(messages)[-1]
        assert c['reason']=='original_evidence_not_examined'
        assert c['engagement']['counts']['original_fields']==0
        return reply(calls=[call('show_evidence',dict(evidence_id=c['engagement']['unexamined_ids'][0],limit=3))]) if recover else reply('Insufficient examination.')
    session,_,_=session_for(tmp_path,[overview(),reply('Would recommend inspection.'),challenged,reply('Partial original-field inspection; no causality established.')])
    try:
        if recover:
            result=session.submit('Investigate substantively',intent='broad')
            e=result['completion_assessment']['engagement']['counts']
            assert e['original_records']==1 and e['original_fields']>0 and e['fields_possibly_disclosed']>0
            assert e['inspection_operations']==1 and e['verifications']==0
        else:
            with pytest.raises(Paused,match='INCONCLUSIVE_NO_PROGRESS'):session.submit('Investigate substantively',intent='broad')
        assert session.used['completion_challenges']==1 and session.used['nonproductive_repetitions']==0
    finally:session.close()


def test_unavailable_success_is_coverage_not_information(tmp_path):
    def informed(messages):
        p=notices(messages)[-1]
        assert p['state']=='known_unavailable' and p['new_information'] is False
        assert last(messages)['records']==[] and 'guidance' not in last(messages)
        return overview()
    session,_,_=session_for(tmp_path,[overview('browser_downloads'),informed,inspect,reply('Partial.')])
    try:
        session.submit('Investigate',intent='broad')
        assert session.workspace.engagement()['counts']['unavailable_operations']==1
        assert session.used['failed_operations']==0
    finally:session.close()
    rows=operation_trace(session.journal.path)['operations']
    assert rows[0]['progress']['new_coverage']
    assert rows[0]['progress_feedback_sent_request']==2
    assert rows[0]['progress_subsequent_operations'][0]['tool']=='activity_overview'


def test_unknown_availability_not_negative_and_duplicate_count(tmp_path):
    from forensic_assistant.conversational_ai.progress import Progress
    session,_,_=session_for(tmp_path,[])
    try:
        p=Progress(session.workspace,session.scope,session.view,1)
        args={'kind':'browser_downloads'};result={'records':[],'has_more':False}
        for i in range(2):session.event('operation_progress',p.assess('A'+str(i),'activity_overview',args,result))
        assert session.workspace.engagement()['counts']['unavailable_operations']==2
        p.available={'browser':'unknown'}
        a=p.assess('A3','activity_overview',args,result)
        assert a['reason']!='known_unavailable_family'
    finally:session.close()


def test_timestamp_feedback_actual_worker_then_valid_and_out_of_scope(tmp_path):
    def corrected(messages):
        failure=last(messages)
        assert failure['parameter']=='request.end'
        assert failure['constraint']=='invalid timestamp format'
        assert 'dot' in failure['correction'] and 'not a colon' in failure['correction']
        assert '00:00:00:000' not in json.dumps(failure)
        return overview('process_images',end='2020-01-02T00:00:00.000000000Z')
    session,_,_=session_for(tmp_path,[overview('process_images',end='2020-01-02T00:00:00:000000000Z'),corrected,overview('process_images',end='2021-01-02T00:00:00Z'),reply('Partial.')])
    try:session.submit('Inventory',intent='inventory')
    finally:session.close()
    rows=operation_trace(session.journal.path)['operations']
    assert rows[0]['error'] and not rows[1].get('error') and rows[2]['error']
    assert rows[0]['error']['validation_detail']['validation_path']=='request.end'
    assert rows[2]['error']['validation_detail']['rule']=='Discovery cannot expand approved time interval'


def test_budget_refuses_aggregate_recovery(tmp_path):
    session,_,_=session_for(tmp_path,[overview(),reply('Stop')],{'requests':2})
    try:
        with pytest.raises(Paused,match='RESOURCE_LIMIT'):session.submit('Investigate',intent='broad')
        assert session.used['requests']==2 and session.used['completion_challenges']==0
    finally:session.close('RESOURCE_LIMIT')

def test_compact_context_wire_measurement(tmp_path):
    from copy import deepcopy
    from scripts.diagnose_local_provider import fixture_prompt,fixture_tokens
    from forensic_assistant.conversational_ai.local import body_for,configuration
    from forensic_assistant.conversational_ai.contracts import catalog
    measured={}
    def measure(messages):
        updated=deepcopy(messages);baseline=deepcopy(messages)
        prefix='LOCAL NOTEBOOK CONTEXT (UNTRUSTED DATA): '
        for m in baseline:
            if m.get('content','') and m['content'].startswith(prefix):
                ctx=json.loads(m['content'][len(prefix):]);ctx.pop('engagement')
                ctx['state']=session.workspace.query()
                ctx['recent_query_coverage']=json.loads(session.workspace.meta('recent_coverage') or '[]')
                m['content']=prefix+encoded(ctx)
        for name,msg in [('baseline',baseline),('updated',updated)]:
            body=body_for(configuration('http://127.0.0.1:1','synthetic'),msg,catalog(),2048)
            measured[name]=dict(serialized_bytes=len(json.dumps(body,ensure_ascii=False,separators=(',',':')).encode()),fixture_tokens=fixture_tokens(fixture_prompt(body)))
        assert len(catalog())==10
        assert measured['updated']['serialized_bytes']<session.scope['limits']['request_bytes']
        return reply('Inventory.')
    session,_,_=session_for(tmp_path,[overview(),measure])
    try:session.submit('Inventory',intent='inventory')
    finally:session.close()
    print('CONTEXT_MEASUREMENT '+json.dumps(measured,sort_keys=True))

def test_preview_truncation_and_redaction_are_not_original_examination(tmp_path):
    session,_,_=session_for(tmp_path,[])
    try:
        session.event('tool_attempt',dict(operation_id='synthetic-A',name='show_evidence',arguments={'evidence_id':'synthetic-eid'}))
        session.event('tool_result',dict(operation_id='synthetic-A',result=dict(evidence_id='synthetic-eid',fields=[{'field':'/a','truncated':True},{'field':'/b','redacted':True}],previews=[{'field':'/c','value':'synthetic'}])))
        e=session.workspace.engagement()
        assert e['counts']['inspection_operations']==1 and e['counts']['original_fields']==0
        assert e['unexamined_ids']==['synthetic-eid']
        assert session.workspace.query('fields')['items'] # retained, not silently discarded
    finally:session.close()


def test_unavailable_exact_repeats_preserve_existing_loop_guard(tmp_path):
    session,_,_=session_for(tmp_path,[overview('browser_downloads') for _ in range(6)])
    try:
        with pytest.raises(Paused,match='NONPRODUCTIVE_REPETITION'):session.submit('Investigate',intent='broad')
        # First unavailable operation already supplies feedback; two further
        # identical exhausted queries consume the existing two opportunities.
        assert session.used['requests']==3 and session.used['nonproductive_repetitions']==2
        assert session.workspace.engagement()['counts']['unavailable_operations']==3
    finally:session.close('NONPRODUCTIVE_REPETITION')

"""Disposable SQLite and mock-provider contextual inspection acceptance."""
from contextlib import closing
from copy import deepcopy
import json
import pytest
from forensic_assistant.investigation_ai import context_inspection as c, follow_up as f, autonomous as a
from forensic_assistant.investigation_ai import autonomous_policy as policy, disclosure
from forensic_assistant.investigation_ai.runner import ForensicWorker, WorkerError
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.ai import openai_schema
from test_autonomous_stage_a import grant
from test_follow_up_discovery import discovery_grant
from test_compact_disclosure import answer
from test_v4_controller import Scripted


def case(path,count=2):
    from forensic_assistant.database.db import connect,register_source,insert_events
    from forensic_assistant.database import sources
    from forensic_assistant.ingest.normalize import normalize
    with closing(connect(path)) as db:
        sid=sources.create(db,hostname='synthetic',volume_root='C:')
        sha='a'*64;register_source(db,sha,100,'synthetic.evtx')
        items=[]
        for n in range(count):
            entries=''.join(f'<Data Name="Background{i}">'+('background '*50)+'</Data>' for i in range(10))
            entries+='<Data Name="SubjectUserName">AnalystAlpha</Data><Data Name="SubjectLogonId">0x42</Data><Data Name="ObjectName">C:/lab/item.txt</Data><Data Name="ObjectType">File</Data><Data Name="ProcessName">neutral.exe</Data>'
            xml=f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="SyntheticProvider"/><EventID>900</EventID><Channel>Application</Channel><TimeCreated SystemTime="2026-09-30T12:00:0{n}Z"/></System><EventData>{entries}</EventData></Event>'
            items.append(normalize(xml,sha,'synthetic.evtx',n))
        insert_events(db,items);sources.assign(db,sid,[sha],reason='Synthetic');db.commit()
    g=discovery_grant(grant(path,[{'id':i.id,'source_type':'evtx'} for i in items]))
    g.update(contract=c.CONTRACT,tools=['show_evidence','follow_up','inspect_context'],context_inspection=deepcopy(c.LIMITS),source_ids=[sid])
    return g


def test_real_worker_context_readonly_scope_and_cleanup(tmp_path):
    path=tmp_path/'case.db';g=case(path);before=path.read_bytes()
    w=ForensicWorker(dict(case_path=str(path),semantic_enabled=False,_transaction_view=True,_stage_a=g))
    args=dict(evidence_id=g['evidence_ids'][0],category='actor')
    try:
        initial=w.call('initial',question=g['objective'])
        seed=w.call('show_evidence',{'evidence_id':args['evidence_id']},known_ids=g['evidence_ids'])
        assert 'AnalystAlpha' not in json.dumps(seed['result']['records'])
        with pytest.raises(WorkerError):w.call('inspect_context',args,known_ids=[])
        result=w.call('inspect_context',args,known_ids=[args['evidence_id']])
        assert result['evidence_state']==initial['evidence_state'] and result['database_changes']==0
        c.validate_result(g,args,result['result'])
        fields=result['result']['records'][0]['original_event_data']
        assert [(e['name'],e['value'],e['ordinal']) for e in fields]==[('SubjectUserName','AnalystAlpha',10),('SubjectLogonId','0x42',11)]
        assert all(e['truncated'] is False for e in fields)
        forged={**args,'evidence_id':g['evidence_ids'][1]}
        with pytest.raises(WorkerError):w.call('inspect_context',forged,known_ids=[forged['evidence_id']])
    finally:w.close()
    assert w.process.poll() is not None and path.read_bytes()==before


def test_mock_openai_context_pipeline_and_replay(tmp_path):
    path=tmp_path/'case.db';g=case(path);before=path.read_bytes();seen=[]
    def final(messages):
        p=json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']
        ans=answer(p);ans['interpretations']=[]
        return dict(action='final',answer=ans)
    def inspect(messages):
        body=json.loads(messages[1]['content']);p=body['UNTRUSTED FORENSIC EVIDENCE']
        assert 'inspect_context' in body['controller']['tools']
        eid=p['records'][0]['id'];seen.append(eid)
        return dict(action='tool',tool='inspect_context',arguments=dict(evidence_id=eid,category='actor'),reason='Inspect recorded actor context')
    def grounded(messages):
        p=json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']
        value=final(messages)
        matches=[(r['id'],i[1]) for r in p['records'] for i in r['observations'] if i[2]=='AnalystAlpha']
        assert matches
        value['answer']['observed']=[dict(evidence_id=matches[0][0],field=matches[0][1])]
        return value
    client=Scripted([final,inspect,grounded]);client.provider_name='openai';client.model_name='synthetic'
    result=a.run(dict(case_path=str(path),semantic_enabled=False,_transaction_view=True,_stage_a=g),g['objective'],tmp_path/'runs',client=client)
    assert result['validated_batches']==2, result.get('failure_diagnostic')
    assert result['follow_up']['context_inspections']==1 and result['metrics']['ai_requests']==3
    assert any(r['reported_value']=='AnalystAlpha' for r in result['findings']['observed'])
    assert len(result['findings']['observed'])>=2
    assert all(sum(len(m['content'].encode()) for m in openai_schema.instruct(call))<=5600 for call in client.calls)
    m,e=load(tmp_path/'runs',result['investigation_id']);f.validate_journal(m,e)
    first=a.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert first==a.reconstruct(tmp_path/'runs',result['investigation_id']) and first['findings']==result['findings']
    assert path.read_bytes()==before
    tampered=deepcopy(e)
    next(x for x in tampered if x['kind']=='context_proposed')['data']['proposal']['arguments']['category']='process'
    with pytest.raises(ValueError):f.validate_journal(m,tampered)


def test_old_grant_and_schema_and_forged_disclosure(tmp_path):
    path=tmp_path/'case.db';g=case(path);args=dict(evidence_id=g['evidence_ids'][0],category='actor')
    old=deepcopy(g);old.update(contract=f.CONTRACT,tools=['show_evidence','follow_up']);old.pop('context_inspection')
    with pytest.raises(ValueError):policy.operation(old,path,'inspect_context',args)
    policy.operation(g,path,'inspect_context',args)
    proposal=dict(action='tool',tool='inspect_context',arguments=args,reason='Inspect context')
    with pytest.raises(ValueError):f.parse(json.dumps(proposal))
    assert f.parse(json.dumps(proposal),True)==proposal
    assert openai_schema.investigation(f.schema(True))
    assert openai_schema.request_schema('openai',f.schema(True))
    empty=dict(contract=disclosure.CONTRACT,records=[],relationships=[],detections=[])
    with pytest.raises(ValueError):c.proposed(g,args,disclosure.encode(empty))
    for extra in ({'sql':'SELECT 1'},{'category':'all'},{'field':'/secret'}):
        with pytest.raises(ValueError):c.arguments(g,{**args,**extra})
    expired=deepcopy(g);expired['issued']-=301;expired['expires']-=301
    with pytest.raises(ValueError,match='EXPIRED'):policy.operation(expired,path,'inspect_context',args)


def test_temporal_search_still_works_under_context_grant(tmp_path,monkeypatch):
    import test_follow_up_discovery as legacy
    old=legacy.discovery_grant
    def contextual(g):
        g=old(g);g.update(contract=c.CONTRACT,tools=['show_evidence','follow_up','inspect_context'],context_inspection=deepcopy(c.LIMITS))
        return g
    monkeypatch.setattr(legacy,'discovery_grant',contextual)
    result,client,calls,closed,_=legacy.run_mock(tmp_path)
    assert result['validated_batches']==3 and calls.count('follow_up')==1 and closed
    assert result['follow_up']['context_inspections']==0 and len(client.calls)==4
    a.reconstruct(tmp_path/'runs',result['investigation_id'])


def test_question_grouping_keeps_history_and_negation():
    questions=['What was the recorded actor?', 'Which was the recorded actor?', 'Was the actor not recorded?','Which object was affected?']
    original=list(questions);shown=f.concise_questions(questions)
    assert len(shown)==3 and questions==original
    assert 'Was the actor not recorded?' in shown


@pytest.mark.parametrize('failure',['worker','cancel','forged','provider'])
def test_partial_findings_survive_context_failure(tmp_path,failure):
    path=tmp_path/'case.db';g=case(path);before=path.read_bytes();closed=[]
    class Worker(ForensicWorker):
        def call(self,name,*args,**kw):
            if name=='inspect_context' and failure in ('worker','cancel'):
                if failure=='cancel':raise KeyboardInterrupt()
                raise WorkerError('synthetic failure')
            return super().call(name,*args,**kw)
        def close(self):
            super().close();closed.append(self.process.poll() is not None)
    def final(m):
        ans=answer(json.loads(m[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']);ans['interpretations']=[]
        return dict(action='final',answer=ans)
    def inspect(m):
        eid=json.loads(m[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']['records'][0]['id']
        if failure=='forged':eid='EVTX:'+'b'*64+':Offset:999'
        return dict(action='tool',tool='inspect_context',arguments=dict(evidence_id=eid,category='actor'),reason='Inspect actor')
    def bad(m):raise ValueError('mock provider failure')
    client=Scripted([final,inspect,bad]);client.provider_name='openai';client.model_name='synthetic'
    result=a.run(dict(case_path=str(path),semantic_enabled=False,_transaction_view=True,_stage_a=g),g['objective'],tmp_path/'runs',client=client,worker_factory=Worker)
    assert result['validated_batches']==1 and closed and all(closed)
    assert result['termination']==dict(worker='WORKER_FAILURE',cancel='ANALYST_CANCELLED',forged='VALIDATION_FAILURE',provider='PROVIDER_FAILURE')[failure]
    assert result['answer_assessment']['status']=='PARTIAL' and path.read_bytes()==before
    assert a.reconstruct(tmp_path/'runs',result['investigation_id'])['findings']==result['findings']


def test_context_and_temporal_share_six_operations(tmp_path):
    path=tmp_path/'case.db';g=case(path)
    def propose(category):
        def response(m):
            p=json.loads(m[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']
            return dict(action='tool',tool='inspect_context',arguments=dict(evidence_id=p['records'][0]['id'],category=category),reason='Inspect retained context')
        return response
    def final(m):
        ans=answer(json.loads(m[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']);ans['interpretations']=[]
        return dict(action='final',answer=ans)
    # Four context operations plus two seeds consume all six operations.
    client=Scripted([propose(x) for x in ('actor','object','process','event')]+[final,propose('actor')])
    client.provider_name='openai';client.model_name='synthetic'
    result=a.run(dict(case_path=str(path),semantic_enabled=False,_transaction_view=True,_stage_a=g),g['objective'],tmp_path/'runs',client=client)
    assert result['state']['accepted_calls']==6 and result['metrics']['ai_requests']==6
    assert result['follow_up']['context_inspections']==4
    # Attempt six is now analysis-only; a scripted tool response is rejected.
    assert result['termination']=='VALIDATION_FAILURE'
    assert result['answer_assessment']['status']=='PARTIAL' and result['validated_batches']==1
    a.reconstruct(tmp_path/'runs',result['investigation_id'])


def test_missing_or_oversized_context_stays_unknown(tmp_path,monkeypatch):
    from forensic_assistant.investigation_ai import tools
    from forensic_assistant.retrieval import evidence
    path=tmp_path/'case.db';g=case(path)
    from forensic_assistant.investigation_ai.case import open_readonly
    with closing(open_readonly(path)) as db:
        raw=evidence.get_evidence(db,g['evidence_ids'][0]);record=tools.compact(raw)
        raw['event_data_json']=json.dumps([dict(name='SubjectUserName',value='x'*4000)])
        monkeypatch.setattr(evidence,'get_evidence',lambda *args:raw)
        result=c.inspect(db,g,dict(evidence_id=record['id'],category='actor'),{record['id']:record})
        assert result['records'][0]['original_event_data']==[]
        assert 'unknown' in ' '.join(result['plan']['limitations'])
        assert result['plan']['omitted_fields']==1

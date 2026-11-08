"""Synthetic Stage A authorization, incremental grounding and worker checks."""
import copy
import json
import time
from pathlib import Path
import pytest
from forensic_assistant.investigation_ai import autonomous as a, autonomous_policy as policy
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.investigation_ai.disclosure import decode
from forensic_assistant.investigation_ai.runner import ForensicWorker,WorkerError
from test_compact_disclosure import records,envelope,answer
from test_v4_controller import Scripted


def grant(path,rows):
    p=Path(path).resolve();info=p.stat();now=time.time()
    return dict(contract=policy.CONTRACT,id='test-grant',case=str(p),file_identity=[info.st_dev,info.st_ino],
        objective='What supports the activity?',provider='openai',model='synthetic',
        source_ids=['source-test'],families=sorted({r['source_type'] for r in rows}),
        evidence_ids=[r['id'] for r in rows],tools=['show_evidence'],start='2026-09-30T00:00:00Z',end='2026-09-30T23:59:59Z',
        temporal_policy=policy.TEMPORAL,issued=now,expires=now+300,
        limits=dict(requests=6,steps=8,seconds=300,records=200,prompt_bytes=5600,tool_calls=6,tool_seconds=45,output_tokens=1024))


def setup(tmp_path,actions=None,count=3):
    path=tmp_path/'case.db';path.touch();rows=records()
    extra=copy.deepcopy(rows[0]);extra['id']='BROWSER:'+'f'*64+':download:99';rows.append(extra);rows=rows[:count]
    for r in rows:r['source_context']={'source_ids':['source-test'],'basis':'analyst assertion'}
    g=grant(path,rows);seen=[];closed=[]
    view={'contract':'sqlite-read-view-v1','view_id':'a'*32,'file_identity':{'device':1,'inode':1}}
    class Worker:
        def __init__(self,config):pass
        def close(self):closed.append(True)
        def call(self,name,args=None,**kw):
            seen.append((name,args))
            chosen=[] if name in ('initial','check') else [next(r for r in rows if r['id']==args['evidence_id'])]
            return dict(result=envelope(chosen),evidence_state=view,fingerprint=None,database_changes=0,schema=5)
    def respond(messages):
        data=json.loads(messages[1]['content']);p=data['UNTRUSTED FORENSIC EVIDENCE']
        result=answer(p);result['unknowns']=['Inspect the distinctive registry lead.']
        return dict(action='final',answer=result)
    client=Scripted(actions or [respond]*6);client.provider_name='openai';client.model_name='synthetic'
    config=dict(case_path=str(path),_stage_a=g,_stage_a_hints={rows[-1]['id']:'distinctive registry lead'})
    return config,Worker,client,seen,closed


def test_incremental_state_drives_next_batch_and_reconstruction(tmp_path):
    config,worker,client,seen,closed=setup(tmp_path)
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert result['validated_batches']==3 and len(client.calls)==3 and closed
    assert result['termination']=='AUTHORIZED_PLAN_EXHAUSTED'
    lookups=[args['evidence_id'] for name,args in seen if name=='show_evidence']
    assert lookups[1]==config['_stage_a']['evidence_ids'][-1]  # Delta changed scheduler order.
    second=json.loads(client.calls[1][1]['content'])
    assert second['incremental']['previous_unresolved_unverified']==['Inspect the distinctive registry lead.']
    assert lookups[0] in {g['id'] for g in second['UNTRUSTED FORENSIC EVIDENCE']['records']}
    assert all(sum(len(m['content'].encode()) for m in call)<=5600 for call in client.calls)
    rebuilt=a.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert rebuilt['findings']==result['findings'] and rebuilt['validated_batches']==3
    _,events=load(tmp_path/'runs',result['investigation_id'])
    assert [e['kind'] for e in events].count('validated_delta')==3
    from forensic_assistant.investigation_ai.presentation import render
    assert 'Execution completion is not forensic completeness' in render(result)


@pytest.mark.parametrize('failure',['provider','validation','cancel'])
def test_partial_preserved_after_failure(tmp_path,failure):
    config,worker,client,seen,closed=setup(tmp_path)
    normal=next(client.actions)
    def bad(messages):
        if failure=='provider':raise ValueError('synthetic provider failure')
        if failure=='cancel':raise KeyboardInterrupt()
        value=normal(messages);value['answer']['observed'][0]['field']='/invented_execution'
        return value
    client.actions=iter([normal,bad])
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert result['validated_batches']==1 and result['findings']['observed'] and closed
    assert len(client.calls)==2
    assert a.reconstruct(tmp_path/'runs',result['investigation_id'])['findings']==result['findings']


@pytest.mark.parametrize('change',['source','tool','time','provider','expiry'])
def test_policy_blocks_expansion(tmp_path,change):
    config,worker,client,seen,closed=setup(tmp_path);g=config['_stage_a']
    if change=='expiry':g['issued']-=301;g['expires']-=301
    elif change=='provider':g['provider']='other'
    elif change=='time':g['end']='2026-10-03T00:00:00Z'
    elif change=='tool':g['tools']=['search_evidence']
    else:g['source_ids']=[]
    with pytest.raises(ValueError):policy.operation(g,config['case_path'],'show_evidence',{'evidence_id':g['evidence_ids'][0]})


def test_real_worker_denies_unapproved_tool_before_retrieval(tmp_path):
    from test_v4_worker import make_case
    path=tmp_path/'real.db';event=make_case(path)
    g=grant(path,[{'id':event['id'],'source_type':'evtx'}])
    before=path.read_bytes()
    with ForensicWorker(dict(case_path=str(path),semantic_enabled=False,_transaction_view=True,_stage_a=g)) as worker:
        initial=worker.call('initial',question='Inspect')
        assert initial['result']['records']==[]
        with pytest.raises(WorkerError,match='ADDITIONAL_SCOPE_REQUIRED'):
            worker.call('search_evidence',{'process':'powershell'},known_ids=g['evidence_ids'])
        # No source membership is authorized in this synthetic legacy fixture.
        with pytest.raises(WorkerError,match='ADDITIONAL_SCOPE_REQUIRED'):
            worker.call('show_evidence',{'evidence_id':event['id']},known_ids=g['evidence_ids'])
    assert path.read_bytes()==before


def test_request_tool_budget_stops_with_partial_coverage(tmp_path):
    config,worker,client,seen,closed=setup(tmp_path,count=7)
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert len(client.calls)==6 and result['validated_batches']==6
    assert result['termination']=='RESOURCE_BUDGET_EXHAUSTED'
    assert len([n for n,_ in seen if n=='show_evidence'])==6
    assert result['metrics']['usage_unknown']==6


def test_single_authorization_and_no_lookup_callback(tmp_path,monkeypatch):
    config,worker,client,seen,closed=setup(tmp_path)
    client.config={'cloud_acknowledged':True}
    handoff={'case':{'path':config['case_path']},'question':config['_stage_a']['objective'],
        'assessment_id':'assessment','assessment_digest':'digest',
        'hints':[{'id':eid} for eid in config['_stage_a']['evidence_ids']],
        'scope':{'start':config['_stage_a']['start'],'end':config['_stage_a']['end']}}
    assessment={'records':{eid:{'source_context':{'source_ids':['source-test']},'match':{}} for eid in config['_stage_a']['evidence_ids']}}
    from forensic_assistant.ai import readiness
    from forensic_assistant import assessment_handoff
    from forensic_assistant.investigation_ai import supervision
    monkeypatch.setattr(readiness,'status',lambda _: {'investigation_compatibility':'ready'})
    monkeypatch.setattr(assessment_handoff,'validate',lambda *a:None)
    approvals=[]
    def confirm(envelope):approvals.append(envelope);return True
    def supervised(c,q,r,**kwargs):
        assert kwargs.get('approval') is None
        return a.run(c,q,tmp_path/'runs',client=kwargs['client'],worker_factory=worker)
    monkeypatch.setattr(supervision,'run',supervised)
    result=a.start(handoff,assessment,client,confirm)
    assert len(approvals)==1 and result['validated_batches']==3


def test_real_worker_source_and_temporal_guard(tmp_path):
    from test_v4_worker import make_case
    from forensic_assistant.database.db import connect
    from forensic_assistant.database.sources import create,assign
    path=tmp_path/'real.db';event=make_case(path)
    db=connect(path)
    row=db.execute('SELECT file_sha256 FROM evidence_records WHERE evidence_id=?',(event['id'],)).fetchone()
    with db:
        sid=create(db,name='Synthetic source')
        assign(db,sid,[row[0]],reason='Synthetic test')
        second=create(db,name='Second synthetic source')
        assign(db,second,[row[0]],reason='Synthetic test')
    stamp=db.execute('SELECT timestamp_utc FROM evidence_timestamps WHERE evidence_id=?',(event['id'],)).fetchone()[0]
    db.close()
    g=grant(path,[{'id':event['id'],'source_type':'evtx'}]);g['source_ids']=[sid,second];g['start']=g['end']=stamp
    before=path.read_bytes()
    with ForensicWorker(dict(case_path=str(path),semantic_enabled=False,_transaction_view=True,_stage_a=g)) as worker:
        first=worker.call('initial',question='Inspect')
        result=worker.call('show_evidence',{'evidence_id':event['id']},known_ids=g['evidence_ids'])
        assert result['evidence_state']==first['evidence_state'] and result['result']['records']
    for key,value in [('source_ids',['not-authorized']),('source_ids',[sid]),('start','2030-01-01T00:00:00Z')]:
        denied=copy.deepcopy(g);denied[key]=value
        if key=='start':denied['end']=value
        with ForensicWorker(dict(case_path=str(path),semantic_enabled=False,_transaction_view=True,_stage_a=denied)) as worker:
            worker.call('initial',question='Inspect')
            with pytest.raises(WorkerError,match='ADDITIONAL_SCOPE_REQUIRED'):
                worker.call('show_evidence',{'evidence_id':event['id']},known_ids=g['evidence_ids'])
    assert path.read_bytes()==before


def test_new_scope_model_tool_proposal_rejected_without_execution(tmp_path):
    config,worker,client,seen,closed=setup(tmp_path)
    normal=next(client.actions)
    client.actions=iter([normal,dict(action='tool',tool='search_evidence',arguments={'process':'outside.exe'},reason='Expand')])
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert result['termination']=='VALIDATION_FAILURE' and result['validated_batches']==1
    assert not any(name=='search_evidence' for name,_ in seen)


def test_expiry_during_response_keeps_previous_delta(tmp_path):
    config,worker,client,seen,closed=setup(tmp_path);normal=next(client.actions)
    def expire(messages):
        config['_stage_a']['expires']=time.time()-1
        return normal(messages)
    client.actions=iter([normal,expire])
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert result['termination']=='AUTHORIZATION_EXPIRED' and result['validated_batches']==1
    assert len(client.calls)==2


def test_sparse_utf8_and_durable_checkpoint(tmp_path):
    config,worker,client,seen,closed=setup(tmp_path,count=1)
    config['_stage_a']['objective']='Inspect café 日本語 activity'
    checkpoints=[];config['_stage_a_checkpoint']=checkpoints.append
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert result['validated_batches']==1 and result['termination']=='AUTHORIZED_PLAN_EXHAUSTED'
    assert checkpoints[0]['findings']==result['findings']
    assert result['metrics']['prompt_bytes']==[sum(len(m['content'].encode('utf-8')) for m in client.calls[0])]
    assert result['state']['requested_calls']==result['state']['accepted_calls']==1


def test_application_rejects_worker_source_expansion_before_model(tmp_path):
    config,worker,client,seen,closed=setup(tmp_path)
    class Expanded(worker):
        def call(self,name,args=None,**kw):
            response=super().call(name,args,**kw)
            for row in response['result']['records']:
                row['source_context']['source_ids'].append('unauthorized-source')
            return response
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=Expanded)
    assert result['termination']=='ADDITIONAL_SCOPE_REQUIRED' and not client.calls and closed


def test_provider_change_stops_before_another_request(tmp_path):
    config,worker,client,seen,closed=setup(tmp_path);normal=next(client.actions)
    def changed(messages):
        client.model_name='unapproved-model'
        return normal(messages)
    client.actions=iter([normal,changed])
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert result['termination']=='PROVIDER_SCOPE_CHANGED' and result['validated_batches']==1
    assert len(client.calls)==2 and closed


def test_historical_only_field_cannot_ground_later_delta(tmp_path):
    config,worker,client,seen,closed=setup(tmp_path,count=4);normal=next(client.actions)
    historical=[]
    def first(messages):
        value=normal(messages);historical.extend(value['answer']['observed'])
        return value
    def later(messages):
        value=normal(messages)
        represented={(r['id'],o[1]) for r in json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']['records'] for o in r['observations']}
        missing=next((r for r in historical if (r['evidence_id'],r['field']) not in represented),None)
        assert missing is not None
        value['answer']['observed']=[missing]
        return value
    # Force the immediately preceding accepted support to a different record.
    def second(messages):
        value=normal(messages)
        first_id=historical[0]['evidence_id']
        value['answer']['observed']=[r for r in value['answer']['observed'] if r['evidence_id']!=first_id]
        return value
    client.actions=iter([first,second,later])
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert result['validated_batches']==2 and result['termination']=='VALIDATION_FAILURE'
    assert result['state']['rejected_requests']==1


def test_empty_assessment_never_authorizes_or_dispatches(tmp_path,monkeypatch):
    config,worker,client,seen,closed=setup(tmp_path)
    client.config={'cloud_acknowledged':True}
    from forensic_assistant.ai import readiness
    monkeypatch.setattr(readiness,'status',lambda _: {'investigation_compatibility':'ready'})
    with pytest.raises(ValueError,match='no evidence references'):
        a.start({'case':{'path':config['case_path']},'hints':[]},{'records':{}},client,
                lambda _: pytest.fail('Empty assessment must not request authorization'))
    assert not client.calls


def test_invented_interpretation_rejected_and_coverage_preserved(tmp_path):
    config,worker,client,seen,closed=setup(tmp_path,count=6);normal=next(client.actions)
    def bad(messages):
        value=normal(messages);value['answer']['interpretations']=['invented-execution-proof']
        return value
    client.actions=iter([normal,bad])
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert result['validated_batches']==1 and result['termination']=='VALIDATION_FAILURE'
    coverage=result['narrative']['coverage']
    assert coverage['inspected_records']==2 and coverage['eligible_disclosed_records']==2
    assert coverage['inspected_not_represented']


def test_stage_a_six_artifact_records_and_historical_adapters(tmp_path):
    config,worker,client,seen,closed=setup(tmp_path,count=6)
    result=a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    assert result['validated_batches']==6
    assert set(result['state']['inspected_artifact_families'])=={'browser','evtx','mft','prefetch'}
    assert result['findings']['interpretations']
    assert all('does not establish successful' in i['text'] for i in result['findings']['interpretations'])
    from forensic_assistant.reporting import transcripts
    from forensic_assistant.investigation_ai import replay
    with pytest.raises(ValueError):
        transcripts.load(tmp_path/'runs',result['investigation_id'])
    with pytest.raises(ValueError):
        replay.replay(config,tmp_path/'runs',result['investigation_id'])


def checkpoint_then_block(connection,gate,request):
    """Synthetic contained child: no provider or case access."""
    gate.wait()
    import os
    if os.name!='nt':os.setsid()
    connection.send_bytes(json.dumps({'kind':'startup_complete'}).encode())
    connection.send_bytes(json.dumps({'kind':'stage_a_checkpoint','value':request['config']['_test_checkpoint']}).encode())
    time.sleep(30)


def test_uncertain_worker_cleanup_blocks_return_to_shell(tmp_path):
    from forensic_assistant.investigation_ai.lifecycle import CleanupError
    config,worker,client,seen,closed=setup(tmp_path,count=1)
    class Uncertain(worker):
        def close(self):raise RuntimeError('synthetic cleanup failure')
    with pytest.raises(CleanupError) as failure:
        a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=Uncertain)
    assert failure.value.result['validated_batches']==1
    assert failure.value.result['cleanup']['status']=='CLEANUP_LIMITATION'


def test_supervisor_retains_checkpoint_when_child_is_terminated(tmp_path,monkeypatch):
    from forensic_assistant.investigation_ai import supervision
    from forensic_assistant.investigation_ai.state import Budget
    from forensic_assistant.llm.client import LocalClient
    config,worker,client,seen,closed=setup(tmp_path,count=1)
    checkpoints=[];config['_stage_a_checkpoint']=checkpoints.append
    a.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=client,worker_factory=worker)
    monkeypatch.setattr(supervision,'_child',checkpoint_then_block)
    result=supervision.run({'case_path':config['case_path'],'_stage_a':config['_stage_a'],
                           '_test_checkpoint':checkpoints[0]},'synthetic',tmp_path/'supervised',
                          client=LocalClient(),budget=Budget(seconds=5))
    assert result['termination']=='MAX_SECONDS'
    assert result['validated_batches']==1 and result['findings']==checkpoints[0]['findings']
    assert result['transcript_complete'] is False
    assert result.get('cleanup',{}).get('status')!='CLEANUP_LIMITATION'

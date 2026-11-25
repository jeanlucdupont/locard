"""Real supervised controller/SQLite worker; no real evidence or provider calls."""
from contextlib import closing
from copy import deepcopy
import json
import sqlite3
import time
import pytest
from forensic_assistant.investigation_ai import autonomous, supervision, extended, context_inspection, follow_up
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.llm.client import LocalClient
from test_context_inspection import case
from test_compact_disclosure import answer


def scripted_child(connection, gate, request):
    if request['config'].get('_test_worker_script'):
        from forensic_assistant.investigation_ai.runner import ForensicWorker
        ForensicWorker.worker_script=request['config']['_test_worker_script']
    class Provider:
        provider_name='openai';model_name='synthetic'
        def __init__(self):self.calls=0;self.context_id=None
        def complete(self,messages,schema=None):
            self.calls+=1
            packet=json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']
            if self.calls in (1,2,7):
                target=request['config']['_test_seed'] if self.calls==7 else None
                candidates=[(r['id'],v[1],v[2]) for r in packet['records'] for v in r['observations'] if v[1] in ('/timestamps/0/utc','/timestamp_utc') and (target is None or r['id']==target)]
                eid,field,_=max(candidates,key=lambda row:row[2])
                return json.dumps(dict(action='tool',tool='follow_up',arguments=dict(evidence_id=eid,field=field,family='evtx'),reason='Inspect authorized temporal neighbors'))
            if self.calls in (3,4,5):
                if self.context_id is None:self.context_id=packet['records'][0]['id']
                return json.dumps(dict(action='tool',tool='inspect_context',arguments=dict(evidence_id=self.context_id,category=['actor','object','process'][self.calls-3]),reason='Inspect distinct original context'))
            result=answer(packet);result['interpretations']=[]
            return json.dumps(dict(action='final',answer=result))
    supervision.LocalClient=lambda *args:Provider()
    supervision._child(connection,gate,request)


def configured(tmp_path):
    path=tmp_path/'case.db';g=case(path,count=8)
    # The second seed is outside the first neighborhood; remains pending for batch two.
    with sqlite3.connect(path) as db:
        # Dense repeated observations are irrelevant after seed retrieval but still
        # exercise the actual covering timestamp-index candidate cap.
        db.executemany('INSERT INTO evidence_timestamps(evidence_id,slot,timestamp_utc,source,meaning,normalization_status) VALUES(?,?,?,?,?,?)',
            [(g['evidence_ids'][0],f'z-density-{i:05d}','2026-09-30T12:04:00Z','synthetic','Recorded metadata','normalized') for i in range(3000)])
        for i in (1,7):
            db.execute('UPDATE evidence_timestamps SET timestamp_utc=? WHERE evidence_id=?',(f'2026-09-30T13:00:0{i}Z',g['evidence_ids'][i]))
            db.execute('UPDATE events SET timestamp_utc=? WHERE id=?',(f'2026-09-30T13:00:0{i}Z',g['evidence_ids'][i]))
    g['evidence_ids']=g['evidence_ids'][:2]
    g['contract']=context_inspection.CAPACITY_CONTRACT;g['limits']['prompt_bytes']=24576
    g=extended.authorize(g);g['expires']=g['issued']+900
    return dict(case_path=str(path),_stage_a=g,_test_seed=g['evidence_ids'][1],semantic_enabled=False)


@pytest.mark.parametrize('failure',[None,'sqlite','timeout','internal','exit','cancel'])
def test_three_real_searches_across_supervised_batches(tmp_path,monkeypatch,failure):
    config=configured(tmp_path)
    if failure:
        from pathlib import Path
        shim=tmp_path/'synthetic_worker.py'
        root=str(Path(__file__).resolve().parents[1])
        shim.write_text('import sys,time,os\n'
            f'sys.path.insert(0,{root!r})\n'
            'from forensic_assistant.investigation_ai import worker,follow_up\n'
            'original=follow_up._search\ncount=0\n'
            'def search(db,*args,**kwargs):\n'
            ' global count\n count+=1\n if count==3:\n'+
            {'sqlite':"  db.execute('WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT sum(x) FROM n').fetchone()\n",
             'timeout':'  time.sleep(20)\n',
             'cancel':'  time.sleep(20)\n',
             'internal':"  raise RuntimeError('SECRET synthetic evidence or credential')\n",
             'exit':'  os._exit(9)\n'}[failure]+
            ' return original(db,*args,**kwargs)\nfollow_up._search=search\nworker.serve()\n',encoding='utf-8')
        config['_test_worker_script']=str(shim)
    before=(tmp_path/'case.db').read_bytes()
    monkeypatch.setattr(supervision,'_child',scripted_child)
    phases=[]
    def status(phase):
        phases.append(phase)
        if failure=='cancel' and phases.count('temporal_search')==3:raise KeyboardInterrupt()
    result=supervision.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=LocalClient(),status=status)
    if failure=='cancel':
        assert result['termination']=='ANALYST_CANCELLED'
        assert result['validated_batches']==1 and len(result['work_batches'])==1
        assert result['startup_diagnostic']['cleanup_confirmed']
        assert (tmp_path/'case.db').read_bytes()==before
        assert autonomous.reconstruct(tmp_path/'runs',result['investigation_id'])['findings']==result['findings']
        return
    assert result['follow_up']['executed']==3, result
    assert result['follow_up']['context_completed']==3
    assert result['metrics']['ai_requests']==(7 if failure else 8)
    if failure:
        assert result['validated_batches']==1
        assert len(result['work_batches'])==1
        assert result['failure_diagnostic']['worker']['category']=={'sqlite':'SQLITE_QUERY_DEADLINE','timeout':'PARENT_WORKER_TIMEOUT','internal':'WORKER_INTERNAL_ERROR','exit':'WORKER_UNAVAILABLE'}[failure]
        assert result['failure_diagnostic']['worker']['deadline_exceeded']==(failure in ('sqlite','timeout'))
        assert 'SECRET' not in json.dumps(result)
        assert result['follow_up']['records_returned']==7
        assert result['primary_termination']=='WORKER_FAILURE'
        assert result['termination']==('INTEGRITY_UNCONFIRMED' if failure in ('timeout','exit') else 'WORKER_FAILURE')
    else:
        assert result['validated_batches']==2, (result['termination'],result.get('failure_diagnostic'))
        assert [v['totals']['operations'] for v in result['work_batches']]==[6,8]
        assert all(s['fetched_candidates']<=1000 for s in result['follow_up']['searches'])
        assert any(not s['complete'] for s in result['follow_up']['searches'])
    assert result['startup_diagnostic']['cleanup_confirmed']
    assert (tmp_path/'case.db').read_bytes()==before
    one=autonomous.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert one==autonomous.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert one['findings']==result['findings']
    manifest,events=load(tmp_path/'runs',result['investigation_id'])
    assert 'SECRET' not in json.dumps(events)


def test_sqlite_interrupt_reproduction_and_transaction_survival(monkeypatch):
    # Real SQLite interruption, accelerated safely; the pinned SELECT view survives.
    db=sqlite3.connect(':memory:');db.execute('BEGIN');db.execute('SELECT 1')
    monkeypatch.setitem(follow_up.LIMITS,'search_seconds',.02)
    def expensive(*args,**kwargs):
        return db.execute('WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT sum(x) FROM n').fetchone()
    monkeypatch.setattr(follow_up,'_search',expensive)
    try:
        with pytest.raises(sqlite3.OperationalError,match='interrupted'):follow_up.search(db,{}, {},{})
        assert db.in_transaction and db.execute('SELECT 1').fetchone()==(1,)
    finally:db.close()


def test_safe_diagnostic_contract_and_legacy_compatibility():
    from forensic_assistant.investigation_ai import worker_diagnostics as d, failure_diagnostics as f
    from forensic_assistant.investigation_ai.state import State,Budget
    for category in d.CATEGORIES:
        value=f.diagnostic('WORKER_FAILURE','worker_retrieval','follow_up',State(Budget()),0,0,
                           worker=d.detail(category,'temporal_search',category.endswith('TIMEOUT')))
        f.validate(value)
        value['worker']['phase']='SECRET'
        with pytest.raises(ValueError):f.validate(value)
    f.validate(f.diagnostic('WORKER_FAILURE','worker_retrieval','follow_up',State(Budget()),0,0))
    assert d.classify(ValueError('ADDITIONAL_SCOPE_REQUIRED'),'authorization_validation',False)['category']=='SEARCH_AUTHORIZATION_REJECTED'
    assert d.classify(sqlite3.DatabaseError('SECRET'),'temporal_search',False)['category']=='DATABASE_READ_VIEW_FAILURE'


def test_timestamp_query_plan_uses_existing_covering_index(tmp_path):
    config=configured(tmp_path)
    with sqlite3.connect(config['case_path']) as db:
        plan=db.execute('EXPLAIN QUERY PLAN SELECT t.timestamp_utc,t.evidence_id,t.slot FROM evidence_timestamps t INDEXED BY artifact_time CROSS JOIN evidence_records e ON e.evidence_id=t.evidence_id WHERE t.timestamp_utc>=? AND t.timestamp_utc<? AND e.source_type=? ORDER BY t.timestamp_utc,t.evidence_id,t.slot LIMIT 501',('2026-09-30T12:00:00Z','2026-09-30T12:05:00Z','evtx')).fetchall()
    assert any('COVERING INDEX artifact_time' in r[3] for r in plan)
    assert not any('TEMP B-TREE' in r[3] for r in plan)


def test_absolute_deadline_reserved_inside_five_seconds(monkeypatch):
    observed=[]
    class DB:
        def set_progress_handler(self,callback,steps):observed.append((callback,steps))
    monkeypatch.setattr(follow_up.time,'monotonic',lambda:10.0)
    monkeypatch.setattr(follow_up,'_search',lambda *args,**kwargs:kwargs['deadline'])
    assert follow_up.search(DB(),{}, {},{},deadline=14.0)==13.9
    assert follow_up.search(DB(),{}, {},{},deadline=99.0)==14.9
    assert observed[1]==(None,0) and observed[-1]==(None,0)


@pytest.mark.parametrize('payload',['[]','{"startup_diagnostic":{"stage":"SECRET"}}','{"result":null}'])
def test_protocol_failures_are_bounded(tmp_path,monkeypatch,payload):
    from forensic_assistant.investigation_ai.runner import ForensicWorker,WorkerError
    config=configured(tmp_path);script=tmp_path/'malformed_worker.py'
    script.write_text('import sys,json,os\nsys.stdin.readline()\nprint(json.dumps({"ready":True,"worker_pid":os.getpid()}),flush=True)\nsys.stdin.readline()\n'+f'print({payload!r},flush=True)\n'+'sys.stdin.read()\n',encoding='utf-8')
    monkeypatch.setattr(ForensicWorker,'worker_script',script)
    with ForensicWorker(config) as worker:
        with pytest.raises(WorkerError) as error:worker.call('initial',question='Synthetic')
        assert error.value.diagnostic['category']=='WORKER_PROTOCOL_ERROR'
        assert 'SECRET' not in str(error.value)
    assert worker.process.poll() is not None



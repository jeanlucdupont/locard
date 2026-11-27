"""6.177 retrieval equivalence, cancellable real worker and mock-provider recovery."""
import json
import sqlite3
import threading
import time
from pathlib import Path
import pytest
from test_conversational_ai import setup,reply,call
from forensic_assistant.conversational_ai.service import Session,Paused,ChatWorker
from forensic_assistant.conversational_ai.supervision import ConversationWorkerError
from forensic_assistant.conversational_ai.tools import Tools
from forensic_assistant.retrieval.evidence import EvidenceQueries

@pytest.fixture(autouse=True)
def private(tmp_path,monkeypatch):monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))

def test_bounded_equivalence_and_no_repeat_eligibility(tmp_path,monkeypatch):
    path,_,scope=setup(tmp_path,[])
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
    try:
        query=EvidenceQueries(db);args=dict(artifact='evtx',start=scope['start'],end=scope['end'],source_scope=scope['source_ids'][0])
        exact=query.search(**args,limit=1)
        bounded=query.search(**args,limit=1,exact_count=False)
        assert exact.records==bounded.records and bounded.total is None and bounded.has_more
        second=query.search(**args,limit=1,offset=1,exact_count=False)
        assert second.records==query.search(**args,limit=1,offset=1).records
        tool=Tools(db,scope)
        monkeypatch.setattr(tool,'eligible',lambda *a,**k:pytest.fail('Repeated eligibility query'))
        result=tool.execute('search_evidence',{'artifact':'evtx','limit':1})
        assert result['total'] is None and result['total_exact'] is False and result['next_offset']==1
    finally:db.close()

def shim(tmp_path,body):
    path=tmp_path/'worker_shim.py';root=str(Path(__file__).resolve().parents[1])
    path.write_text('import sys,time\n'+f'sys.path.insert(0,{root!r})\nfrom forensic_assistant.conversational_ai import worker\n'+body+'\nworker.serve()\n')
    class Synthetic(ChatWorker):worker_script=path
    return Synthetic

def test_cancel_sqlite_preserves_view_and_next_operation(tmp_path):
    path,_,scope=setup(tmp_path,[])
    worker_type=shim(tmp_path,"original=worker.Tools.execute\ndef execute(self,name,args):\n if args.get('offset')==1:\n  self.db.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) SELECT sum(x) FROM n').fetchone()\n return original(self,name,args)\nworker.Tools.execute=execute")
    before=path.read_bytes()
    with worker_type(dict(case_path=str(path),scope=scope,_transaction_view=True)) as w:
        view=w.call('chat_init',seconds=5)['evidence_state']
        timer=threading.Timer(.2,w.cancel);timer.start()
        try:
            with pytest.raises(ConversationWorkerError) as error:w.call('search_evidence',{'artifact':'evtx','offset':1},seconds=None)
        finally:timer.join()
        assert error.value.code=='ANALYST_CANCELLED' and error.value.recoverable and error.value.view==view
        assert w.call('search_evidence',{'artifact':'evtx'},seconds=None)['evidence_state']==view
    assert path.read_bytes()==before

def test_deadline_healthy_worker_and_recoverable_multi_call(tmp_path):
    path,provider,scope=setup(tmp_path,[reply(calls=[dict(id='one',name='search_evidence',arguments={'artifact':'evtx','offset':1}),dict(id='two',name='search_evidence',arguments={'artifact':'evtx'})]),reply('Partial scope only.')],{'tool_seconds':1})
    worker_type=shim(tmp_path,"original=worker.Tools.execute\ndef execute(self,name,args):\n if args.get('offset')==1:\n  self.db.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) SELECT sum(x) FROM n').fetchone()\n return original(self,name,args)\nworker.Tools.execute=execute")
    session=Session(scope,provider,lambda _:True,worker_factory=worker_type)
    try:
        session.submit('Inspect')
        assert session.used['failed_operations']==1 and session.used['successful_forensic_operations']==1
        assert not session.suspended
        tools=[m for b in session.turns for m in b if m['role']=='tool']
        assert [m['tool_call_id'] for m in tools]==['one','two']
        assert json.loads(tools[0]['content'])['error']=='OPERATION_DEADLINE'
        assert json.loads(tools[1]['content'])['records']
    finally:session.close()

def test_progress_events_and_soft_threshold(tmp_path):
    from forensic_assistant.conversational_ai.activity import Activity
    events=[];now=[100];waiting=threading.Event()
    def emit(event):
        events.append(event)
        if event['status']=='waiting':waiting.set()
    with Activity(emit,'Synthetic query',interval=.01,clock=lambda:now[0]):
        now[0]=175;assert waiting.wait(2)
    assert events[0]['status']=='started' and events[-1]['status']=='completed'
    assert any(e['status']=='slow' for e in events) and any(e['status']=='waiting' for e in events)
    assert events[-1]['elapsed_seconds']==75
    assert all(e['computational_progress']=='unavailable' and 'percent' not in e for e in events)

def test_failed_worker_suspends_no_pending_dispatch(tmp_path):
    path,provider,scope=setup(tmp_path,[reply(calls=[dict(id=str(i),name='search_evidence',arguments={'artifact':'evtx'}) for i in range(2)])])
    worker_type=shim(tmp_path,'import os\ndef execute(*a,**kw):os._exit(7)\nworker.Tools.execute=execute')
    session=Session(scope,provider,lambda _:True,worker_factory=worker_type)
    try:
        with pytest.raises(Paused):session.submit('Inspect')
        assert session.suspended and session.used['failed_operations']==1
        tools=[m for b in session.turns for m in b if m['role']=='tool']
        assert json.loads(tools[0]['content'])['error']=='WORKER_TERMINATED'
        assert json.loads(tools[1]['content'])['error']=='OPERATION_NOT_EXECUTED'
        with pytest.raises(Paused):session.submit('Continue')
        assert len(provider.calls)==1
    finally:session.close()

def test_no_hidden_sixty_second_deadline(tmp_path):
    path,_,scope=setup(tmp_path,[])
    worker_type=shim(tmp_path,"original=worker.Tools.execute\nclock=time.monotonic\ndef execute(self,name,args):\n time.monotonic=lambda:clock()+75\n return original(self,name,args)\nworker.Tools.execute=execute")
    with worker_type(dict(case_path=str(path),scope=scope,_transaction_view=True)) as worker:
        worker.call('chat_init',seconds=5)
        assert worker.call('search_evidence',{'artifact':'evtx'},seconds=None)['result']['records']

def test_cancel_pending_calls_preserves_notebook(tmp_path,monkeypatch):
    path,provider,scope=setup(tmp_path,[reply(calls=[dict(id=str(i),name='search_evidence',arguments={'artifact':'evtx','offset':i}) for i in range(3)]),reply('Retained context.')])
    worker_type=shim(tmp_path,"original=worker.Tools.execute\ndef execute(self,name,args):\n if args.get('offset')==1:\n  self.db.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) SELECT sum(x) FROM n').fetchone()\n return original(self,name,args)\nworker.Tools.execute=execute")
    session=Session(scope,provider,lambda _:True,worker_factory=worker_type)
    timer=threading.Timer(.3,session.cancel)
    original_call=session.worker.call
    def call_when_ready(name,args=None,**kwargs):
        if name=='search_evidence' and args.get('offset')==1:timer.start()
        return original_call(name,args,**kwargs)
    monkeypatch.setattr(session.worker,'call',call_when_ready)
    try:
        with pytest.raises(Paused):session.submit('Inspect')
        assert not session.suspended and not session.closed
        assert session.known and session.used['successful_forensic_operations']==1 and session.used['failed_operations']==1
        tools=[m for b in session.turns for m in b if m['role']=='tool']
        assert json.loads(tools[1]['content'])['error']=='ANALYST_CANCELLED'
        assert json.loads(tools[2]['content'])['error']=='OPERATION_NOT_EXECUTED'
        session.submit('Summarize retained context')
    finally:
        if timer.ident is not None:timer.join()
        session.close()


def test_cancellation_between_calls_is_not_discarded(tmp_path):
    path,_,scope=setup(tmp_path,[])
    with ChatWorker(dict(case_path=str(path),scope=scope,_transaction_view=True)) as worker:
        worker.call('chat_init',seconds=5)
        worker.cancel()
        with pytest.raises(ConversationWorkerError,match='ANALYST_CANCELLED'):
            worker.call('search_evidence',{'artifact':'evtx'},seconds=5)

def test_query_error_sanitized_and_projection_rolls_back(tmp_path):
    path,_,scope=setup(tmp_path,[])
    worker_type=shim(tmp_path,"original=worker.Tools.execute\ndef execute(self,name,args):\n if args.get('offset')==1:self.db.execute('SELECT * FROM private_missing_table')\n value=original(self,name,args)\n if args.get('offset')==2:value['large']='sensitive'*100000\n return value\nworker.Tools.execute=execute")
    with worker_type(dict(case_path=str(path),scope=scope,_transaction_view=True)) as worker:
        worker.call('chat_init',seconds=5)
        for offset,code in ((1,'DATABASE_QUERY_ERROR'),(2,'RESULT_PROJECTION')):
            with pytest.raises(ConversationWorkerError) as error:worker.call('search_evidence',{'artifact':'evtx','offset':offset},seconds=None)
            assert error.value.code==code and error.value.recoverable
            assert 'private' not in str(error.value) and 'sensitive' not in str(error.value)
        assert worker.call('search_evidence',{'artifact':'evtx'},seconds=None)['result']['records']

@pytest.mark.parametrize('version',[3,5])
def test_registry_userassist_semantics_with_current_command(tmp_path,monkeypatch,version):
    # Reuse the canonical fixture and retain its semantic assertions.
    import test_userassist as original
    from types import SimpleNamespace
    fixture=original.case.__wrapped__(tmp_path,SimpleNamespace(param=version))
    original.test_ingestion_identity_raw_bytes_source_and_search(fixture)
    original.test_legacy_projection_readonly_timeline_slots_and_filters(fixture)
    path,eid,_,sid,_=fixture
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
    try:
        q=EvidenceQueries(db)
        for timeline in (False,True):
            args=dict(artifact='registry',source_scope=sid,timeline=timeline,start='2010-01-01T00:00:00Z',end='2030-01-01T00:00:00Z')
            exact=q.search(**args);bounded=q.search(**args,exact_count=False)
            assert exact.records==bounded.records
    finally:db.close()

def test_browser_plan_avoids_unrelated_registry_and_preserves_occurrences(tmp_path):
    from test_browser_parser import history
    from test_browser_integration import ingest
    from forensic_assistant.database.db import connect
    from forensic_assistant.database import sources
    path=tmp_path/'case.db';db=connect(path)
    sid=sources.create(db,hostname='lab',volume_root='C:');db.commit()
    history(tmp_path/'History').close();ingest(db,tmp_path/'History',source=sid)
    profile=[];q=EvidenceQueries(db,profile=profile)
    args=dict(artifact='browser',source_scope=sid,start='2020-01-01T00:00:00Z',end='2020-01-02T00:00:00Z')
    exact=q.search(**args);profile.clear();bounded=q.search(**args,exact_count=False)
    assert exact.records==bounded.records and len(exact.records)>0
    plan=json.dumps(profile)
    assert 'registry_values' not in plan and 'exact_count' not in plan
    assert 'browser_record_occurrences' in plan or 'SCAN o' in plan
    assert 'evidence_timestamps' in plan
    # A second source sharing History bytes must be resolved by occurrence, not hash assignment.
    second=sources.create(db,hostname='other',volume_root='C:');db.commit()
    sources.assign(db,second,[exact.records[0]['file_sha256']],reason='synthetic');db.commit()
    assert q.search(**args).records==exact.records
    assert q.search(**{**args,'source_scope':second}).records==[]
    db.close()

@pytest.mark.parametrize('failure',['protocol','communication'])
def test_parent_failure_categories_and_containment(tmp_path,failure):
    path,_,scope=setup(tmp_path,[])
    worker_type=ChatWorker
    if failure=='protocol':worker_type=shim(tmp_path,"def execute(*a,**k):\n print('not-json',flush=True)\n time.sleep(20)\nworker.Tools.execute=execute")
    with worker_type(dict(case_path=str(path),scope=scope,_transaction_view=True)) as worker:
        worker.call('chat_init',seconds=5)
        if failure=='communication':
            class Broken:
                def write(self,*a):raise BrokenPipeError()
                def flush(self):pass
                def close(self):pass
            pipe=worker.process.stdin;worker.process.stdin=Broken()
        try:
            with pytest.raises(ConversationWorkerError) as error:worker.call('search_evidence',{'artifact':'evtx'},seconds=None)
            assert error.value.code==('WORKER_PROTOCOL' if failure=='protocol' else 'WORKER_COMMUNICATION')
            assert worker.process.poll() is not None and not error.value.recoverable
        finally:
            if failure=='communication':pipe.close()

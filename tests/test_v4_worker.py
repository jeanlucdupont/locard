import json
import sqlite3
import pytest
from forensic_assistant.database.db import connect,register_source
from forensic_assistant.investigation_ai.runner import ForensicWorker,WorkerError
from forensic_assistant.investigation_ai.contracts import request,TOOLS
from v1_fixtures import process
from test_ingest import SHA

def make_case(path,wal=True):
    db=connect(path)
    if wal:db.execute('PRAGMA journal_mode=WAL')
    with db:register_source(db,SHA,1,'synthetic.evtx')
    event=process(db,1,'20');db.close();return event

def config(path):return {'case_path':str(path),'semantic_enabled':False,'rule_ids':[]}

def test_short_snapshot_rejects_changed_state_and_releases_wal(tmp_path):
    path=tmp_path/'case.db';event=make_case(path)
    with ForensicWorker(config(path)) as worker:
        first=worker.call('initial',question='PowerShell')
        assert first['result']['records'] and first['database_changes']==0
        writer=sqlite3.connect(path)
        writer.execute("UPDATE events SET command_line='changed' WHERE id=?",(event['id'],));writer.commit()
        assert writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()==(0,0,0)
        with pytest.raises(WorkerError,match='EVIDENCE_STATE_CHANGED'):
            worker.call('show_evidence',{'evidence_id':event['id']},fingerprint=first['fingerprint'],known_ids=[event['id']])
        writer.close()

def test_worker_deadline_and_abnormal_termination(tmp_path):
    path=tmp_path/'case.db';make_case(path)
    worker=ForensicWorker(config(path))
    with pytest.raises(WorkerError,match='TIMEOUT'):worker.call('check',seconds=0)
    assert worker.process.poll() is not None;worker.close()
    worker=ForensicWorker(config(path));worker.process.kill();worker.process.wait()
    with pytest.raises(WorkerError):worker.call('check')
    worker.close()
    writer=sqlite3.connect(path);assert writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()==(0,0,0);writer.close()

@pytest.mark.parametrize('tool,args',[
 ('shell',{'command':'delete evidence'}),('search_evidence',{'sql':'SELECT * FROM events'}),
 ('around',{'evidence_id':'EVTX:fake','seconds':10}),('search_evidence',{'hostname':'host','limit':True}),
 ('search_evidence',{'hostname':'host','limit':100000}),('show_evidence',{'evidence_id':'x','database':'other'}),
 ('timeline',{'start':'2020-01-01T00:00:00Z','end':'2021-01-01T00:00:00Z'}),
])
def test_strict_tool_contract(tool,args):
    with pytest.raises(ValueError):request(json.dumps({'action':'tool','tool':tool,'arguments':args,'reason':'test'}),TOOLS)

def test_duplicate_json_keys_and_nonfinite_rejected():
    with pytest.raises(ValueError):request('{"action":"final","action":"tool"}',TOOLS)
    with pytest.raises(ValueError):request('{"action":NaN}',TOOLS)

def test_closed_output_registry_and_original_id_checks(tmp_path):
    from forensic_assistant.investigation_ai.contracts import catalog,validate_output
    path=tmp_path/'case.db';make_case(path)
    definitions=catalog()
    assert len(definitions)==9 and definitions['semantic_search']['requires_semantic_index']
    assert all('input_schema' in d and 'output_schema' in d for d in definitions.values())
    with ForensicWorker(config(path)) as worker:result=worker.call('initial',question='PowerShell')['result']
    validate_output(result)
    result['records'][0]['id']='EVTX:fake'
    with pytest.raises(ValueError,match='Invalid original'):validate_output(result)

def test_worker_does_not_advertise_semantics_after_stale_index_fallback(tmp_path,monkeypatch):
    import io
    from types import SimpleNamespace
    import forensic_assistant.investigation_ai.worker as module
    from forensic_assistant.retrieval.v1_planner import retrieve_question
    path=tmp_path/'case.db';make_case(path)
    generation=tmp_path/'generation';generation.mkdir();(generation/'manifest.json').write_text('{}')
    monkeypatch.setattr('forensic_assistant.artifacts.worker.limit_memory',lambda:None)
    monkeypatch.setattr('forensic_assistant.semantic.index._generation',lambda root:generation)
    monkeypatch.setattr('forensic_assistant.semantic.model.LocalModel',lambda path:SimpleNamespace(identity={'synthetic':True}))
    def fallback(queries,question,date_hint,limit,**kwargs):
        plan,context=retrieve_question(queries,question,date_hint,limit)
        return {**plan,'semantic_coverage':'unavailable','semantic_reason':'Semantic index is stale'},context
    monkeypatch.setattr('forensic_assistant.semantic.hybrid.retrieve',fallback)
    requests=[{'config':{**config(path),'semantic_enabled':True,'index_root':str(generation),'model_path':'synthetic'}},
        {'operation':'initial','question':'PowerShell','seconds':5}]
    output=io.BytesIO()
    monkeypatch.setattr(module.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(('\n'.join(json.dumps(v) for v in requests)+'\n').encode())))
    monkeypatch.setattr(module.sys,'stdout',SimpleNamespace(buffer=output))
    module.serve()
    response=json.loads(output.getvalue().splitlines()[1])
    assert response['result']['records'] and response['semantic_available'] is False

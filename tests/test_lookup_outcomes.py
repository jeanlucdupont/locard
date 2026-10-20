import json
import pytest
from forensic_assistant.investigation_ai import tools, controller, contracts
from forensic_assistant.investigation_ai.runner import WorkerError
from test_investigation_assessment import RecordingWorker, EID
from test_v4_controller import Scripted, tool, final

HOST='Host context missing or conflicting; cannot select same-host temporal neighbors'

@pytest.mark.parametrize('host,sources',[('', ['one']), (None,['one']), ('host',['one','two'])])
def test_around_no_unsafe_fallback(monkeypatch,host,sources):
    class DB:
        def execute(self,*a):return self
        def fetchone(self):return (1,)
    monkeypatch.setattr(tools,'get_evidence',lambda *a:{'host_key':host,'context':{'source_ids':sources},'timestamps':[{'slot':'attribute:128:Created','timestamp_utc':'2026-01-01T00:00:00Z'}]})
    monkeypatch.setattr(tools.EvidenceQueries,'search',lambda *a,**k:pytest.fail('unsafe search'))
    result=tools.execute(DB(),'around',{'evidence_id':EID,'timestamp_slot':'attribute:128:Created'}, {'known_ids':[EID]})
    contracts.validate_output(result)
    assert result['returned_count']==0 and not result['records']
    assert result['limitations'][0] in tools.AROUND_LIMITATIONS

class Worker(RecordingWorker):
    fail=False
    def call(self,name,*args,**kwargs):
        response=super().call(name,*args,**kwargs)
        if name=='around':
            if self.fail:raise WorkerError('Synthetic database error')
            response['result']=tools.envelope(None,'around',{'records':[],'limits':[HOST]})
        response['integrity']={'strategy':'private_sqlite_snapshot','live_case_matches':True if name=='check' else None}
        return response

def test_unresolved_continues_and_checks_integrity(tmp_path):
    worker=Worker({});client=Scripted([tool('around',{'evidence_id':EID}),final])
    result=controller.run({},'Inspect',tmp_path,client=client,worker_factory=lambda _:worker)
    assert worker.calls==['initial','around','check']
    assert result['state']['investigation_path'][-1]['outcome']=='unresolved'
    assert result['metrics']['integrity_status']=='matched'
    assert 'not evidence' in json.dumps(client.calls[-1])
    assert len(result['state']['investigation_path'])==2

def test_failed_tool_still_checks_integrity(tmp_path):
    worker=Worker({});worker.fail=True
    result=controller.run({},'Inspect',tmp_path,client=Scripted([tool('around',{'evidence_id':EID})]),worker_factory=lambda _:worker)
    assert result['termination']=='TOOL_FAILURE'
    assert worker.calls==['initial','around','check']
    assert result['metrics']['failed_lookup_tool']=='around'
    assert result['metrics']['integrity_status']=='matched'

@pytest.mark.parametrize('message,timed,status',[('TOOL_TIMEOUT',True,'check_timed_out'),('worker error',False,'check_failed'),('EVIDENCE_STATE_CHANGED',False,'changed')])
def test_integrity_reasons(tmp_path,message,timed,status):
    class Broken(Worker):
        def call(self,name,*a,**kw):
            if name=='check':raise WorkerError(message,timed_out=timed)
            return super().call(name,*a,**kw)
    worker=Broken({});worker.fail=True
    result=controller.run({},'Inspect',tmp_path,client=Scripted([tool('around',{'evidence_id':EID})]),worker_factory=lambda _:worker)
    assert result['metrics']['integrity_status']==status

def test_repeated_unresolved_lookup_is_not_executed_twice(tmp_path):
    worker=Worker({});proposal=tool('around',{'evidence_id':EID})
    result=controller.run({},'Inspect',tmp_path,client=Scripted([proposal,proposal]),worker_factory=lambda _:worker)
    assert result['termination']=='TOOL_LOOP'
    assert worker.calls==['initial','around','check']

@pytest.mark.parametrize('status,text',[('matched',None),('check_timed_out','Final integrity verification timed out.'),('check_failed','Locard could not complete final integrity verification.'),('not_checked','Final integrity verification was not performed'),('changed','The live case changed')])
def test_specific_integrity_rendering(status,text):
    from forensic_assistant.investigation_ai.presentation import render
    result={'termination':'TOOL_FAILURE','state':{},'findings':{},'metrics':{
        'integrity':{'strategy':'private_sqlite_snapshot','live_case_matches':True if status=='matched' else False if status=='changed' else None},
        'integrity_status':status,'integrity_reason':'Execution budget exhausted',
        'failed_lookup_tool':'around','failed_lookup_reason':'Forensic worker execution failed'},'limitations':[]}
    output=render(result)
    assert 'Tool: around' in output
    if text:assert text in output
    else:assert 'Warning' not in output

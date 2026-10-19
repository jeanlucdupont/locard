"""Synthetic execution clocks, approval accounting and safe request timing."""
import json
import math
import pytest
from forensic_assistant.investigation_ai import controller, timing
from forensic_assistant.investigation_ai.state import Budget
from forensic_assistant.investigation_ai.runner import WorkerError
from test_investigation_assessment import RecordingWorker, EID
from test_v4_controller import Scripted, tool, final


@pytest.fixture
def now(monkeypatch):
    value=[100.0]
    monkeypatch.setattr(timing.time,'monotonic',lambda:value[0])
    return value


def test_nested_pause_execution_and_invalid_credit(now):
    clock=timing.ExecutionClock(100,400)
    now[0]+=10
    with clock.approval_wait():
        now[0]+=200
        with clock.approval_wait():now[0]+=300
        assert clock.remaining()==290
    now[0]+=20
    assert clock.metrics()==dict(elapsed_seconds=530,execution_seconds=30,analyst_wait_seconds=500)
    assert clock.remaining()==270
    for bad in (-1,float('inf'),float('nan'),True,10000):
        with pytest.raises(ValueError):clock.credit_wait(bad)
    assert clock.wait==500
    now[0]+=1000
    assert clock.remaining()==0


@pytest.mark.parametrize('answer',[True,False,'eof','cancel','timeout'])
def test_approval_wait_not_execution_and_final_check_budget(tmp_path,now,answer):
    budgets=[]
    class Worker(RecordingWorker):
        def call(self,name,*a,**kw):
            budgets.append((name,kw['seconds']))
            now[0]+=2  # Initial retrieval, tools and final fingerprint all consume execution.
            result=super().call(name,*a,**kw)
            result['elapsed_seconds']=2
            return result
    def approve(*args):
        assert args[1]==900
        now[0]+=400
        if answer=='eof':raise EOFError()
        if answer=='cancel':raise KeyboardInterrupt()
        if answer=='timeout':raise TimeoutError()
        return answer
    def proposal(messages):
        now[0]+=3
        return tool('show_evidence',{'evidence_id':EID})
    result=controller.run({},'Inspect',tmp_path,budget=Budget(seconds=30),
        client=Scripted([proposal,final]),approval=approve,worker_factory=Worker)
    metrics=result['metrics']
    assert metrics['analyst_wait_seconds']==400
    assert metrics['execution_seconds']<30
    assert metrics['elapsed_seconds']==metrics['execution_seconds']+400
    assert any(name=='check' and seconds>=20 for name,seconds in budgets)
    assert result['termination']==('ANSWER_SUPPORTED' if answer is True else 'USER_SCOPE_REACHED' if answer=='cancel' else 'USER_REJECTED')
    assert result['state']['accepted_calls']==int(answer is True)


def test_multiple_waits_dont_drift(tmp_path,now):
    def approve(*args):now[0]+=150;return True
    actions=[tool('search_evidence',{'process':'one'}),tool('show_evidence',{'evidence_id':EID}),final]
    result=controller.run({},'Inspect',tmp_path,client=Scripted(actions),approval=approve,
                          worker_factory=RecordingWorker,budget=Budget(seconds=10))
    assert result['termination']=='ANSWER_SUPPORTED'
    assert result['metrics']['analyst_wait_seconds']==300
    assert result['metrics']['execution_seconds']==0
    assert result['state']['accepted_calls']==2


@pytest.mark.parametrize('phase',['model','tool','check'])
def test_execution_exhaustion_and_specific_causes(tmp_path,now,phase):
    class Worker(RecordingWorker):
        def call(self,name,*a,**kw):
            if name==('show_evidence' if phase=='tool' else phase):
                now[0]+=31
                raise WorkerError('TOOL_TIMEOUT',timed_out=True)
            return super().call(name,*a,**kw)
    def proposal(messages):
        if phase=='model':now[0]+=31
        return tool('show_evidence',{'evidence_id':EID})
    result=controller.run({},'Inspect',tmp_path,client=Scripted([proposal,final]),
                          worker_factory=Worker,budget=Budget(seconds=30))
    assert result['termination']=='MAX_SECONDS'
    assert result['metrics']['timeout_cause']==('final_integrity_timeout' if phase=='check' else 'execution_budget_exhausted')
    assert result['metrics']['execution_seconds']>=30
    assert result['metrics']['analyst_wait_seconds']==0


def test_provider_timeout_distinct(tmp_path,now):
    from forensic_assistant.ai.provider_diagnostics import ProviderFailure
    def fail(messages):now[0]+=2;raise ProviderFailure('timeout','timeout')
    result=controller.run({},'Inspect',tmp_path,client=Scripted([fail]),worker_factory=RecordingWorker)
    assert result['termination']=='MODEL_FAILURE'
    assert result['metrics']['timeout_cause']=='provider_request_timeout'
    assert result['metrics']['model_seconds']==2


def test_success_provider_timing_safe(tmp_path,monkeypatch,now):
    from forensic_assistant.ai import settings, readiness, diagnostics
    from forensic_assistant.ai.backend import ModelBackend, model_operation
    from forensic_assistant.ai.provider_diagnostics import render
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    monkeypatch.setenv('DEEPSEEK_API_KEY','PRIVATE-KEY')
    client=ModelBackend(config={**settings.defaults(),'provider':'deepseek','model':'deepseek-flash','cloud_acknowledged':True})
    def respond(*args,**kw):
        now[0]+=18.4
        return {'text':'{"answer":"PRIVATE-EVIDENCE"}','usage':{'total_tokens':12,'prompt':'PRIVATE-PROMPT','completion_tokens':True}}
    monkeypatch.setattr(client,'_cloud_request',respond)
    with model_operation('investigation'):
        client._cloud([{'role':'user','content':'PRIVATE-PROMPT'}],{'type':'object'})
    text=diagnostics.tail('provider.log')
    row=json.loads(text)
    assert row['operation']=='investigation' and row['status']=='success'
    assert row['elapsed_seconds']==18.4
    assert row['usage']=={'total_tokens':12}
    assert row['request_features']['structured_output']=='json_object'
    assert 'PRIVATE' not in text
    assert 'Elapsed: 18.4 s' in render(text)
    assert 'Status: success' in render(text)

# Exercise the real supervisor/controller/forensic-worker boundaries, not only mocks.
from test_investigation_hardening import local_model


def test_supervisor_wait_credit_reaches_worker_and_final_integrity(tmp_path,local_model):
    import time
    from forensic_assistant.investigation_ai import supervision
    from forensic_assistant.llm.client import LocalClient
    from test_v4_worker import make_case,config
    from forensic_assistant.investigation_ai.transcript import load
    path=tmp_path/'synthetic.db'
    make_case(path)
    original=path.read_bytes()
    def approve(proposal,seconds):
        assert seconds==900
        time.sleep(11)
        return True
    result=supervision.run(config(path),'PowerShell',tmp_path/'runs',
        budget=Budget(steps=1,seconds=10),approval=approve,
        client=LocalClient(f'http://127.0.0.1:{local_model.server_port}'))
    assert result['termination']=='BUDGET_EXHAUSTED',result
    assert result['state']['accepted_calls']==1
    assert result['metrics']['elapsed_seconds']>11
    assert result['metrics']['execution_seconds']<10
    assert result['metrics']['analyst_wait_seconds']>=11
    assert result['metrics']['integrity']['live_case_matches'] is True
    assert path.read_bytes()==original
    _,events=load(tmp_path/'runs',result['investigation_id'])
    terminal=next(event['data'] for event in events if event['kind']=='terminal')
    assert terminal['metrics']['analyst_wait_seconds']==result['metrics']['analyst_wait_seconds']


def test_tool_watchdog_cause_distinct_from_execution(tmp_path,now):
    class Worker(RecordingWorker):
        def call(self,name,*a,**kw):
            if name=='show_evidence':
                now[0]+=4
                raise WorkerError('TOOL_TIMEOUT',timed_out=True)
            return super().call(name,*a,**kw)
    result=controller.run({},'Inspect',tmp_path,client=Scripted([tool('show_evidence',{'evidence_id':EID})]),
                          worker_factory=Worker,budget=Budget(seconds=30,tool_seconds=4))
    assert result['metrics']['timeout_cause']=='tool_timeout'
    assert result['termination']=='BUDGET_EXHAUSTED'


def test_debug_timing_has_no_evidence(tmp_path,caplog):
    import logging
    with caplog.at_level(logging.DEBUG,logger='forensic_assistant.investigation_ai'):
        result=controller.run({},'PRIVATE QUESTION',tmp_path,client=Scripted([tool('show_evidence',{'evidence_id':EID}),final]),
            approval=lambda *args:True,worker_factory=RecordingWorker)
    for phase in ('model_request','validation','final_fingerprint','finalization'):
        assert 'stage='+phase in caplog.text
    assert 'phase=approval_wait' in caplog.text and 'remaining_execution_budget=' in caplog.text
    assert EID not in caplog.text and 'PRIVATE QUESTION' not in caplog.text

"""Synthetic loopback protocol and read-only orchestration; no real model."""
import copy
import json
import time
import pytest
from forensic_assistant.conversational_ai import local
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from forensic_assistant.conversational_ai.contracts import authorize,arguments,FAMILIES,catalog
from forensic_assistant.conversational_ai.service import Session,Paused
from forensic_assistant.conversational_ai.resources import request_capacity
from scripts.diagnose_local_provider import MockEndpoint,wire,simulated
from test_conversational_ai import setup,reply,call

@pytest.fixture(autouse=True)
def private(tmp_path,monkeypatch):monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))

@pytest.mark.parametrize('endpoint',['http://192.168.1.2:8080','http://example.org','https://127.0.0.1','http://127.0.0.1@evil.example','http://127.0.0.1/redirect','http://127.0.0.1?target=cloud'])
def test_nonloopback_and_redirect_targets_rejected(endpoint):
    with pytest.raises(ValueError):local.configuration(endpoint,'synthetic')

def test_canonical_endpoint_and_context():
    value=local.configuration('http://localhost:8080/v1','synthetic',32768)
    assert value['endpoint']=='http://127.0.0.1:8080'
    assert local.checked(value)==value
    with pytest.raises(ValueError):local.checked({**value,'context_tokens':float('nan')})
    from forensic_assistant.conversational_ai.contracts import DEFAULTS
    assert request_capacity('synthetic',{**DEFAULTS,'output_tokens':2048},value)[0]==28672-local.wire_overhead(value,2048)

@pytest.mark.parametrize('kind',['duplicate','arguments','length','legacy','unknown_finish','usage','object_calls'])
def test_invalid_native_responses(kind):
    value=wire(reply(calls=[call('note',{'kind':'hypothesis','text':'Unverified','status':'active'})]))
    msg=value['choices'][0]['message']
    if kind=='duplicate':msg['tool_calls']*=2
    if kind=='arguments':msg['tool_calls'][0]['function']['arguments']='not-json'
    if kind=='length':value['choices'][0]['finish_reason']='length'
    if kind=='legacy':msg['function_call']={'name':'note'}
    if kind=='unknown_finish':value['choices'][0]['finish_reason']='other'
    if kind=='usage':value['usage']={'total_tokens':-1}
    if kind=='object_calls':msg['tool_calls']={'name':'note'}
    with pytest.raises(ProviderFailure):local.parse(value)

def test_native_multiple_calls_unknown_usage_and_prose():
    value=wire(reply(calls=[dict(id='1',name='note',arguments={}),dict(id='2',name='memory',arguments={})]))
    value.pop('usage')
    parsed=local.parse(value)
    assert [c['id'] for c in parsed['tool_calls']]==['1','2'] and parsed['usage']=={}
    assert not local.parse(wire(reply('call search_evidence {"artifact":"evtx"}')))['tool_calls']

def test_full_local_protocol_memory_recovery(tmp_path):
    result=simulated(tmp_path)
    assert all(result['checks'].values()) and result['sequential_mode']
    assert result['protocol_requests']==result['usage']['requests']
    assert result['usage']['memory_operations']==2 and result['usage']['context_consolidations']>0

def test_local_binding_and_small_envelope_fail_before_provider(tmp_path,monkeypatch):
    path,_,old=setup(tmp_path,[])
    client=ModelBackend.local_conversation('http://127.0.0.1:1','synthetic',4096)
    scope=authorize(path,old['source_ids'],old['start'],old['end'],FAMILIES,'local','synthetic',{'output_tokens':512},local=client.conversation_binding())
    monkeypatch.setattr(client,'converse',lambda *a,**k:pytest.fail('Unexpected inference'))
    s=Session(scope,client,lambda _:True)
    try:
        with pytest.raises(Paused,match='CONTEXT_CAPACITY'):s.submit('Inspect synthetic evidence.')
        client.endpoint='http://127.0.0.1:2'
        with pytest.raises(ValueError,match='LOCAL_PROVIDER_CHANGED'):s.admit('requests')
        with pytest.raises(ValueError):s.workspace.bound({**scope,'local':{**scope['local'],'endpoint':client.endpoint}},s.view)
    finally:s.close()
    with pytest.raises(ValueError):authorize(path,old['source_ids'],old['start'],old['end'],FAMILIES,'local','synthetic')

def test_memory_filter_guidance_and_no_authority(tmp_path):
    with pytest.raises(ValueError,match='MEMORY_FILTER_MISMATCH'):arguments('memory',{'kind':'fields','query':'secret'})
    path,provider,scope=setup(tmp_path,[reply(calls=[call('memory',{'kind':'evidence','query':'filename'})]),reply('No result is not absence.')])
    s=Session(scope,provider,lambda _:True)
    try:
        s.submit('Inspect memory.')
        result=json.loads(next(m['content'] for m in provider.calls[-1] if m['role']=='tool'))
        assert 'query: notes' in result['argument_guidance']
        assert not s.known and s.used['failed_operations']==1
    finally:s.close()

def test_network_failure_has_no_cloud_fallback(monkeypatch):
    client=ModelBackend.local_conversation('http://127.0.0.1:1','synthetic')
    monkeypatch.setattr(client,'_cloud_request',lambda *a,**k:pytest.fail('Cloud fallback'))
    with pytest.raises(ProviderFailure) as caught:client.converse([{'role':'user','content':'harmless'}],catalog(),timeout=3,output_tokens=100)
    assert caught.value.category in ('network_error','timeout')

def test_timeout_contains_request_child(monkeypatch):
    children=[];original=local.subprocess.Popen
    def track(*a,**k):
        child=original(*a,**k);children.append(child);return child
    monkeypatch.setattr(local.subprocess,'Popen',track)
    def slow(body):time.sleep(3);return wire(reply('Too late'))
    with MockEndpoint(slow) as server:
        client=ModelBackend.local_conversation(server.endpoint,'synthetic')
        with pytest.raises(ProviderFailure) as caught:client.converse([{'role':'user','content':'test'}],catalog(),timeout=1,output_tokens=100)
        assert caught.value.category=='timeout'
        assert children and all(c.poll() is not None for c in children)

def test_keyboard_interrupt_closes_child(monkeypatch):
    from forensic_assistant.investigation_ai import lifecycle
    events=[]
    class Child:
        pid=123;returncode=None
        def communicate(self,*a,**k):raise KeyboardInterrupt()
        def poll(self):return self.returncode
        def kill(self):events.append('kill');self.returncode=-1
        def wait(self,timeout):events.append('wait');return self.returncode
    class Job:
        def __init__(self,pid):pass
        def close(self):events.append('job')
    monkeypatch.setattr(local.subprocess,'Popen',lambda *a,**k:Child())
    monkeypatch.setattr(lifecycle,'WorkerJob',Job)
    with pytest.raises(KeyboardInterrupt):local.dispatch(local.configuration('http://127.0.0.1:1','synthetic'),[],[],30,100)
    assert 'kill' in events and 'wait' in events


def test_local_options_cannot_silently_select_cloud():
    from types import SimpleNamespace
    from forensic_assistant.conversational_ai.cli import _run
    output=[]
    assert _run(SimpleNamespace(local_model='synthetic'),read=lambda _:pytest.fail('No approval needed for invalid options'),write=output.append)==2
    assert 'No provider request' in output[0]


def test_full_wire_capacity_before_child(monkeypatch):
    config=local.configuration('http://127.0.0.1:1','synthetic',4096)
    monkeypatch.setattr(local.subprocess,'Popen',lambda *a,**k:pytest.fail('Oversized request dispatched'))
    with pytest.raises(ProviderFailure) as caught:local.dispatch(config,[{'role':'user','content':'x'*4000}],catalog(),30,512)
    assert caught.value.category=='local_context_exhausted'


def test_redirect_not_followed(monkeypatch):
    addresses=[]
    class Response:
        status=302
        def read(self,*a):return b'{}'
    class Connection:
        def __init__(self,host,port,timeout):addresses.append((host,port))
        def request(self,*a,**k):pass
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr(local.http.client,'HTTPConnection',Connection)
    with pytest.raises(ProviderFailure):local.http_json(local.configuration('http://127.0.0.1:1234','synthetic'),'/v1/models')
    assert addresses==[('127.0.0.1',1234)]


def test_live_protocol_diagnostic_against_mock():
    from scripts.diagnose_local_provider import probe
    def respond(body):
        if body['tool_choice']=='required':return wire(reply(calls=[dict(id='echo-1',name='synthetic_echo',arguments={'text':'locard-local-test'})]))
        if any(m['role']=='tool' for m in body['messages']):
            assert next(m for m in body['messages'] if m['role']=='tool')['tool_call_id']=='echo-1'
        return wire(reply('Harmless synthetic response.'))
    with MockEndpoint(respond) as server:
        result=probe(ModelBackend.local_conversation(server.endpoint,'synthetic'))
        assert all(result['checks'].values()) and len(server.calls)==3


def test_real_model_synthetic_mode_without_real_model(tmp_path):
    from scripts.diagnose_local_provider import synthetic_investigation
    with MockEndpoint(lambda _:wire(reply('Insufficient inspection; no conclusion supported.'))) as server:
        result=synthetic_investigation(tmp_path,ModelBackend.local_conversation(server.endpoint,'synthetic'))
        assert all(result['checks'].values()) and result['diagnostic_request_ceiling']==12
        assert not result['observations']['verification'] and result['observations']['final_response']

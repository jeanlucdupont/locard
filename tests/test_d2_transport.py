"""Actual installed SDK serialization, only in-memory HTTP; no provider access."""
import hashlib
import json
import socket
import pytest
from forensic_assistant.investigation_ai import d2_wire as w
from forensic_assistant.ai import cloud_worker, d2_transport
from test_d2_execution import prepared, response, generic_packet, scenarios


@pytest.fixture
def sdk(monkeypatch):
    monkeypatch.setenv('LITELLM_LOCAL_MODEL_COST_MAP','True')
    monkeypatch.setenv('LITELLM_TELEMETRY','False')
    monkeypatch.setenv('DO_NOT_TRACK','1')
    monkeypatch.setenv('OPENAI_API_KEY','synthetic-not-a-key')
    monkeypatch.setattr(socket.socket,'connect',lambda *a,**k:pytest.fail('network prohibited'))
    monkeypatch.setattr(socket,'create_connection',lambda *a,**k:pytest.fail('network prohibited'))
    litellm=pytest.importorskip('litellm')
    pytest.importorskip('openai')
    from litellm._service_logger import ServiceLogging
    monkeypatch.setattr(ServiceLogging,'_dispatch_from_sync',staticmethod(lambda *a,**k:None))
    litellm.telemetry=False
    return litellm


@pytest.mark.parametrize('outcome',['success','refusal','truncated','provider_failure'])
def test_actual_serialization_no_retry(sdk,monkeypatch,outcome):
    import httpx
    p=prepared();seen=[]
    raw=json.dumps(response(p.packet))
    def handle(req):
        seen.append(req.content)
        assert req.content==p.body and len(req.content)<=5600
        if outcome=='provider_failure':return httpx.Response(400,json={'error':{'message':'SENSITIVE_VALUE','type':'invalid_request_error'}})
        msg={'role':'assistant','content':raw}
        if outcome=='refusal':msg.update(content=None,refusal='Refused')
        return httpx.Response(200,json={'id':'mock','object':'chat.completion','created':0,'model':p.config['model'],
            'choices':[{'index':0,'message':msg,'finish_reason':'length' if outcome=='truncated' else 'stop'}],
            'usage':{'prompt_tokens':1,'completion_tokens':1,'total_tokens':2}})
    factory=d2_transport.guarded_client
    monkeypatch.setattr(d2_transport,'guarded_client',lambda request:factory(request,httpx.MockTransport(handle)))
    request=dict(provider='openai',model=p.config['model'],messages=p.messages,schema=w.SCHEMA,
                 timeout=10,handshake=False,raw_diagnostics=False,final_only=False,d2_body_sha256=hashlib.sha256(p.body).hexdigest())
    if outcome=='success':
        result=cloud_worker.generate(request,sdk)
        assert result['text']==raw and result['finish_reason']=='stop'
    else:
        with pytest.raises(Exception):cloud_worker.generate(request,sdk)
    assert len(seen)==1


@pytest.mark.parametrize('mutation',['changed_bytes','oversized','wrong_digest','wrong_model','second_attempt'])
def test_actual_transport_rejects_before_network(sdk,mutation):
    import httpx
    p=prepared();seen=[]
    request=dict(provider='openai',model=p.config['model'],messages=p.messages,schema=w.SCHEMA,timeout=10,
                 _key='synthetic-not-a-key',d2_body_sha256=hashlib.sha256(p.body).hexdigest())
    if mutation=='oversized':request['messages']=[dict(role='user',content='x'*6000)]
    if mutation=='wrong_digest':request['d2_body_sha256']='0'*64
    if mutation=='wrong_model':request['model']='different-model'
    def handle(req):
        seen.append(1);return httpx.Response(200,json={})
    if mutation in ('oversized','wrong_digest','wrong_model'):
        with pytest.raises(ValueError):d2_transport.guarded_client(request,httpx.MockTransport(handle))
    else:
        with d2_transport.guarded_client(request,httpx.MockTransport(handle)) as client:
            http=client._client
            if mutation=='second_attempt':
                http.post('https://api.openai.com/v1/chat/completions',content=p.body)
            with pytest.raises(ValueError):
                http.post('https://api.openai.com/v1/chat/completions',content=p.body+(b' ' if mutation=='changed_bytes' else b''))
    assert len(seen)==int(mutation=='second_attempt')


@pytest.mark.parametrize('name',list(scenarios))
def test_generic_actual_sdk_body(sdk,monkeypatch,name):
    import httpx
    packet=generic_packet(name);messages=w.messages(packet);expected=w.body(messages,'gpt-6.1-sol');seen=[]
    def handle(req):
        seen.append(req.content)
        assert req.content==expected
        return httpx.Response(200,json={'id':'mock','object':'chat.completion','created':0,'model':'gpt-6.1-sol',
            'choices':[{'index':0,'message':{'role':'assistant','content':'{}'},'finish_reason':'stop'}]})
    factory=d2_transport.guarded_client
    monkeypatch.setattr(d2_transport,'guarded_client',lambda request:factory(request,httpx.MockTransport(handle)))
    request=dict(provider='openai',model='gpt-6.1-sol',messages=messages,schema=w.SCHEMA,
                 timeout=10,handshake=False,raw_diagnostics=False,final_only=False,d2_body_sha256=hashlib.sha256(expected).hexdigest())
    if len(expected)>5600:
        with pytest.raises(ValueError):cloud_worker.generate(request,sdk)
        assert seen==[]
    else:
        cloud_worker.generate(request,sdk);assert len(seen)==1
    print(name,len(expected),'network=0')

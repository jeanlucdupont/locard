"""Quality profile actual SDK serialization, only mock HTTP transport."""
import copy
import hashlib
import json
import pytest
from test_d2_transport import sdk
from test_d2_execution import generic_packet,scenarios
from test_d2_quality import answer
from forensic_assistant.investigation_ai import d2_quality as q,d2_wire as w
from forensic_assistant.ai import d2_transport,cloud_worker


@pytest.mark.parametrize('name',list(scenarios))
def test_quality_sdk_bytes(sdk,monkeypatch,name):
    import httpx
    p=generic_packet(name);messages=q.messages(p);schema=w.schema_for(messages);body=w.body(messages,'gpt-6.1-sol',schema);seen=[]
    def handle(request):
        assert request.content==body;seen.append(len(request.content))
        return httpx.Response(200,json={'id':'mock','object':'chat.completion','created':0,'model':'gpt-6.1-sol',
            'choices':[{'index':0,'message':{'role':'assistant','content':json.dumps(answer('no_material_inference'))},'finish_reason':'stop'}]})
    factory=d2_transport.guarded_client
    monkeypatch.setattr(d2_transport,'guarded_client',lambda r:factory(r,httpx.MockTransport(handle)))
    request=dict(provider='openai',model='gpt-6.1-sol',messages=messages,schema=schema,timeout=10,
                 handshake=False,raw_diagnostics=False,final_only=False,d2_body_sha256=hashlib.sha256(body).hexdigest())
    if len(body)>5600:
        with pytest.raises(ValueError):cloud_worker.generate(request,sdk)
        assert seen==[]
    else:
        result=cloud_worker.generate(request,sdk)
        assert result['finish_reason']=='stop' and len(seen)==1
        assert q.parse(q.expand_response(result['text'],p))['reasoning_outcome']=='no_material_inference'
    obj=json.loads(body)
    # Additive partition: serialized system string, user string, response-format
    # value; all outer keys/punctuation/request fields are the remainder.
    import httpx
    enc=lambda v:httpx.Request('POST','https://example.invalid',json=v).content
    system=len(enc(messages[0]['content']));user=len(enc(messages[1]['content']));schema=len(enc(obj['response_format']))
    canonical=copy.deepcopy(obj['response_format']);canonical['json_schema']['schema']=schema
    view=json.loads(messages[1]['content']);empty=copy.deepcopy(view)
    for key in ('supports','interpretations','relationships','qualifications','sources'):empty[key]=[] if isinstance(empty[key],list) else {}
    print('QUALITY_EVIDENCE',name,len(enc(w.J(view)))-len(enc(w.J(empty))),'adaptation',len(enc(obj['response_format']))-len(enc(canonical)))
    print('QUALITY_BYTES',name,len(body),'system',system,'user',user,'schema',schema,'outer',len(body)-system-user-schema)

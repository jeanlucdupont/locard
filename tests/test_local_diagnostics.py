import io
import json
from types import SimpleNamespace as NS
import pytest
from forensic_assistant.ai import local_diagnostics as d, raw_diagnostics as r, diagnostics
from forensic_assistant.llm.client import LocalClient, LLMError

@pytest.mark.parametrize('text,finish,category',[
 ('{"status":"ok"}','stop','structured_validation_passed'),
 ('not json','stop','response_parse_failed'),
 ('{"status":3}','stop','structured_validation_failed'),
 ('{"status":','length','output_truncated')])
def test_local_response(monkeypatch,text,finish,category):
    logs=[];requests=[]
    monkeypatch.setattr(diagnostics,'append',lambda path,line:logs.append(line))
    payload=json.dumps({'choices':[{'finish_reason':finish,'message':{'content':text}}],'usage':{'prompt_tokens':1400,'completion_tokens':20}}).encode()
    connection=NS(request=lambda *a,**k:requests.append(k),getresponse=lambda:NS(status=200,read=lambda n:payload),close=lambda:None)
    monkeypatch.setattr('http.client.HTTPConnection',lambda *a,**k:connection)
    r.clear();r.enabled=True
    schema={'type':'object','properties':{'status':{'type':'string'}},'required':['status'],'additionalProperties':False}
    try:
        if finish=='length':
            with pytest.raises(LLMError):LocalClient().complete([],schema)
        else:assert LocalClient().complete([],schema)==text
        assert json.loads(logs[-1])['local_request']==category
        assert json.loads(logs[-1])['prompt_plus_output_budget']==2424
        body=json.loads(requests[0]['body'])
        assert body['max_tokens']==1024 and body['chat_template_kwargs']=={'enable_thinking':False}
        assert body['response_format']['json_schema']['schema']==schema
        assert text in r.display()
        assert text not in logs[-1]
    finally:r.clear()


def test_benign_error_word_not_failure(monkeypatch):
    categories=[]
    monkeypatch.setattr(diagnostics,'record',categories.append)
    diagnostics.drain(io.BytesIO(b'info error rate = 0\nloaded without errors\n'))
    assert categories==[]


def test_context_http_failure(monkeypatch):
    logs=[]
    monkeypatch.setattr(diagnostics,'append',lambda p,l:logs.append(l))
    payload=b'{"error":{"type":"exceed_context_size_error","message":"PRIVATE","n_prompt_tokens":3006,"n_ctx":2048}}'
    connection=NS(request=lambda *a,**k:None,getresponse=lambda:NS(status=400,read=lambda n:payload),close=lambda:None)
    monkeypatch.setattr('http.client.HTTPConnection',lambda *a,**k:connection)
    r.clear()
    with pytest.raises(LLMError):LocalClient().complete([])
    assert json.loads(logs[-1])['local_request']=='context_exhausted'
    assert json.loads(logs[-1])['n_prompt_tokens']==3006
    assert json.loads(logs[-1])['n_ctx']==2048
    assert 'PRIVATE' not in logs[-1] and not r._entries

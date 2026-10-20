import json
from types import SimpleNamespace as NS
import pytest
from forensic_assistant.ai import gemini_adapter as g, readiness, cloud_worker
from forensic_assistant.ai.provider_diagnostics import ProviderFailure

def response(content,finish='stop',**kw):
    return NS(choices=[NS(finish_reason=finish,message=NS(content=content,**kw))])

def test_string():
    text,detail=g.extract(response('{"status":"ok"}'))
    assert g.validate_response(text,readiness.SCHEMA,detail)==text

@pytest.mark.parametrize('value',[{'status':'ok'},['text'],None])
def test_unsupported_shapes_fail_closed(value):
    with pytest.raises(ProviderFailure) as e:g.extract(response(value,parsed={'status':'ok'}))
    assert e.value.metadata['gemini_response']['phase']=='extraction'
    assert e.value.metadata['gemini_response']['content_type']==g.kind(value)

@pytest.mark.parametrize('text,phase,rule',[
    ('{"status":"SECRET"}','wire_validation','enum'),('{}','wire_validation','required'),
    ('{"status":"ok","SECRET":"PRIVATE"}','wire_validation','additionalProperties'),
    ('[]','wire_validation','type'),('```json\n{}\n```','json_parse',None)])
def test_precise_failure_without_values(text,phase,rule):
    raw,detail=g.extract(response(text))
    with pytest.raises(ProviderFailure) as e:g.validate_response(raw,readiness.SCHEMA,detail)
    metadata=e.value.metadata
    assert metadata['gemini_response']['phase']==phase
    assert 'SECRET' not in json.dumps(metadata) and 'PRIVATE' not in json.dumps(metadata)
    if rule:assert metadata['validation_diagnostics']['errors'][0]['validator_keyword']==rule

def test_length_is_extraction_not_enum():
    with pytest.raises(ProviderFailure) as e:g.extract(response('',finish='length'))
    assert e.value.metadata['gemini_response']['finish_reason']=='length'
    assert e.value.metadata['gemini_response']['json_parse']=='not_attempted'

def test_native_parameters(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY','synthetic')
    kwargs=cloud_worker.request_kwargs(dict(provider='gemini',model='gemini-3.5-flash',messages=readiness.MESSAGES,schema=readiness.SCHEMA,timeout=15,handshake=True))
    assert kwargs['response_mime_type']=='application/json'
    assert kwargs['response_json_schema']==readiness.SCHEMA
    assert 'response_format' not in kwargs

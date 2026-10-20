import json
from types import SimpleNamespace as NS
import pytest
from forensic_assistant.ai import cloud_worker, readiness, provider_diagnostics as d
from forensic_assistant.ai.anthropic_diagnostics import extract


def test_native_request(monkeypatch):
    monkeypatch.setenv('ANTHROPIC_API_KEY','synthetic')
    kw=cloud_worker.request_kwargs(dict(provider='anthropic',model='claude-sonnet-4-5',schema=readiness.SCHEMA,messages=readiness.MESSAGES,handshake=True,timeout=15))
    assert kw['model']=='anthropic/claude-sonnet-4-5'
    assert kw['custom_llm_provider']=='anthropic' and kw['max_tokens']==64
    assert kw['response_format']=={'type':'json_schema','json_schema':{'name':'forensic_analysis','strict':True,'schema':readiness.SCHEMA}}
    assert not any(k in kw for k in ('output_config','tools','tool_choice','extra_body','response_mime_type'))
    f=d.request_features(kw)
    assert f['structured_output_mechanism']=='litellm_response_format'
    assert not f['output_schema'] and f['response_format'] and not f['tools'] and not f['tool_choice']


@pytest.mark.parametrize('field',['output_config.format.schema','max_tokens','model'])
def test_error_metadata_redacted(field,monkeypatch):
    monkeypatch.setenv('ANTHROPIC_API_KEY','synthetic')
    class BadRequestError(Exception):
        status_code=400
        body={'error':{'type':'invalid_request_error','message':field+': SECRET EVIDENCE KEY'}}
    def reject(**kw):raise BadRequestError('SECRET')
    with pytest.raises(d.ProviderFailure) as caught:
        cloud_worker.generate(dict(provider='anthropic',model='claude-sonnet-4-5',schema=readiness.SCHEMA,messages=readiness.MESSAGES,handshake=True,timeout=15),NS(completion=reject))
    exc=caught.value
    assert exc.stage=='provider_request'
    assert exc.category=='invalid_request'
    assert exc.metadata['anthropic_request_field']==field
    assert exc.metadata['provider_type']=='invalid_request_error'
    logs=[]
    monkeypatch.setattr(d.diagnostics,'append',lambda path,text:logs.append(text))
    d.record('anthropic','claude-sonnet-4-5',exc.stage,exc.category,metadata=exc.metadata)
    assert 'SECRET' not in logs[0] and 'SECRET' not in d.render(logs[0])
    assert 'Request field: '+field in d.render(logs[0])


def test_unknown_message_not_guessed():
    assert extract(NS(body={'error':{'message':'SECRET: arbitrary'}}))=={'anthropic_provider_detail':'unavailable'}
    assert extract(NS(body='not JSON SECRET'))=={'anthropic_provider_detail':'unavailable'}


def test_explicit_model_error_distinct():
    assert d.classify(NS(body={'error':{'code':'model_not_found'}}))=='model_rejected'
    assert d.classify(NS(status_code=400))=='request_rejected'


@pytest.mark.parametrize('prefix',['litellm.BadRequestError: AnthropicException - ','litellm.BadRequestError: AnthropicError - '])
def test_actual_litellm_message_wrapper(prefix,monkeypatch):
    body={'type':'error','error':{'type':'invalid_request_error','code':'unsupported_parameter','param':'output_schema','message':'SECRET PROMPT EVIDENCE Authorization: KEY'}}
    detail=extract(NS(body=None,response=NS(content=b''),message=prefix+json.dumps(body)))
    assert detail=={'provider_type':'invalid_request_error','anthropic_error_code':'unsupported_parameter','anthropic_request_field':'output_schema','anthropic_error_category':'unsupported_parameter'}
    logs=[]
    monkeypatch.setattr(d.diagnostics,'append',lambda path,text:logs.append(text))
    d.record('anthropic','claude-sonnet-4-5','provider_request','request_rejected',metadata=detail)
    assert all(word not in logs[0] for word in ('SECRET','PROMPT','EVIDENCE','Authorization','KEY'))
    assert 'output_schema' in d.render(logs[0])

@pytest.mark.parametrize('message,expected',[
    ('Unsupported parameter: output_schema',{'anthropic_request_field':'output_schema','anthropic_error_category':'unsupported_parameter'}),
    ('This model does not support structured outputs.',{'anthropic_error_category':'unsupported_model_feature'}),
    ('Unknown parameter: PRIVATE',{'anthropic_provider_detail':'unavailable'}),
    ('PRIVATE'*4000,{'anthropic_provider_detail':'unavailable'}),
])
def test_conservative_messages(message,expected):
    assert extract(NS(message='litellm.BadRequestError: AnthropicException - '+message))==expected


def test_unknown_fields_rejected_at_log_boundary():
    assert d.safe_metadata({'anthropic_request_field':'SECRET','anthropic_error_code':'SECRET','anthropic_error_category':'SECRET'})=={}


@pytest.mark.parametrize('code,label',[('unsupported_feature','unsupported_feature'),('missing_beta_requirement','missing_beta_requirement'),('model_not_found','invalid_model')])
def test_nested_error_codes(code,label):
    detail=extract(NS(error={'type':'invalid_request_error','code':code,'param':'output_schema','message':'SECRET'}))
    assert detail['anthropic_error_category']==label
    assert detail['anthropic_request_field']=='output_schema'
    assert 'SECRET' not in json.dumps(detail)


def test_beta_phrase_and_feature():
    detail=extract(NS(body={'error':{'message':'Structured outputs require the structured-outputs-2025-11-13 beta header.'}}))
    assert detail=={'anthropic_error_category':'missing_beta_requirement','anthropic_feature':'structured_outputs'}


def test_type_alone_explicitly_unavailable(monkeypatch):
    detail=extract(NS(body={'error':{'type':'invalid_request_error','message':'PRIVATE UNKNOWN'}},request_id='PRIVATE'))
    assert detail=={'provider_type':'invalid_request_error','anthropic_provider_detail':'unavailable'}
    logs=[]
    monkeypatch.setattr(d.diagnostics,'append',lambda path,text:logs.append(text))
    d.record('anthropic','claude-sonnet-4-5','provider_request','request_rejected',metadata=detail)
    assert 'No safe field-level metadata available' in d.render(logs[0])
    assert 'PRIVATE' not in logs[0]

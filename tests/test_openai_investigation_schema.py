"""OpenAI wire/schema subset checks, canonical rejection and evidence-free readiness."""
import copy
import json
import pytest
from forensic_assistant.ai import openai_schema as adapter, readiness, settings, cloud_worker
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.ai.response_contract import validate
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from forensic_assistant.ai.schema_diagnostics import profiles
from forensic_assistant.investigation_ai import contracts


@pytest.fixture(autouse=True)
def isolate(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    monkeypatch.setenv('OPENAI_API_KEY','PRIVATE-SECRET')
    readiness.reset()
    yield
    readiness.reset()


def config():
    return {**settings.defaults(),'provider':'openai','model':'gpt-6-luna','cloud_acknowledged':True}


def encode(proposal,schema):
    value=copy.deepcopy(proposal)
    if value['action']=='tool':
        branch=next(v for v in schema['oneOf'] if v['properties'].get('tool',{}).get('enum')==[value['tool']])
        for key in branch['properties']['arguments']['properties']:
            value['arguments'].setdefault(key,None)
    return json.dumps({'proposal':value})


def strict_shape(node,root=True):
    assert 'oneOf' not in node and 'uniqueItems' not in node
    if root:assert node['type']=='object' and 'anyOf' not in node
    if node.get('type')=='object':
        assert node['additionalProperties'] is False
        assert set(node['required'])==set(node['properties'])
        for v in node['properties'].values():strict_shape(v,False)
    if 'items' in node:strict_shape(node['items'],False)
    for v in node.get('anyOf',[]):strict_shape(v,False)


@pytest.mark.parametrize('browser',[True,False])
def test_wire_subset_and_canonical_unchanged(browser):
    canonical=contracts.schema(list(contracts.TOOLS),browser)
    original=copy.deepcopy(canonical)
    wire=adapter.request_schema('openai',canonical)
    strict_shape(wire)
    assert canonical==original
    p=profiles('openai',canonical)
    assert p['schema_profile']['oneOf_count']==1
    assert p['schema_profile']['optional_property_count']==49
    assert p['provider_schema_profile']['optional_property_count']==0
    assert p['provider_schema_profile']['nesting_depth']<=10
    for key in ('evidence_fingerprint','metrics','audit','source_context','transcript'):
        assert key not in json.dumps(wire)


@pytest.mark.parametrize('name',list(contracts.TOOLS))
def test_each_tool_roundtrip_is_unambiguous(name):
    canonical=contracts.schema(list(contracts.TOOLS))
    args={'show_evidence':{'evidence_id':'EVTX:'+'a'*64+':Offset:1'},
          'search_evidence':{'process':'synthetic.exe'},
          'semantic_search':{'query':'synthetic'},'timeline':{'start':'2026-01-01T00:00:00Z','end':'2026-01-01T01:00:00Z'},
          'detections':{'rule_id':'synthetic'}}.get(name,{'evidence_id':'EVTX:'+'a'*64+':Offset:1'})
    proposal={'action':'tool','tool':name,'arguments':args,'reason':'Synthetic lookup'}
    raw=encode(proposal,canonical)
    decoded=adapter.response('openai',raw,canonical)
    assert json.loads(decoded)==proposal
    assert contracts.request(decoded,list(contracts.TOOLS))['tool']==name


def test_wire_valid_duplicate_final_fails_canonical():
    schema=contracts.schema([])
    final={'action':'final','answer':{'observed':[],'relationships':[],'detections':[],'hypotheses':[],'unknowns':['same','same']}}
    raw=encode(final,schema)
    validate(raw,adapter.request_schema('openai',schema))
    with pytest.raises(ProviderFailure):adapter.response('openai',raw,schema)


@pytest.mark.parametrize('raw',['not json','{"proposal":{},"extra":1}','{"proposal":{"action":"tool","tool":"shell","arguments":{},"reason":"bad"}}',
    '{"proposal":{"action":"final","answer":null}}','{"proposal":{},"proposal":{}}'])
def test_malformed_or_ambiguous_wire_rejected(raw):
    with pytest.raises(ProviderFailure):adapter.response('openai',raw,contracts.schema(list(contracts.TOOLS)))


def test_non_openai_and_advisory_unchanged():
    from forensic_assistant.interactive.advisory import SCHEMA
    assert adapter.request_schema('openai',SCHEMA) is SCHEMA
    canonical=contracts.schema(list(contracts.TOOLS))
    for provider in ('deepseek','local','anthropic','gemini','xai'):
        assert adapter.request_schema(provider,canonical) is canonical


def test_openai_wire_request_shape_and_prompt_copy():
    schema=contracts.schema(list(contracts.TOOLS))
    messages=[{'role':'system','content':'Original contract'},{'role':'user','content':'PRIVATE EVIDENCE'}]
    original=copy.deepcopy(messages)
    kwargs=cloud_worker.request_kwargs(dict(provider='openai',model='gpt-6-luna',messages=messages,schema=schema,timeout=10))
    assert kwargs['response_format']['type']=='json_schema'
    assert kwargs['response_format']['json_schema']['strict'] is True
    strict_shape(kwargs['response_format']['json_schema']['schema'])
    assert kwargs['response_format']['json_schema']['name']=='investigation_proposal'
    assert kwargs['model']=='openai/gpt-6-luna'
    assert messages==original and 'proposal' in kwargs['messages'][0]['content']
    assert kwargs['messages'][1]==messages[1]
    assert kwargs['num_retries']==0 and 'tools' not in kwargs


def test_readiness_actual_families_and_gate(monkeypatch):
    calls=[]
    probes=list(readiness.openai_probes())
    def transport(self,messages,schema,**kw):
        calls.append((messages,schema))
        if schema==readiness.SCHEMA:return {'text':'{"status":"ok"}','usage':{}}
        _,expected_schema,expected,_=probes[len(calls)-2]
        assert schema==expected_schema
        return {'text':encode(expected,schema) if adapter.investigation(schema) else json.dumps(expected),'usage':{}}
    monkeypatch.setattr(ModelBackend,'_cloud_request',transport)
    result=readiness.check(config())
    assert result['advisory_compatibility']==result['investigation_compatibility']==result['locard_compatibility']=='ready'
    assert len(calls)==4
    assert calls[2][1]==calls[3][1]==contracts.schema(list(contracts.TOOLS))
    assert 'PRIVATE' not in json.dumps(calls)


def test_advisory_ready_is_not_investigation_ready(monkeypatch):
    from forensic_assistant.interactive.advisory import SCHEMA
    calls=[]
    def transport(self,messages,schema,**kw):
        calls.append(schema)
        if schema==readiness.SCHEMA:return {'text':'{"status":"ok"}','usage':{}}
        if schema==SCHEMA:return {'text':json.dumps(next(readiness.openai_probes())[2]),'usage':{}}
        raise ProviderFailure('invalid_request')
    monkeypatch.setattr(ModelBackend,'_cloud_request',transport)
    result=readiness.check(config())
    assert result['advisory_compatibility']=='ready'
    assert result['investigation_compatibility']=='unavailable'
    assert result['locard_compatibility']!='ready'
    client=ModelBackend(config=config())
    with pytest.raises(ProviderFailure):client.complete([{'role':'user','content':'PRIVATE-EVIDENCE'}],contracts.schema(list(contracts.TOOLS)))
    assert len(calls)==3
    assert client.complete([],SCHEMA)
    assert len(calls)==4


def test_schema_profiles_and_rule_diagnostics_never_expose_values():
    from forensic_assistant.ai import provider_diagnostics as pd
    data=profiles('openai',contracts.schema(list(contracts.TOOLS)))
    data['schema_profile']['EVTX:PRIVATE']='PRIVATE'
    exc=type('BadRequestError',(Exception,),{'body':{'error':{'param':'response_format','message':"PRIVATE 'oneOf' is not permitted"}}})('PRIVATE')
    safe=pd.error_metadata(exc)
    assert safe['schema_rule']=='unsupported_oneOf'
    pd.record('openai','gpt-6-luna','provider_request','invalid_request',metadata={**data,**safe})
    raw=(settings.root()/'provider.log').read_text()
    assert 'PRIVATE' not in raw and 'properties' not in json.loads(raw)['schema_profile']
    assert 'Schema profile:' in pd.render(raw) and 'unsupported_oneOf' in pd.render(raw)


def test_final_probe_failure_cannot_mark_investigation_ready(monkeypatch):
    probes=list(readiness.openai_probes())
    calls=[]
    def transport(self,messages,schema,**kw):
        calls.append(schema)
        if len(calls)==1:return {'text':'{"status":"ok"}','usage':{}}
        if len(calls)==4:raise ProviderFailure('invalid_request')
        expected=probes[len(calls)-2][2]
        return {'text':encode(expected,schema) if adapter.investigation(schema) else json.dumps(expected),'usage':{}}
    monkeypatch.setattr(ModelBackend,'_cloud_request',transport)
    result=readiness.check(config())
    assert len(calls)==4
    assert result['advisory_compatibility']=='ready'
    assert result['investigation_compatibility']=='unavailable'
    assert result['locard_compatibility']=='failed'


def test_required_null_and_browser_disabled_filter_remain_rejected():
    schema=contracts.schema(list(contracts.TOOLS),False)
    required_null={'action':'tool','tool':'show_evidence','arguments':{'evidence_id':None},'reason':'Synthetic'}
    with pytest.raises(ProviderFailure):adapter.response('openai',encode(required_null,schema),schema)
    browser={'action':'tool','tool':'search_evidence','arguments':{'artifact':'browser'},'reason':'Synthetic'}
    with pytest.raises(ProviderFailure):adapter.response('openai',encode(browser,schema),schema)

"""Offline OpenAI request compatibility and safe briefing failure reporting."""
import copy
import json
import pytest
from forensic_assistant import briefing as b, briefing_cli
from forensic_assistant.ai import capabilities, openai_schema
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from test_briefing import Fake, item


def without_unique(node):
    if isinstance(node,dict):return {k:without_unique(v) for k,v in node.items() if k!='uniqueItems'}
    if isinstance(node,list):return [without_unique(v) for v in node]
    return node


def test_actual_openai_request_preserves_shape_and_canonical():
    before=copy.deepcopy(b.SCHEMA);messages=[{'role':'user','content':'synthetic'}]
    result=capabilities.configure({'messages':messages},'openai',b.SCHEMA)
    wire=result['response_format']['json_schema']['schema']
    assert wire==without_unique(before) and b.SCHEMA==before
    assert result['messages']==messages and 'proposal' not in wire['properties']
    nested={'type':'array','items':{'type':'object','required':['nested'],'properties':{'nested':before}},'uniqueItems':True}
    assert openai_schema._wire(nested)==without_unique(nested)
    for provider in ('anthropic','gemini','xai','deepseek'):
        assert openai_schema.request_schema(provider,b.SCHEMA) is b.SCHEMA
    assert openai_schema.request_schema('openai',{'type':'object'})=={'type':'object'}


@pytest.mark.parametrize('nested',[False,True])
def test_wire_omission_never_relaxes_canonical_uniqueness(nested):
    value=item('baje.ps1')
    if nested:value['entity_ids']=['L-one','L-one']
    raw=json.dumps({'items':[value] if nested else [value,value]})
    with pytest.raises(ProviderFailure) as failure:openai_schema.response('openai',raw,b.SCHEMA)
    assert failure.value.category=='structured_validation_failed'
    p=b.extract('baje.ps1');b.interpret(p,Fake(json.loads(raw)))
    assert p['ai_error']['rule']=='uniqueItems' and not p['ai_items']


class Raise:
    provider_name='openai'
    def __init__(self,exc):self.exc=exc
    def complete(self,*args):raise self.exc


@pytest.mark.parametrize('category,expected',[
    ('timeout','provider_transport'),('network_error','provider_transport'),
    ('authentication_failed','provider_authentication'),('authorization_failed','provider_authentication'),
    ('rate_limited','provider_rate_limit'),('invalid_request','provider_failure'),
    ('response_parse_failed','response_parsing'),('structured_validation_failed','structural_validation')])
def test_provider_categories_safe_in_json_and_human(category,expected):
    p=b.extract('SecretNarrative baje.ps1')
    exc=ProviderFailure(category,metadata={'body':'sk-SUPERSECRET SecretNarrative','message':'SecretNarrative'})
    b.interpret(p,Raise(exc),allow_cloud=True)
    assert p['ai_status']=='failed' and p['ai_error']['category']==expected and p['leads']
    assert 'SecretNarrative' not in json.dumps(p['ai_error'])
    assert 'sk-SUPERSECRET' not in briefing_cli.render(p)


def test_schema_rejection_metadata_and_cli_json(monkeypatch,capsys):
    from forensic_assistant.ai.backend import ModelBackend
    from forensic_assistant.cli import main
    exc=ProviderFailure('invalid_request','provider_request',metadata={
        'http_status':400,'rejected_parameter':'response_format','schema_rule':'unsupported_uniqueItems',
        'body':'sk-SECRET SecretNarrative'})
    monkeypatch.setattr(ModelBackend,'complete',lambda *args:(_ for _ in ()).throw(exc))
    assert main(['briefing','--text','baje.ps1','--ai','--allow-cloud','--json'])==0
    p=json.loads(capsys.readouterr().out)
    assert p['ai_error']['category']=='provider_schema_rejection'
    rendered=briefing_cli.render(p)
    assert all(s in rendered for s in ('HTTP 400','response_format','unsupported_uniqueItems'))
    assert 'sk-SECRET' not in json.dumps(p) and 'SecretNarrative' not in rendered


@pytest.mark.parametrize('raw,rule', [('not json','invalid_json'),('{"items":[],"items":[]}','duplicate_json_key'),('x'*16385,'response_size_limit')])
def test_parse_failures(raw,rule):
    class Raw(Fake):
        def complete(self,*args):return raw
    p=b.extract('baje.ps1');b.interpret(p,Raw(None))
    assert p['ai_error']['category']=='response_parsing' and p['ai_error']['rule']==rule


@pytest.mark.parametrize('change,rule', [({'category':'invented'},'enum'),({'text':None},'type')])
def test_structural_failures(change,rule):
    p=b.extract('baje.ps1');b.interpret(p,Fake({'items':[{**item('baje.ps1'),**change}]}))
    assert p['ai_error']['category']=='structural_validation' and p['ai_error']['rule']==rule


def test_missing_field_internal_failure_and_empty_success():
    p=b.extract('baje.ps1');b.interpret(p,Fake({'items':[{}]}))
    assert p['ai_error']['rule']=='required'
    b.interpret(p,Raise(RuntimeError('sk-SECRET narrative')),allow_cloud=True)
    assert p['ai_error']=={'category':'internal_failure','stage':'interpretation'}
    p=b.extract('baje.ps1');assert p['ai_status']=='not_requested'
    b.interpret(p,Fake({'items':[]}));assert p['ai_status']=='success' and p['ai_items']==[]


@pytest.mark.parametrize('change,rule', [({'start':1},'source_span'),({'entity_ids':['L-fake']},'unknown_entity'),
    ({'basis':'inferred','text':'other.ps1 executed'},'unsupported_technical_literal')])
def test_reconciliation_reason(change,rule):
    p=b.extract('baje.ps1');b.interpret(p,Fake({'items':[{**item('baje.ps1'),**change}]}))
    assert p['ai_error']['category']=='reconciliation' and p['ai_error']['rejected_items'][0]['rule']==rule
    assert rule in briefing_cli.render(p)


def test_bom_preserved_valid_categories_and_partial_status():
    text='\ufeffbaje.ps1';p=b.extract(text);identity=next(r['id'] for r in p['leads'] if r['type']=='filename')
    assert identity==next(r['id'] for r in b.extract('baje.ps1')['leads'] if r['type']=='filename')
    values=[{**item(text),'category':c,'entity_ids':[identity]} for c in ('reported_activity','hypothesis','question','ambiguity')]
    b.interpret(p,Fake({'items':values}))
    assert p['ai_status']=='success' and len(p['ai_items'])==4 and p['inputs']['original']==text
    p=b.extract(text);b.interpret(p,Fake({'items':[values[0],{**values[1],'start':1}]}))
    assert p['ai_status']=='partial' and len(p['ai_items'])==1

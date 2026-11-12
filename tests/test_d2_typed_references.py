"""Packet-derived schemas, real SDK mock transport and supervised parent validation."""
import copy
import functools
import hashlib
import json
import multiprocessing
from unittest.mock import patch

import pytest
from test_d2_quality import prepared,answer
from test_d2_execution import generic_packet,scenarios,config
from test_d2_diagnostics import sdk_call,sdk_child,USAGE,fixture
from test_d2_transport import sdk
from forensic_assistant.investigation_ai import d2_schema as policy,d2_quality as q,d2_wire as w,d2_execution as ex,d2_diagnostics as diag
from forensic_assistant.ai.openai_schema import request_schema

SIZES={'browser_only':3486,'registry_persistence':3689,'process_service':4645,
 'filesystem_no_evtx':3876,'prefetch_only':3610,'mixed':6204,'mixed_small':4543,
 'shared_path_relationship':4645,'no_relationships':3309,'contradictory_incomplete':4777,
 'large_value':5568,'extensive_qualifications':7183,'oversized_original_value':5968}


@pytest.mark.parametrize('name',scenarios)
def test_generic_packet_policy(name):
    p=generic_packet(name);before=copy.deepcopy(p)
    schema=policy.from_packet(p);fields=schema['properties']['a']['items']['properties']
    aliases=[s['alias'] for s in p['content']['supports']]
    assert fields['e']['items']==fields['c']['items']=={'type':'string','enum':aliases}
    assert fields['i']['maxItems']==0 and 'enum' not in fields['i']['items']
    assert schema==w.schema_for(q.messages(p)) and policy.recognized(schema)
    assert len(w.body(q.messages(p),'gpt-6.1-sol',schema))==SIZES[name]
    assert p==before


@pytest.mark.parametrize('mutation',['extra_alias','missing_restriction','wrong_type','wrong_category','empty_enum','extra_field'])
def test_closed_schema_recognizer(mutation):
    schema=copy.deepcopy(prepared().schema);fields=schema['properties']['a']['items']['properties']
    if mutation=='extra_alias':fields['e']['items']['enum'].append('O999')
    elif mutation=='missing_restriction':fields['c']['items'].pop('enum')
    elif mutation=='wrong_type':fields['e']['items']['type']='integer'
    elif mutation=='wrong_category':fields['e']['items']['enum']=['I1']
    elif mutation=='empty_enum':fields['i']['items']['enum']=[]
    else:schema['extra']=True
    assert not policy.recognized(schema)


@pytest.mark.parametrize('mutation',['schema','schema_digest','policy','model','source','view','packet','context'])
def test_authorization_cannot_mutate(mutation,monkeypatch):
    p=prepared();permit=ex.authorize(p,lambda _:True)
    if mutation=='schema':p.schema['properties']['a']['items']['properties']['e']['items']['enum'].append('O999')
    elif mutation=='schema_digest':permit.grant['schema_sha256']='0'*64
    elif mutation=='policy':permit.grant['schema_policy']='future'
    elif mutation=='model':p.config['model']='different'
    elif mutation=='source':p.packet['content']['source']['event_head']='0'*64
    elif mutation=='view':p.packet['content']['view']={}
    elif mutation=='packet':p.packet['packet_digest']='0'*64
    else:p._response_context['source']={}
    monkeypatch.setattr(ex,'Launch',lambda *a:pytest.fail('must not launch'))
    with pytest.raises(ValueError):ex.execute(permit)


def test_stable_identity_and_legacy():
    p=prepared();other=prepared()
    assert p.identity()==other.identity() and p.body==other.body
    assert p.preview()['schema_policy']==policy.POLICY
    permit=ex.authorize(p,lambda _:True)
    assert permit.grant['schema_sha256']==p.preview()['schema_sha256']
    old=copy.deepcopy(p.messages);old[0]['content']=q.LEGACY_GUIDE
    assert w.schema_for(old)==q.SCHEMA and w.schema_for(w.messages(p.packet))==w.SCHEMA
    assert p.history.validate(p.packet,q.expand_response(json.dumps(answer()),p.packet),**p.options)


@pytest.mark.parametrize('alias,field,reason,member',[
 ('E1','e','wrong_namespace',True),('C1','c','wrong_namespace',True),('P1','e','wrong_namespace',True),
 ('I1','e','wrong_namespace',True),('O1','i','wrong_namespace',True),('R99','e','wrong_namespace',False),
 ('O999','e','not_in_current_packet',False),('other:O1','e','malformed_reference',False),
 ('Ｏ1','e','malformed_reference',False),(1,'e','malformed_reference',False)])
def test_sanitized_reference_categories(alias,field,reason,member):
    p=prepared();v=answer();v['a'][0][field]=[alias]
    with pytest.raises(ValueError) as caught:ex.validate_model_response(p,json.dumps(v),parent=True)
    detail=diag.failure(caught.value,reported=USAGE,received=True)
    assert detail['stage']=='provider_schema' and detail['pointer']=='/a/0/'+field
    assert detail['reference_namespace']==('I' if field=='i' else 'O')
    assert detail['reference_reason']==reason and detail['other_namespace_member'] is member
    assert detail['usage_availability']=='reported'
    assert str(alias) not in json.dumps(detail) if type(alias) is str and len(alias)>1 else True
    assert detail['normalization']['canonical_validation']=='not_attempted'


def test_empty_and_omitted_interpretations():
    from forensic_assistant.ai.response_contract import validator
    p=prepared();assert p.schema['properties']['a']['items']['properties']['i']['items']['enum']==['I1']
    absent=generic_packet('browser_only');schema=policy.from_packet(absent)
    v=answer();v['a'][0]['i']=['I1']
    assert list(validator(request_schema('openai',schema)).iter_errors(v))
    # Even if an interpretation exists elsewhere, only this packet supplies enums.
    v['a'][0]['i']=[]
    assert not list(validator(request_schema('openai',schema)).iter_errors(v))
    with pytest.raises(ValueError):policy.build([],[])


def test_multiple_interpretations_max_table_sdk(sdk):
    import httpx
    from openai import OpenAI
    from forensic_assistant.ai.response_contract import validator
    schema=policy.build(['O'+str(i) for i in range(1,13)],['I'+str(i) for i in range(1,5)])
    assert policy.recognized(schema)
    adapted=request_schema('openai',schema);v=answer();v['a'][0]['e']=['O12'];v['a'][0]['i']=['I4']
    assert not list(validator(adapted).iter_errors(v))
    v['a'][0]['i']=['I5'];assert list(validator(adapted).iter_errors(v))
    body=w.body([{'role':'system','content':'Synthetic schema serialization only.'}],config()['model'],schema)
    seen=[]
    def handle(req):
        assert req.content==body;seen.append(1)
        return httpx.Response(200,json=fixture('abstention',prepared()))
    with OpenAI(api_key='synthetic',max_retries=0,http_client=httpx.Client(transport=httpx.MockTransport(handle))) as client:
        client.chat.completions.create(**json.loads(body))
    assert seen==[1]  # No claim this cardinality-only fixture is an authorized evidence packet.


@pytest.mark.parametrize('mutation',['extra','extra_consistent','loose','digest','model','messages'])
def test_actual_transport_rejects_schema_tampering(sdk,mutation):
    from forensic_assistant.ai import cloud_worker
    p=prepared();request=dict(provider='openai',model=config()['model'],messages=copy.deepcopy(p.messages),schema=copy.deepcopy(p.schema),timeout=10,
        handshake=False,raw_diagnostics=False,final_only=False,d2_body_sha256=hashlib.sha256(p.body).hexdigest())
    if mutation=='extra':request['schema']['properties']['a']['items']['properties']['e']['items']['enum'].append('O999')
    elif mutation=='extra_consistent':
        fields=request['schema']['properties']['a']['items']['properties']
        for key in ('e','c'):fields[key]['items']['enum'].append('O'+str(len(fields[key]['items']['enum'])+1))
        assert policy.recognized(request['schema'])
        request['d2_body_sha256']=hashlib.sha256(w.body(p.messages,config()['model'],request['schema'])).hexdigest()
    elif mutation=='loose':request['schema']=q.SCHEMA
    elif mutation=='digest':request['d2_body_sha256']='0'*64
    elif mutation=='model':request['model']='different'
    else:request['messages'][1]['content']+=' '
    with patch('httpx.HTTPTransport.handle_request',side_effect=AssertionError('network forbidden')):
        with pytest.raises(ValueError):cloud_worker.generate(request,sdk)


@pytest.mark.parametrize('change',['partial','boolean','pointer','pointer_type','category'])
def test_reference_diagnostic_closed(change):
    value=diag.base(received=True,outcome='rejected')
    value.update(pointer='/a/0/e',reference_namespace='O',reference_reason='wrong_namespace',other_namespace_member=True)
    if change=='partial':del value['reference_namespace']
    elif change=='boolean':value['other_namespace_member']='true'
    elif change=='pointer':value['pointer']='/a/0/s'
    elif change=='pointer_type':value['pointer']=1
    else:value['reference_namespace']='I'
    with pytest.raises(ValueError):diag.validate(value)


def typed_fixture(name,p):
    if name in ('record','support_in_i','invented'):
        v=fixture('inference',p);raw=json.loads(v['choices'][0]['message']['content'])
        raw['a'][0]['i' if name=='support_in_i' else 'e']=['O1' if name=='support_in_i' else 'E1' if name=='record' else 'O999']
        v['choices'][0]['message']['content']=json.dumps(raw);return v
    return fixture(name,p)


def child(name,connection,gate,request):
    with patch('test_d2_diagnostics.fixture',typed_fixture):sdk_child(name,connection,gate,request)


@pytest.mark.parametrize('name,code',[
 ('inference','none'),('interpretation','none'),('abstention','none'),('insufficient','none'),
 ('duplicate_alias','none'),('record','unknown_support'),('support_in_i','unknown_support'),('invented','unknown_support'),
 ('incomplete_interpretation','incomplete_interpretation'),('malformed','malformed_json'),('truncated','output_truncated'),('refusal','provider_refusal')])
def test_sdk_windows_parent(sdk,monkeypatch,name,code):
    p=prepared();monkeypatch.setattr(ex,'_child',functools.partial(child,name))
    result=ex.execute(ex.authorize(p,lambda _:True))
    assert result['diagnostic']['code']==code,result
    assert result['status']==('accepted' if code=='none' else 'rejected')
    assert result['usage']==USAGE and result['attempts']==1 and result['lookups']==0
    assert result['cleanup']=='confirmed' and not multiprocessing.active_children()
    assert result['ipc_result_bytes']+8<=32768
    if code=='none':assert result['validated']['original_s3_assessment']==p.history._original
    else:assert 'validated' not in result and 'response' not in result
    if name=='duplicate_alias':assert result['diagnostic']['normalization']['duplicates_removed']==1


def empty_prepared():
    from d2_generic_fixtures import context,row
    from test_d2_preview import history
    ctx,_=context([row('browser',991,target_path='C:/Synthetic/O999-I1.txt')])
    h=history(ctx)
    return ex.Prepared(h,h.preview(exploratory=True)['packets'][0],config(),dict(exploratory=True),profile=q.VERSION)


def empty_fixture(name,p):
    value=fixture('inference',p)
    if name=='invented_interpretation':
        raw=json.loads(value['choices'][0]['message']['content']);raw['a'][0]['i']=['I1']
        value['choices'][0]['message']['content']=json.dumps(raw)
    return value


def empty_child(name,connection,gate,request):
    with patch('test_d2_diagnostics.prepared',empty_prepared),patch('test_d2_diagnostics.fixture',empty_fixture):
        sdk_child(name,connection,gate,request)


@pytest.mark.parametrize('name',['valid','invented_interpretation'])
def test_empty_namespace_sdk_windows(sdk,monkeypatch,name):
    p=empty_prepared();fields=p.schema['properties']['a']['items']['properties']
    assert fields['i']['maxItems']==0 and 'enum' not in fields['i']['items']
    assert 'O999' not in fields['e']['items']['enum']  # Evidence text cannot add aliases.
    monkeypatch.setattr(ex,'_child',functools.partial(empty_child,name))
    result=ex.execute(ex.authorize(p,lambda _:True))
    assert result['attempts']==1 and result['lookups']==0 and result['usage']==USAGE
    assert result['cleanup']=='confirmed' and not multiprocessing.active_children()
    if name=='valid':
        assert result['status']=='accepted' and result['validated']['original_s3_assessment']==p.history._original
    else:
        assert result['status']=='rejected' and result['diagnostic']['code']=='item_count'
        assert result['diagnostic']['reference_namespace']=='I'
        assert result['diagnostic']['reference_reason']=='not_in_current_packet'
        assert not result['diagnostic']['other_namespace_member']

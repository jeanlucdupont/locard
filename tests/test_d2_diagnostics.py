"""Synthetic rejection identities, IPC sanitization and real Windows supervision."""
import copy
import functools
import hashlib
import json
import multiprocessing
import socket
import sqlite3
from unittest.mock import patch

import pytest
from test_d2_quality import prepared, answer
from test_d2_execution import config, generic_packet
from test_d2_transport import sdk
from forensic_assistant.investigation_ai import d2, d2_quality as q, d2_execution as ex, d2_result as ipc, d2_diagnostics as diag
from forensic_assistant.ai import cloud_worker, d2_transport, settings
from forensic_assistant.ai.provider_diagnostics import ProviderFailure, classify, error_metadata

ORIGINAL_CHILD = ex._child
USAGE = dict(prompt_tokens=10,completion_tokens=10,total_tokens=20)
CASES = {
    'abstention':'none','insufficient':'none','inference':'none','competing':'none','empty_optional':'none',
    'contrary':'none','interpretation':'none','incomplete_interpretation':'incomplete_interpretation',
    'unknown_alias':'unknown_support','missing_field':'missing_field','null_optional':'wrong_type',
    'wrong_type':'wrong_type','outcome':'unsupported_enum','empty_inference':'outcome_accounts',
    'too_many':'item_count','utf8':'utf8_byte_limit','duplicate_alias':'duplicate_item',
    'blank_optional':'blank_text','nul_optional':'nul_text','missing_reason':'outcome_reason',
    'inference_reason':'outcome_reason','one_competing':'competing_account_required','empty_support':'item_count',
    'missing_statement':'blank_text','d2c2':'unsupported_enum','wrapped':'missing_field',
    'malformed':'malformed_json','incomplete':'malformed_json','missing_content':'invalid_response_envelope',
    'refusal':'provider_refusal','truncated':'output_truncated','list_content':'invalid_response_envelope',
    'provider_error':'provider_failure','responses_wrapper':'invalid_response_envelope'}


def fixture(name,p):
    v=answer();a=v['a'][0]
    if name in ('abstention','insufficient'):v=answer('no_material_inference' if name=='abstention' else 'insufficient_packet_support')
    if name=='competing':
        v['o']='competing_explanations';b=copy.deepcopy(a);b['s']='The activities may instead be independent.';v['a'].append(b)
    if name=='empty_optional':a.update(a='',u='',d='',n='')
    if name=='contrary':a['c']=[p.packet['content']['supports'][-1]['alias']]
    if name in ('interpretation','incomplete_interpretation'):
        a['i']=[p.packet['content']['interpretations'][0]['alias']]
        if name=='interpretation':a['e']=[s['alias'] for s in p.packet['content']['supports']]
    if name=='unknown_alias':a['e']=['O999']
    if name=='missing_field':del a['n']
    if name=='null_optional':a['n']=None
    if name=='wrong_type':v['a']='accounts'
    if name=='outcome':v['o']='proved'
    if name=='empty_inference':v['a']=[]
    if name=='too_many':v['a']=[dict(a,s='Account '+str(i)) for i in range(3)]
    if name=='utf8':a['s']='界'*134
    if name=='duplicate_alias':a['e']=['O1','O1']
    if name=='blank_optional':a['d']=' '
    if name=='nul_optional':a['d']='\0'
    if name=='missing_reason':v=answer('no_material_inference');v['r']=''
    if name=='inference_reason':v['r']='Some reasoning.'
    if name=='one_competing':v['o']='competing_explanations'
    if name=='empty_support':a['e']=[]
    if name=='missing_statement':a['s']=''
    if name=='d2c2':v['v']='d2c2'
    if name=='wrapped':v={'proposal':v}
    raw=json.dumps(v)
    if name=='malformed':raw='{bad'
    if name=='incomplete':raw=raw[:-1]
    msg={'role':'assistant','content':raw};finish='stop'
    if name=='missing_content':del msg['content']
    if name=='refusal':msg.update(content=None,refusal='Sensitive generated refusal')
    if name=='truncated':finish='length'
    if name=='list_content':msg['content']=[{'type':'text','text':raw}]
    body={'id':'mock','object':'chat.completion','created':0,'model':'gpt-6.1-sol','choices':[{'index':0,'message':msg,'finish_reason':finish}], 'usage':USAGE}
    if name=='responses_wrapper':body={'id':'mock','object':'response','output':[]}
    return body


def sdk_call(name,p,sdk):
    import httpx
    body=fixture(name,p);seen=[];factory=d2_transport.guarded_client
    def handle(req):
        assert req.content==p.body;seen.append(1)
        if name=='provider_error':return httpx.Response(400,json={'error':{'message':'SENSITIVE_PROVIDER_BODY','type':'invalid_request_error'}})
        return httpx.Response(200,json=body)
    req=dict(provider='openai',model=config()['model'],messages=p.messages,schema=q.SCHEMA,timeout=10,handshake=False,raw_diagnostics=False,final_only=False,d2_body_sha256=hashlib.sha256(p.body).hexdigest())
    with patch.object(d2_transport,'guarded_client',lambda r:factory(r,httpx.MockTransport(handle))),patch.object(socket.socket,'connect',side_effect=AssertionError('network')),patch.object(socket,'create_connection',side_effect=AssertionError('network')):
        try:return cloud_worker.generate(req,sdk)
        except Exception as e:raise ProviderFailure(classify(e),getattr(e,'stage','provider_request'),metadata=error_metadata(e)) from None
        finally:assert len(seen)==1


@pytest.mark.parametrize('name',CASES)
def test_sdk_matrix(sdk,name):
    p=prepared();received=None;usage={};stage='provider_dispatch';completion=None
    try:
        result=sdk_call(name,p,sdk);received=True;usage=result['usage'];completion=result['finish_reason'];stage='compact_schema'
        d2.validate_response(p.packet,q.expand_response(result['text'],p.packet),p._response_context)
        assert CASES[name]=='none'
    except Exception as e:
        if isinstance(e,ProviderFailure):usage=diag.usage(e.metadata.get('response_envelope',{}))
        detail=diag.failure(e,stage=stage,received=received,reported=usage,completion=completion)
        assert detail['code']==CASES[name],detail
        assert 'SENSITIVE' not in json.dumps(detail) and 'Sensitive' not in json.dumps(detail)
        if stage=='compact_schema':assert detail['usage_availability']=='reported'
        if name=='utf8':assert detail['pointer']=='/a/0/s' and detail['utf8_bytes']==402 and detail['maximum_bytes']==400


def sdk_child(name,connection,gate,request):
    import os
    os.environ.update(LITELLM_LOCAL_MODEL_COST_MAP='True',LITELLM_TELEMETRY='False',DO_NOT_TRACK='1',OPENAI_API_KEY='synthetic-not-a-key')
    with patch.object(socket.socket,'connect',side_effect=AssertionError('network')):
        import litellm
    from litellm._service_logger import ServiceLogging
    ServiceLogging._dispatch_from_sync=staticmethod(lambda *a,**k:None)
    litellm.telemetry=False
    p=prepared()
    def cloud(self,messages,schema,**kw):
        assert schema==q.SCHEMA
        return sdk_call(name,p,litellm)
    with patch.object(settings,'load',config),patch.object(ex,'prepare',lambda *a,**k:p),patch('forensic_assistant.ai.backend.ModelBackend._cloud_request',cloud),patch.object(sqlite3,'connect',side_effect=AssertionError('database')):
        ORIGINAL_CHILD(connection,gate,request)


@pytest.mark.parametrize('name',['abstention','competing','unknown_alias','utf8','missing_reason','refusal','truncated','provider_error'])
def test_windows_spawn(sdk,monkeypatch,name):
    p=prepared();monkeypatch.setattr(ex,'_child',functools.partial(sdk_child,name))
    r=ex.execute(ex.authorize(p,lambda _:True));detail=r['diagnostic']
    assert r['attempts']==1 and r['lookups']==0 and r['cleanup']=='confirmed'
    assert detail['cleanup']=='confirmed' and detail['code']==CASES[name]
    assert not multiprocessing.active_children()
    if name!='provider_error':assert r['usage']==USAGE and detail['usage_availability']=='reported'
    if name in ('abstention','competing'):assert r['validated']['original_s3_assessment']==p.history._original
    else:assert 'validated' not in r
    assert r['ipc_result_bytes']+8<=ipc.LIMIT
    print('D2_DIAGNOSTIC_IPC',name,r['ipc_result_bytes'],len(ipc.encode(detail)))


@pytest.mark.parametrize('raw,code',[( '{"v":"d2q1","v":"d2q1"}','duplicate_key'),('{bad','malformed_json')])
def test_json_codes(raw,code):
    with pytest.raises(ValueError) as caught:q.expand_response(raw,prepared().packet)
    assert diag.failure(caught.value)['code']==code


@pytest.mark.parametrize('path',['d2_quality.a[0].SECRET','d2_quality.a[0].s/secret','d2_quality.a[100000].s','d2_quality.界','/forensic/value'])
def test_path_sanitization(path):assert diag.pointer(path) is None


def test_unknown_field_never_exposed():
    value=answer();value['SECRET_FORENSIC_NAME']='secret model text'
    with pytest.raises(ValueError) as caught:q.validate(value)
    detail=diag.failure(caught.value)
    assert detail['code']=='unknown_field' and 'SECRET' not in json.dumps(detail)
    assert 'secret' not in json.dumps(diag.failure(RuntimeError('secret')))


@pytest.mark.parametrize('mutation',['extra','unicode','bad_path','cleanup','usage','receipt','origin'])
def test_malicious_diagnostic_rejected(mutation):
    p=prepared();detail=diag.base(received=True,reported=USAGE,outcome='accepted');v=ipc.envelope(ipc.binding(p),response='{}',usage=USAGE,attempted=True,received=True,diagnostics=detail)
    if mutation=='extra':detail['raw']='forensic secret'
    if mutation=='unicode':detail['code']='界'*1000
    if mutation=='bad_path':detail['pointer']='/secret'
    if mutation=='cleanup':detail['cleanup']='confirmed'
    if mutation=='usage':detail['usage_availability']='absent'
    if mutation=='receipt':detail['provider_response_received']=False
    if mutation=='origin':detail['origin']='parent'
    with pytest.raises(ValueError):ipc.parse(ipc.encode(v),ipc.binding(p))


def test_diagnostic_overflow_small_single_message():
    p=prepared();detail=diag.base(received=True,reported=USAGE,outcome='rejected');detail['raw']='界'*3000
    v=ipc.envelope(ipc.binding(p),category='response_schema_validation',received=True,attempted=True,usage=USAGE,diagnostics=detail)
    from test_d2_result import Pipe
    pipe=Pipe();assert ipc.send(pipe,v) and pipe.calls==1
    actual=ipc.parse(pipe.values[0],ipc.binding(p))
    assert actual['response'] is None and actual['usage']==USAGE
    assert actual['diagnostic']['code']=='diagnostic_limit' and len(ipc.encode(actual['diagnostic']))<=2048
    assert '界' not in pipe.values[0].decode()


def test_full_result_overflow_does_not_blame_diagnostic():
    p=prepared();detail=diag.base(received=True,reported=USAGE,outcome='accepted')
    v=ipc.envelope(ipc.binding(p),response='x'*40000,received=True,attempted=True,usage=USAGE,diagnostics=detail)
    from test_d2_result import Pipe
    pipe=Pipe();assert ipc.send(pipe,v) and pipe.calls==1
    actual=ipc.parse(pipe.values[0],ipc.binding(p))
    assert actual['category']=='result_byte_limit' and actual['diagnostic']['code']=='ipc_failure'
    assert actual['response'] is None and actual['usage']==USAGE


def forged_accept(connection,gate,request,*,unknown=True):
    gate.wait();v=answer()
    if unknown:v['a'][0]['e']=['O999']
    detail=diag.base(received=True,reported=USAGE,outcome='accepted')
    ipc.send(connection,ipc.envelope(request['binding'],response=json.dumps(v),usage=USAGE,attempted=True,received=True,diagnostics=detail));connection.close()


def test_parent_revalidation_identity(monkeypatch):
    p=prepared();monkeypatch.setattr(ex,'_child',forged_accept)
    r=ex.execute(ex.authorize(p,lambda _:True))
    assert r['status']=='rejected' and 'validated' not in r and r['usage']==USAGE
    assert r['diagnostic']['origin']=='parent' and r['diagnostic']['stage']=='parent_canonical_revalidation'
    assert r['diagnostic']['code']=='unknown_support' and r['diagnostic']['failure_stage']=='alias_membership'


def test_parent_unexpected_failure_is_not_startup(monkeypatch):
    p=prepared();permit=ex.authorize(p,lambda _:True)
    monkeypatch.setattr(ex,'_child',functools.partial(forged_accept,unknown=False))
    def fail(*a,**k):raise RuntimeError('SECRET MODEL TEXT')
    monkeypatch.setattr(d2,'validate_response',fail)
    r=ex.execute(permit)
    assert r['diagnostic']['stage']=='parent_canonical_revalidation'
    assert r['diagnostic']['code']=='unknown_internal_validation_error' and r['usage']==USAGE
    assert 'SECRET' not in json.dumps(r['diagnostic'])


@pytest.mark.parametrize('token,code',[('D2_INCOMPLETE_RELATIONSHIP','incomplete_relationship'),('D2_RESPONSE_REQUEST_BINDING','request_binding')])
def test_additional_validation_codes(token,code):assert diag.failure(ValueError(token))['code']==code


def test_legacy_result_unchanged():
    p=prepared();v=ipc.envelope(ipc.binding(p),response='{}',received=True,attempted=True)
    assert v['contract']=='d2-worker-result-v1' and 'diagnostic' not in ipc.parse(ipc.encode(v),ipc.binding(p))


def test_missing_usage_states():
    assert diag.base(received=True)['usage_availability']=='absent'
    assert diag.base(received=False)['usage_availability']=='not_received'
    e=ProviderFailure('response_envelope_failed','response_envelope',metadata={'response_envelope':{'envelope_received':True}})
    assert diag.failure(e)['usage_availability']=='discarded_by_earlier_failure'


def test_clarified_guide_gate(sdk):
    """Measure SDK serialization only; never admit the oversized candidate."""
    import httpx
    from openai import OpenAI
    from forensic_assistant.investigation_ai import d2_wire as w
    packet=generic_packet('large_value');messages=q.messages(packet)
    extra=' For inference r must be empty; for abstention r must be nonblank. A single competing account needs an alternative. Use unique aliases, no null text, and respect UTF-8 byte limits. Cite every original premise alias when citing an interpretation.'
    for suffix,expected in [('',5552),(extra,5797),
            (' Use empty r for inference, nonblank r otherwise.',5601),
            (' Inference r must be empty; abstention r nonblank.',5602)]:
        candidate=copy.deepcopy(messages);candidate[0]['content']+=suffix
        body=w.body(candidate,'gpt-6.1-sol',q.SCHEMA);assert len(body)==expected
        def handle(request):
            assert request.content==body
            return __import__('httpx').Response(200,json={'id':'mock','object':'chat.completion','created':0,'model':'gpt-6.1-sol','choices':[{'index':0,'message':{'role':'assistant','content':'{}'},'finish_reason':'stop'}]})
        with OpenAI(api_key='synthetic',max_retries=0,http_client=httpx.Client(transport=httpx.MockTransport(handle))) as client:
            client.chat.completions.create(**json.loads(body))
    assert len(q.GUIDE.encode('utf-8'))==546


def test_ui_rejection_diagnostic():
    from forensic_assistant.investigation_ai import d2_presentation
    p=prepared();detail=diag.failure(ValueError('D2_UNKNOWN_SUPPORT'),received=True,reported=USAGE)
    detail['cleanup']='confirmed'
    r=dict(status='rejected',reason='response_schema_validation',usage=USAGE,diagnostic=detail,attempts=1,lookups=0,cleanup='confirmed')
    rendered=d2_presentation.render(d2_presentation.view(r,p))
    assert 'Validation: alias_membership / unknown_support' in rendered
    assert 'Usage availability: reported' in rendered


def test_diagnostic_byte_limit_preserved(monkeypatch):
    value=diag.base(received=True,outcome='rejected')
    monkeypatch.setattr(diag,'LIMIT',10)
    with pytest.raises(ValueError,match='D2_DIAGNOSTIC_LIMIT'):diag.validate(value)


@pytest.mark.parametrize('family',['browser','registry','evtx','mft','prefetch'])
def test_artifact_independent_diagnostics(family):
    from d2_generic_fixtures import context,row
    from test_d2_preview import history
    ctx,_=context([row(family,700,hostname='synthetic-host',current_path='C:/Synthetic/file',process_name='test.exe')])
    h=history(ctx);packet=h.preview(exploratory=True)['packets'][0]
    bad=answer();bad['a'][0]['e']=['O999']
    with pytest.raises(ValueError) as caught:h.validate(packet,q.expand_response(json.dumps(bad),packet),exploratory=True)
    detail=diag.failure(caught.value,received=True,reported=USAGE)
    assert detail['code']=='unknown_support' and family not in json.dumps(detail)

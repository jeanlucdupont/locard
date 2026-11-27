"""Generation relaxation cannot authorize execution. No real model/provider."""
import copy
import json
import pytest
from forensic_assistant.conversational_ai.contracts import catalog,arguments
from forensic_assistant.conversational_ai.local_schema import generation_catalog,REMOVED
from forensic_assistant.conversational_ai import local
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.ai.provider_diagnostics import ProviderFailure,safe_metadata
from scripts.diagnose_local_provider import full_catalog,successful,MockEndpoint,wire
from test_conversational_ai import reply,call

@pytest.fixture(autouse=True)
def private(tmp_path,monkeypatch):monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))

def test_catalog_immutable_deterministic_preserves_structure():
    canonical=catalog();before=copy.deepcopy(canonical);wire_tools=generation_catalog(canonical)
    assert canonical==before==catalog() and len(wire_tools)==10
    assert wire_tools==generation_catalog(canonical)==generation_catalog(wire_tools)
    def compare(a,b):
        for key,value in a.items():
            if key in REMOVED:assert key not in b
            elif key=='properties':
                assert set(value)==set(b[key])
                for name in value:compare(value[name],b[key][name])
            elif key=='items':compare(value,b[key])
            else:assert value==b[key]
    for a,b in zip(canonical,wire_tools):
        assert a['function']['name']==b['function']['name']
        compare(a['function']['parameters'],b['function']['parameters'])

@pytest.mark.parametrize('name,args',[
    ('note',dict(kind='hypothesis',text='x'*2001,status='active')),
    ('note',dict(kind='hypothesis',text='x',status='active',evidence_ids=[str(n) for n in range(41)])),
    ('note',dict(kind='hypothesis',text='x',status='active',alternatives=['same','same'])),
    ('note',dict(kind='fact',text='x',status='active')),
    ('show_evidence',dict(evidence_id=10)),('show_evidence',{}),
    ('show_evidence',dict(evidence_id='x',command='shell')),
    ('show_evidence',dict(evidence_id='x',limit=41)),
    ('show_evidence',dict(evidence_id='x',limit=True)),
    ('note',dict(kind='hypothesis',text='é'*1001,status='active')),
])
def test_canonical_rejects_relaxed_generation(name,args):
    generation_catalog(catalog())
    with pytest.raises(ValueError):arguments(name,args)

def test_full_catalog_protocol_and_actual_wire_size():
    def respond(body):
        assert body['tools']==generation_catalog(catalog())
        return wire(reply(calls=[call('memory',{'kind':'state'})]) if body['tool_choice']=='required' else reply('Simulated empty state.'))
    with MockEndpoint(respond) as server:
        result=full_catalog(ModelBackend.local_conversation(server.endpoint,'synthetic'))
        assert successful(result) and len(server.calls)==2
        assert [r['request_bytes'] for r in result['requests']]==[len(local.encoded(b)) for b in server.calls]

def test_error_classification_and_redaction(monkeypatch):
    secret='PRIVATE EVIDENCE C:\\secret token=credential\x1b[31m'
    raw=json.dumps({'error':{'message':'failed to parse grammar '+secret}}).encode()
    class Response:
        status=500
        def read(self,*a):return raw
    class Connection:
        def __init__(self,*a,**k):pass
        def request(self,*a,**k):pass
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr(local.http.client,'HTTPConnection',Connection)
    with pytest.raises(ProviderFailure) as caught:local.http_json(local.configuration('http://127.0.0.1:1','synthetic'),'/v1/chat/completions',{})
    error=caught.value
    assert error.category=='local_grammar_rejected' and error.metadata['http_status']==500
    assert error.metadata['local_transport']['server_code']=='grammar_rejected'
    assert secret not in json.dumps(error.metadata) and 'PRIVATE' not in json.dumps(error.metadata)
    sanitized=safe_metadata({'local_transport':{'server_code':'grammar_rejected','server_message':secret}})
    assert sanitized['local_transport']['server_message']=='Server reported failure to parse grammar.'

def test_failed_synthetic_safety_is_not_capability_success():
    assert not successful({'outcome':'PROVIDER_FAILURE','checks':{'case_unchanged':True,'worker_closed':True}})
    assert not successful({'outcome':'COMPLETED','checks':{'case_unchanged':True},'observations':{'final_response':True}})

def test_full_catalog_invalid_arguments_not_executed():
    with MockEndpoint(lambda b:wire(reply(calls=[call('memory',{'kind':'state','limit':999})]))) as server:
        result=full_catalog(ModelBackend.local_conversation(server.endpoint,'synthetic'))
        assert not successful(result) and len(server.calls)==1
        assert result['failure_stage']=='argument_selection_or_validation'

def test_openai_catalog_and_local_sizing_are_separate():
    from forensic_assistant.conversational_ai.service import Session
    session=Session.__new__(Session)
    session._scope=json.dumps({'provider':'openai'})
    assert session.catalog()==catalog()
    session._scope=json.dumps({'provider':'local','local':{'synthetic':True}})
    assert session.catalog()==generation_catalog(catalog())
    config=local.configuration('http://127.0.0.1:1','synthetic')
    assert local.body_for(config,[],catalog(),512)['tools']==session.catalog()

def test_diagnostic_failure_has_nonzero_exit(monkeypatch,capsys):
    from scripts import diagnose_local_provider as diagnostic
    monkeypatch.setattr('sys.argv',['diagnose_local_provider','--endpoint','http://127.0.0.1:1','--model','synthetic','--synthetic-investigation'])
    monkeypatch.setattr(diagnostic,'synthetic_investigation',lambda *a:dict(outcome='PROVIDER_FAILURE',checks={'case_unchanged':True,'worker_closed':True}))
    assert diagnostic.main()==1
    assert json.loads(capsys.readouterr().out)['outcome']=='PROVIDER_FAILURE'

def test_synthetic_failure_retains_safe_provider_detail(tmp_path,monkeypatch):
    from scripts.diagnose_local_provider import synthetic_investigation
    client=ModelBackend.local_conversation('http://127.0.0.1:1','synthetic')
    def fail(*a,**k):
        raise ProviderFailure('local_grammar_rejected','provider_request',metadata={'http_status':500,
            'local_transport':{'server_code':'grammar_complexity','request_bytes':19402,'client_cleanup':'confirmed'}})
    monkeypatch.setattr(client,'converse',fail)
    result=synthetic_investigation(tmp_path,client)
    assert not successful(result) and all(result['checks'].values())
    assert result['failure']['category']=='local_grammar_rejected'
    assert result['failure']['diagnostic']['http_status']==500
    assert result['failure']['diagnostic']['local_transport']['request_bytes']==19402

@pytest.mark.parametrize('error,expected',[
    ({'message':'number of rules multiplied by the new repetition exceeds sane defaults'},'grammar_complexity'),
    ({'type':'exceed_context_size_error','message':'private context'},'context_exhausted'),
    ({'message':'private unknown provider detail'},'unavailable'),
    ({'message':{'nested':'untrusted'}},'unavailable'),
])
def test_safe_server_error_categories(error,expected):
    from forensic_assistant.conversational_ai.local_diagnostics import server_detail
    result=server_detail(error)
    assert result['server_code']==expected and result['inference_began']=='unknown'
    assert 'private' not in json.dumps(result) and 'untrusted' not in json.dumps(result)

def test_truncated_response_preserves_available_usage():
    value=wire(reply('incomplete'))
    value['choices'][0]['finish_reason']='length'
    value['usage']={'prompt_tokens':100,'completion_tokens':20,'total_tokens':120,'secret':'withheld'}
    with pytest.raises(ProviderFailure) as caught:local.parse(value)
    assert caught.value.category=='output_truncated'
    assert caught.value.metadata['conversation']['total_tokens']==120
    assert 'secret' not in json.dumps(caught.value.metadata)

def test_full_catalog_failure_reports_available_usage(monkeypatch):
    client=ModelBackend.local_conversation('http://127.0.0.1:1','synthetic')
    def fail(*a,**k):raise ProviderFailure('output_truncated','provider_generation',metadata={'conversation':{'total_tokens':123}})
    monkeypatch.setattr(client,'converse',fail)
    result=full_catalog(client)
    assert not successful(result)
    assert result['requests'][0]['usage']=={'total_tokens':123}
    assert result['requests'][0]['category']=='output_truncated'

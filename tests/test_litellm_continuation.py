"""Lossless bounded provider history, independent of forensic authority."""
import copy,json,importlib.util
from types import SimpleNamespace as N
import pytest
from forensic_assistant.conversational_ai.provider import generate,validate,assistant_message,restore
from forensic_assistant.ai import settings

@pytest.fixture(autouse=True)
def isolated(tmp_path,monkeypatch):
    import socket
    monkeypatch.setattr(socket.socket,'connect',lambda *a:pytest.fail('Network forbidden in continuation tests'))
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:pytest.fail('DNS forbidden in continuation tests'))
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    monkeypatch.setenv('LITELLM_LOCAL_MODEL_COST_MAP','True')
    monkeypatch.setenv('LITELLM_TELEMETRY','False')
    monkeypatch.setattr(settings,'key',lambda _: 'synthetic')

def raw_message():
    return {'role':'assistant','content':None,'tool_calls':[{'id':'call1','type':'function','function':{'name':'note','arguments':'{ "kind": "hypothesis", "text": "Unverified", "status": "active" }'}}],
            'reasoning_items':[{'id':'reason1','encrypted_content':'opaque-sensitive-state','summary':[]}],
            'provider_specific_fields':{'phase':'commentary','openai_responses_replay':{'version':1,'items':[{'type':'reasoning','index':0},{'type':'function_call','index':0}],'checksum':'synthetic'}}}

def normalized(raw):
    return dict(text=raw['content'] or '',tool_calls=[dict(id=c['id'],name=c['function']['name'],arguments=json.loads(c['function']['arguments'])) for c in raw['tool_calls']],
        finish_reason='tool_calls',usage={'total_tokens':1},cost=None,
        continuation={'format':'litellm-openai-history-v1','payload':json.dumps(raw)})

def test_exact_transport_restore_and_extraction():
    raw=raw_message();seen=[]
    message=N(**raw);message.tool_calls=[N(id='call1',type='function',function=N(**raw['tool_calls'][0]['function']))]
    message.model_dump=lambda:copy.deepcopy(raw)
    def complete(**kwargs):
        seen.append(kwargs)
        return N(choices=[N(finish_reason='tool_calls',message=message)],usage=N(total_tokens=1))
    req=dict(provider='openai',model='synthetic',messages=[],timeout=1,conversation={'tools':[],'output_tokens':32})
    first=generate(req,N(completion=complete));assert first['continuation']
    req['messages']=[assistant_message(first),{'role':'tool','tool_call_id':'call1','content':'{}'}]
    generate(req,N(completion=complete))
    assert seen[1]['messages'][0]==raw
    assert 'provider_continuation' not in seen[1]['messages'][0]
    assert seen[1]['messages'][1]['tool_call_id']=='call1'
    assert seen[1]['num_retries']==0 and seen[1]['drop_params'] is False

@pytest.mark.parametrize('change',['id','content','format','size'])
def test_changed_or_oversized_continuation_rejected(change):
    value=normalized(raw_message())
    if change=='id':value['tool_calls'][0]['id']='forged'
    if change=='content':value['text']='different'
    if change=='format':value['continuation']['format']='other-provider'
    if change=='size':value['continuation']['payload']=' '*32769
    with pytest.raises(ValueError):validate(value)

def test_service_retains_bounded_unverified_continuation(tmp_path):
    from test_conversational_ai import setup,reply
    from forensic_assistant.conversational_ai.service import Session,notebook
    first=normalized(raw_message())
    def second(messages):
        saved=next(m for m in messages if m.get('provider_continuation'))
        assert restore(saved)==raw_message()
        assert messages[-1]['tool_call_id']=='call1'
        return reply('The hypothesis remains unverified.')
    path,provider,scope=setup(tmp_path,[first,second])
    session=Session(scope,provider,lambda _:True);result=session.submit('Investigate synthetic evidence');session.close()
    assert not result['verified_observations']
    saved=notebook(str(path)+'.conversations',session.journal.id)
    attempts=[e['data'] for e in saved['events'] if e['kind']=='provider_attempt']
    expected=sum(len(json.dumps(e['messages'],ensure_ascii=True,separators=(',',':')).encode()) for e in attempts)
    assert result['usage']['disclosure_bytes']==expected
    assert 'opaque-sensitive-state' in json.dumps(saved) # private history only, not a fact

def test_secret_redaction_does_not_silently_break_replay(tmp_path,monkeypatch):
    from test_conversational_ai import setup
    from forensic_assistant.conversational_ai.service import Session
    monkeypatch.setenv('OPENAI_API_KEY','opaque-sensitive-state')
    path,provider,scope=setup(tmp_path,[normalized(raw_message())])
    session=Session(scope,provider,lambda _:True)
    with pytest.raises(ValueError,match='PROVIDER_CONTINUATION_REDACTED'):session.submit('Synthetic')
    assert session.closed and 'opaque-sensitive-state' not in (session.journal.path/'events.jsonl').read_text(encoding='utf-8')

def test_installed_litellm_replay_checksum_survives():
    if importlib.util.find_spec('litellm') is None:pytest.skip('Real LiteLLM is checked in the isolated dependency environment')
    from litellm.completion_extras.litellm_responses_transformation.history import replay_fields,replay_items
    raw=raw_message();raw['provider_specific_fields']={'phase':'commentary'}
    output=[{'type':'reasoning','id':'reason1'},{'type':'function_call','id':'fc1','call_id':'call1'}]
    raw['provider_specific_fields'].update(replay_fields(output,raw,completed=True,first_message_only=False))
    original=replay_items(raw,replay_tool_search=False)
    assert original is not None
    rebuilt=restore(assistant_message(validate(normalized(raw))))
    assert replay_items(rebuilt,replay_tool_search=False)==original
    changed=copy.deepcopy(raw);changed['tool_calls'][0]['function']['arguments']=json.dumps(json.loads(changed['tool_calls'][0]['function']['arguments']))
    assert replay_items(changed,replay_tool_search=False) is None

def test_real_litellm_native_roundtrip_without_mcp(monkeypatch):
    if importlib.util.find_spec('litellm') is None:pytest.skip('Run in isolated dependency environment')
    import os,subprocess,sys
    if os.environ.get('LOCARD_SYNTHETIC_LITELLM_CHILD')!='1':
        # Match production's one-shot worker boundary: SDK background executors
        # must not keep a completed test alive during interpreter shutdown.
        code="import os,sys,pytest; result=pytest.main(['tests/test_litellm_continuation.py::test_real_litellm_native_roundtrip_without_mcp','-q','-p','no:cacheprovider','--disable-warnings']); sys.stdout.flush(); sys.stderr.flush(); os._exit(result)"
        done=subprocess.run([sys.executable,'-c',code],env={**os.environ,'LOCARD_SYNTHETIC_LITELLM_CHILD':'1'},capture_output=True,text=True,timeout=30)
        assert done.returncode==0,done.stdout+done.stderr
        return
    import litellm,httpx
    import tiktoken
    # Transport test, not a tokenizer benchmark: prevent first-use BPE download.
    encoding=tiktoken.Encoding(name='synthetic-byte',pat_str=r'(?s).',mergeable_ranks={bytes([i]):i for i in range(256)},special_tokens={})
    monkeypatch.setattr(tiktoken,'get_encoding',lambda *a:encoding)
    monkeypatch.setattr(tiktoken,'encoding_for_model',lambda *a:encoding)
    from openai import OpenAI
    from forensic_assistant.conversational_ai.compatibility import TOOL
    assert importlib.util.find_spec('mcp') is None
    sent=[]
    def transport(request):
        body=json.loads(request.content);sent.append((request.url.path,body))
        assert request.url.path.endswith('/responses')
        if len(sent)==1:
            output=[{'type':'reasoning','id':'rs-synthetic','summary':[],'encrypted_content':'synthetic-opaque'},
                    {'type':'function_call','id':'fc-synthetic','call_id':'call-synthetic','name':'synthetic_echo','arguments':'{ "token": "locard-test" }','status':'completed'}]
        else:
            assert any(i.get('type')=='function_call_output' and i.get('call_id')=='call-synthetic' for i in body['input'])
            assert any(i.get('type')=='reasoning' and i.get('id')=='rs-synthetic' for i in body['input'])
            output=[{'type':'message','id':'msg-synthetic','role':'assistant','status':'completed','content':[{'type':'output_text','text':'The token is locard-test.','annotations':[]}]}]
        return httpx.Response(200,request=request,json={'id':'resp-synthetic-'+str(len(sent)),'object':'response','created_at':1,'status':'completed','error':None,'incomplete_details':None,
            'model':'gpt-6.1-sol','output':output,'parallel_tool_calls':True,'tool_choice':'auto','tools':[],
            'usage':{'input_tokens':30,'output_tokens':10,'total_tokens':40}})
    monkeypatch.setattr(httpx.Client,'send',lambda self,request,**kwargs:transport(request))
    with httpx.Client(transport=httpx.MockTransport(transport)) as http:
        client=OpenAI(api_key='synthetic',http_client=http)
        class SDK:
            def completion(self,**kwargs):
                try:return litellm.completion(**kwargs)
                except Exception as exc:pytest.fail('Synthetic SDK transport: '+str(exc))
        req=dict(provider='openai',model='gpt-6.1-sol',messages=[{'role':'user','content':'Synthetic diagnostic only.'}],timeout=3,
                 conversation=dict(tools=[TOOL],output_tokens=512,tool_choice='required'))
        first=generate(req,SDK());assert first['continuation']
        req['messages'] += [assistant_message(first),{'role':'tool','tool_call_id':'call-synthetic','content':'{"token":"locard-test"}'}]
        req['conversation']['tool_choice']='none'
        final=generate(req,SDK());assert final['text']=='The token is locard-test.'
        assert len(sent)==2

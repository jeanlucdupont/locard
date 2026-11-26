"""Synthetic native provider integration; no credentials or network required."""
import json,os,subprocess,sys
from types import SimpleNamespace as N
import pytest
from forensic_assistant.conversational_ai import provider,compatibility
from forensic_assistant.conversational_ai.contracts import catalog
from forensic_assistant.ai import backend,settings,provider_diagnostics as diag

@pytest.fixture(autouse=True)
def private_diagnostics(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))

def response(text='Synthetic response',calls=(),finish='stop'):
    return N(choices=[N(finish_reason=finish,message=N(content=text,tool_calls=list(calls)))],usage=N(total_tokens=12))

def native_call(arguments='{"token":"locard-test"}'):
    return N(id='synthetic-call',type='function',function=N(name='synthetic_echo',arguments=arguments))

@pytest.fixture
def configured(monkeypatch):
    config=settings.defaults();config.update(provider='openai',model='synthetic',cloud_acknowledged=True)
    monkeypatch.setattr(settings,'key',lambda _: 'SENSITIVE_KEY')
    logs=[];monkeypatch.setattr(diag.diagnostics,'append',lambda name,text:logs.append(text))
    return config,logs

def request():
    return dict(provider='openai',model='synthetic',messages=[{'role':'user','content':'PRIVATE_EVIDENCE'}],timeout=3,conversation=dict(tools=catalog(),output_tokens=512))

@pytest.mark.parametrize('kind,expected',[
    ('parameter','unsupported_parameter'),('schema','unsupported_schema'),('timeout','timeout'),
    ('length','output_truncated'),('finish','conversation_finish'),('envelope','conversation_envelope'),('internal','conversation_adapter')])
def test_safe_failure_categories(configured,kind,expected):
    class BadRequestError(Exception):
        status_code=400
        body={'error':{'code':'unsupported_parameter' if kind=='parameter' else 'invalid_json_schema','param':'tools','message':'PRIVATE_EVIDENCE SENSITIVE_KEY'}}
    class SDK:
        def completion(self,**kwargs):
            if kind in ('parameter','schema'):raise BadRequestError('PRIVATE_EVIDENCE SENSITIVE_KEY')
            if kind=='timeout':raise TimeoutError('PRIVATE_EVIDENCE')
            if kind=='internal':raise TypeError('PRIVATE_EVIDENCE')
            if kind=='envelope':return response(calls=[native_call('not json')],finish='tool_calls')
            return response(finish='length' if kind=='length' else 'unknown-secret-value')
    with pytest.raises(diag.ProviderFailure) as caught:provider.generate(request(),SDK())
    assert caught.value.category==expected
    assert 'PRIVATE_EVIDENCE' not in json.dumps(caught.value.metadata)
    assert 'SENSITIVE_KEY' not in json.dumps(caught.value.metadata)
    assert caught.value.metadata['conversation']['location'] in ('transport','extraction')

def test_backend_logs_success_and_failure(configured,monkeypatch):
    config,logs=configured;client=backend.ModelBackend(config=config)
    def success(*a,**k):return dict(text='PRIVATE_EVIDENCE',tool_calls=[],finish_reason='stop',usage={'total_tokens':12},cost=None)
    monkeypatch.setattr(client,'_cloud_request',success)
    client.converse(request()['messages'],catalog(),timeout=3)
    def failure(*a,**k):raise diag.ProviderFailure('unsupported_parameter',metadata={'http_status':400,'rejected_parameter':'tools'})
    monkeypatch.setattr(client,'_cloud_request',failure)
    with pytest.raises(diag.ProviderFailure):client.converse(request()['messages'],catalog(),timeout=3)
    assert len(logs)==2 and all(json.loads(x)['operation']=='conversation' for x in logs)
    rendered=diag.render(''.join(logs))
    assert 'unsupported_parameter' in rendered and '400' in rendered and 'tool_count' in rendered
    assert 'PRIVATE_EVIDENCE' not in rendered and 'SENSITIVE_KEY' not in rendered

def test_failed_log_does_not_claim_entry(configured,monkeypatch):
    client=backend.ModelBackend(config=configured[0])
    def fail(*a,**k):raise diag.ProviderFailure('timeout')
    monkeypatch.setattr(client,'_cloud_request',fail)
    monkeypatch.setattr(diag.diagnostics,'append',lambda *a:(_ for _ in ()).throw(OSError()))
    with pytest.raises(diag.ProviderFailure,match='could not be persisted') as exc:client.converse([],catalog())
    assert 'See ai logs' not in str(exc.value)

def test_synthetic_roundtrip_uses_production_backend(configured,monkeypatch):
    config,logs=configured;client=backend.ModelBackend(config=config);seen=[]
    class SDK:
        def completion(self,**kwargs):
            seen.append(kwargs)
            assert kwargs['num_retries']==0 and kwargs['drop_params'] is False
            if len(seen)==1:
                assert kwargs['tool_choice']=='required'
                return response('Synthetic tool plan',[N(id='c'+str(i),type='function',function=N(name='synthetic_echo',arguments='{"token":"locard-test"}')) for i in range(6)],'tool_calls')
            if len(seen)==2:
                assert {m['tool_call_id'] for m in kwargs['messages'] if m['role']=='tool'}=={'c'+str(i) for i in range(6)}
                return response(None,[native_call()],'tool_calls')
            if len(seen)==3:
                assert kwargs['messages'][-1]['tool_call_id']=='synthetic-call'
                return response('The returned token is locard-test.')
            assert kwargs['tools']==catalog()
            return response('Catalog accepted.')
    def cloud(messages,schema,**kwargs):
        from forensic_assistant.ai.cloud_worker import generate
        return generate(dict(provider='openai',model='synthetic',messages=messages,timeout=kwargs['timeout'],conversation=kwargs['conversation']),SDK())
    monkeypatch.setattr(client,'_cloud_request',cloud)
    with pytest.raises(ValueError):compatibility.run(config,client=client)
    assert not seen
    result=compatibility.run(config,authorized=True,client=client)
    assert result['overall']=='ready' and len(seen)==4 and len(logs)==4
    assert all(result[k]=='ready' for k in compatibility.STAGES)
    assert 'PRIVATE_EVIDENCE' not in json.dumps(seen)

def test_synthetic_failure_stops_without_retry(configured):
    class Client:
        calls=0
        def converse(self,*a,**k):self.calls+=1;raise diag.ProviderFailure('timeout','timeout')
    client=Client();result=compatibility.run(configured[0],authorized=True,client=client)
    assert client.calls==1 and result['failed_phase']=='native_tools' and result['catalog']=='not reached'

def test_cli_failure_preserves_notebook_and_returns_status(tmp_path,configured):
    from test_conversational_ai import setup
    from forensic_assistant.cli import build_parser
    from forensic_assistant.conversational_ai.cli import run
    def fail(messages):raise diag.ProviderFailure('timeout','timeout')
    path,client,scope=setup(tmp_path,[fail])
    args=build_parser().parse_args(['--db',str(path),'investigation','chat','--source',scope['source_ids'][0],'--start',scope['start'],'--end',scope['end']])
    answers=iter(['Synthetic investigation','y','/exit']);output=[]
    assert run(args,read=lambda _:next(answers),write=output.append,provider=client)==0
    manifests=list(path.parent.glob('case.db.conversations/*/manifest.json'))
    assert len(manifests)==1
    from forensic_assistant.conversational_ai.service import notebook
    saved=notebook(manifests[0].parent.parent,manifests[0].parent.name)
    assert saved['events'][-1]['data']['cleanup_confirmed']
    assert any('Cleanup confirmed' in line for line in output)

def test_check_parser_and_approval(configured,monkeypatch):
    from forensic_assistant.cli import build_parser
    from forensic_assistant.ai.cli import dispatch,render
    args=build_parser().parse_args(['ai','check','--conversation'])
    monkeypatch.setattr(settings,'load',lambda:configured[0]);args._confirm=lambda _: 'n'
    with pytest.raises(ValueError,match='explicit approval'):dispatch(args)
    with pytest.raises(SystemExit):build_parser().parse_args(['ai','check','--conversation','--full'])

def test_interactive_shell_continues_after_conversation_failure(tmp_path,configured,monkeypatch,capsys):
    from test_conversational_ai import setup
    from test_interactive_shell import Input
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from forensic_assistant.conversational_ai import cli
    def fail(messages):raise diag.ProviderFailure('timeout','timeout')
    path,client,scope=setup(tmp_path,[fail]);answers=iter(['Synthetic investigation','y','/exit'])
    original=cli.run
    monkeypatch.setattr(cli,'run',lambda args:original(args,read=lambda _:next(answers),provider=client))
    command='investigation chat --source '+scope['source_ids'][0]+' --start '+scope['start']+' --end '+scope['end']
    reader=Input(str(path),command,'settings version','quit')
    assert Shell(State(None),reader).run()==0
    text=capsys.readouterr().out
    from forensic_assistant import __version__
    assert 'Cleanup confirmed' in text and __version__ in text and 'Traceback' not in text

@pytest.mark.parametrize('kind',['duplicate','missing_id','content_type'])
def test_invalid_native_envelope(configured,kind):
    def invalid(**kwargs):
        if kind=='content_type':return response(42)
        call=native_call()
        if kind=='missing_id':del call.id
        return response(None,[call,call] if kind=='duplicate' else [call],'tool_calls')
    with pytest.raises(diag.ProviderFailure) as exc:provider.generate(request(),N(completion=invalid))
    assert exc.value.category=='conversation_envelope'

def test_real_cloud_worker_boundary_with_synthetic_sdk(tmp_path):
    # Run the production one-shot module. Only its external SDK is replaced;
    # the child cannot make a provider request through this fake SDK.
    (tmp_path/'litellm.py').write_text('from types import SimpleNamespace as N\ndef completion(**kwargs):\n return N(choices=[N(finish_reason="tool_calls",message=N(content=None,tool_calls=[N(id="c1",type="function",function=N(name="synthetic_echo",arguments=\'{"token":"locard-test"}\'))]))],usage=N(total_tokens=8))\n',encoding='utf-8')
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    env={**os.environ,'PYTHONPATH':str(tmp_path)+os.pathsep+str(root),'OPENAI_API_KEY':'synthetic-only'}
    value=request();value['messages']=[{'role':'user','content':'Synthetic only'}]
    process=subprocess.run([sys.executable,'-B','-m','forensic_assistant.ai.cloud_worker'],input=json.dumps(value).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=tmp_path,env=env,timeout=20)
    assert process.returncode==0
    result=provider.validate(json.loads(process.stdout))
    assert result['tool_calls'][0]['arguments']=={'token':'locard-test'}

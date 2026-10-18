"""Synthetic provider and config contracts; never call a real cloud service."""
import json
import os
from types import SimpleNamespace
import pytest
from forensic_assistant.ai import settings, cli, cloud_worker, runtime
from forensic_assistant.ai.backend import ModelBackend, redact
from forensic_assistant.cli import build_parser
from test_investigation_hardening import local_model


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    for _, key in settings.PROVIDERS.values():
        if key: monkeypatch.delenv(key, raising=False)


def args(*words):
    return build_parser().parse_args(['ai', *words])


def test_local_defaults_no_runtime_spawn(monkeypatch):
    monkeypatch.setattr(runtime.subprocess, 'Popen', lambda *a, **k: pytest.fail('unexpected process'))
    value = cli.dispatch(args('status'))
    assert value['provider'] == 'Local' and value['runtime'] == 'stopped'
    assert value['model'] == 'Qwen3-4B-Q4_K_M.gguf'
    assert value['idle_timeout_seconds'] == 900
    assert settings.load()['context'] == 4096 and settings.load()['gpu_layers'] == 99


def test_cloud_confirmation_and_decline():
    a = args('provider', 'openai', '--model', 'synthetic-model')
    a._confirm = lambda _: 'n'
    assert cli.dispatch(a)['status'] == 'unchanged'
    assert settings.load()['provider'] == 'local'
    a._confirm = lambda _: 'y'
    assert cli.dispatch(a)['provider'] == 'OpenAI'
    saved = settings.load()
    assert saved['cloud_acknowledged'] and saved['model'] == 'synthetic-model'
    assert 'API_KEY' not in (settings.root()/'config.json').read_text()


def test_script_acknowledgement_required():
    with pytest.raises(ValueError, match='acknowledge-cloud'):
        cli.dispatch(args('provider', 'xai', '--model', 'synthetic'))
    assert settings.load()['provider'] == 'local'
    assert cli.dispatch(args('provider', 'xai', '--model', 'synthetic', '--acknowledge-cloud'))['provider'] == 'xAI Grok'


@pytest.mark.parametrize('provider', list(settings.PROVIDERS)[1:])
def test_provider_adapter_contract(provider, monkeypatch):
    secret = 'TEST-SECRET-' + provider
    monkeypatch.setenv(settings.PROVIDERS[provider][1], secret)
    calls = []
    def completion(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(finish_reason='stop',
            message=SimpleNamespace(content='{"answer":"bounded"}', tool_calls=None))],
            usage=SimpleNamespace(prompt_tokens=11, completion_tokens=4, total_tokens=15))
    messages = [{'role':'user', 'content':'BOUNDED DISCLOSED CONTEXT'}]
    schema = {'type':'object'}
    result = cloud_worker.generate(dict(provider=provider, model='synthetic', messages=messages,
        schema=schema, timeout=2), SimpleNamespace(completion=completion))
    call = calls[0]
    assert call['model'] == provider + '/synthetic'
    assert call['messages'] is messages
    assert call['response_format']['json_schema']['schema'] is schema
    assert call['num_retries'] == 0 and call['timeout'] == 2
    assert 'tools' not in call and 'fallbacks' not in call
    assert result == {'text':'{"answer":"bounded"}', 'usage':{'prompt_tokens':11,'completion_tokens':4,'total_tokens':15}}
    assert secret not in redact(secret)


@pytest.mark.parametrize('provider', list(settings.PROVIDERS)[1:])
def test_missing_key_no_fallback(provider, monkeypatch):
    config = {**settings.defaults(), 'provider':provider, 'model':'synthetic', 'cloud_acknowledged':True}
    backend = ModelBackend(config=config)
    monkeypatch.setattr(runtime, 'ensure', lambda *a, **k: pytest.fail('fallback'))
    with pytest.raises(ValueError, match=settings.PROVIDERS[provider][1]):
        backend.complete([{'role':'user','content':'bounded'}])


def test_native_tool_response_rejected(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','synthetic-secret')
    sdk = SimpleNamespace(completion=lambda **kw: SimpleNamespace(choices=[SimpleNamespace(
        finish_reason='tool_calls', message=SimpleNamespace(content='', tool_calls=[{'name':'execute'}]))]))
    with pytest.raises(ValueError):
        cloud_worker.generate(dict(provider='openai',model='synthetic',messages=[],schema={},timeout=1),sdk)


def test_owned_argv_and_no_shell(tmp_path):
    exe=tmp_path/'llama-server.exe';exe.write_bytes(b'synthetic')
    model=tmp_path/'model with spaces.gguf';model.write_bytes(b'synthetic')
    config={**settings.defaults(),'executable':str(exe),'model_path':str(model)}
    assert runtime.argv(config,8080)==[str(exe),'-m',str(model),'-ngl','99','-c','4096','--host','127.0.0.1','--port','8080']
    assert not any(key.endswith('_API_KEY') for key in runtime.clean_environment())


def test_external_override_does_not_start_runtime(monkeypatch):
    backend=ModelBackend('http://127.0.0.1:12345')
    monkeypatch.setattr(runtime,'ensure',lambda *a,**kw:pytest.fail('managed startup'))
    assert backend.prepare().endpoint=='http://127.0.0.1:12345'
    assert backend.managed is None


def test_removed_commands():
    import argparse
    parser=build_parser()
    choices=next(a.choices for a in parser._actions if isinstance(a,argparse._SubParsersAction))
    assert 'investigation' not in choices and 'ai-history' in choices
    semantic=next(a.choices for a in choices['semantic']._actions if isinstance(a,argparse._SubParsersAction))
    assert set(semantic)=={'search','status'}
    for words in (['investigation'],['semantic','setup'],['semantic','build'],['semantic','rebuild']):
        with pytest.raises(SystemExit):parser.parse_args(words)


@pytest.mark.parametrize('failure', ['timeout', 'provider_error', 'success'])
def test_cloud_worker_boundary_secrets_and_cleanup(monkeypatch, failure):
    import importlib.util
    import subprocess
    from forensic_assistant.ai import backend as implementation
    from forensic_assistant.llm.client import LLMError
    secret='synthetic-secret-never-log'
    monkeypatch.setenv('OPENAI_API_KEY',secret)
    monkeypatch.setenv('ANTHROPIC_API_KEY','unselected-secret')
    config={**settings.defaults(),'provider':'openai','model':'synthetic','cloud_acknowledged':True}
    client=ModelBackend(config=config,timeout=1)
    seen={}
    class Process:
        pid=123456
        returncode=None
        def communicate(self,data,timeout):
            seen['request']=json.loads(data)
            if failure=='timeout':raise subprocess.TimeoutExpired('synthetic',timeout)
            self.returncode=0
            return json.dumps({'error':secret} if failure=='provider_error' else {'text':secret,'usage':{}}).encode(),None
        def poll(self):return self.returncode
        def kill(self):seen['killed']=True;self.returncode=1
        def wait(self,timeout):seen['waited']=True;return self.returncode
    def spawn(*a,**kwargs):
        seen['env']=kwargs['env']
        return Process()
    monkeypatch.setattr(importlib.util,'find_spec',lambda name:object())
    monkeypatch.setattr(implementation.subprocess,'Popen',spawn)
    monkeypatch.setattr(implementation,'WorkerJob',lambda pid:SimpleNamespace(close=lambda:seen.update(closed=True)))
    messages=[{'role':'user','content':'only disclosed synthetic context'}]
    if failure=='success':
        assert client.complete(messages,{'type':'object'})=='[REDACTED]'
        assert client.last_metadata['provider']=='openai'
        assert secret not in json.dumps(client.last_metadata)
    else:
        with pytest.raises(LLMError) as error:client.complete(messages,{'type':'object'})
        assert secret not in str(error.value)
    assert seen['waited']
    assert seen['request']['messages']==messages
    assert secret not in json.dumps(seen['request'])
    assert seen['env']['OPENAI_API_KEY']==secret
    assert 'ANTHROPIC_API_KEY' not in seen['env']
    if failure=='timeout':assert seen['killed']


def test_oversized_context_never_starts_provider(monkeypatch):
    from forensic_assistant.llm.client import LLMError
    client=ModelBackend()
    monkeypatch.setattr(client,'prepare',lambda *a:pytest.fail('disclosed oversized context'))
    with pytest.raises(LLMError,match='disclosure'):
        client.complete([{'role':'user','content':'x'*(512*1024)}])


@pytest.mark.parametrize('action,label', [('show','Loading saved AI investigation...'),('replay','Replaying AI investigation...')])
@pytest.mark.parametrize('machine', [False,True])
def test_history_indicator_phase_and_json_gate(monkeypatch,action,label,machine):
    from forensic_assistant.investigation_ai import cli as history
    from forensic_assistant import terminal_activity
    seen=[]
    class Indicator:
        def __init__(self,text,*,args):
            real=terminal_activity.ActivityIndicator_original(text,args=args)
            seen.append((text,real.active))
        def __enter__(self):return self
        def __exit__(self,*a):seen.append('closed')
    monkeypatch.setattr(terminal_activity,'ActivityIndicator_original',terminal_activity.ActivityIndicator,raising=False)
    monkeypatch.setattr(terminal_activity,'capable',lambda _:True)
    monkeypatch.setattr(terminal_activity.sys.stdin,'isatty',lambda:True)
    monkeypatch.setattr(terminal_activity,'ActivityIndicator',Indicator)
    monkeypatch.setattr(history,'_dispatch',lambda args:{'synthetic':True})
    request=SimpleNamespace(command='ai-history',investigation_command=action,json=machine)
    assert history.dispatch(request)=={'synthetic':True}
    assert seen==[(label,not machine),'closed']



def test_cloud_controller_keeps_grounding_and_safe_transcript(tmp_path,monkeypatch):
    from forensic_assistant.investigation_ai import controller
    from forensic_assistant.investigation_ai.transcript import load
    from test_investigation_assessment import RecordingWorker
    from test_v4_controller import final
    secret='synthetic-cloud-credential'
    monkeypatch.setenv('OPENAI_API_KEY',secret)
    client=ModelBackend(config={**settings.defaults(),'provider':'openai','model':'synthetic','cloud_acknowledged':True})
    captured=[]
    def cloud(messages,schema,**kwargs):
        captured.append(messages)
        assert secret not in json.dumps(messages)
        assert str(tmp_path) not in json.dumps(messages)
        return {'text':json.dumps(final(messages)),'usage':{'total_tokens':5}}
    monkeypatch.setattr(client,'_cloud',cloud)
    worker=RecordingWorker({})
    result=controller.run({},'Inspect synthetic evidence',tmp_path/'runs',client=client,worker_factory=lambda _:worker)
    assert result['termination']=='ANSWER_SUPPORTED'
    assert result['findings']['observed'][0]['reported_value']=='synthetic.exe'
    assert result['model_metadata'][0]['provider']=='openai'
    manifest,events=load(tmp_path/'runs',result['investigation_id'])
    assert secret not in json.dumps([manifest,events,result])
    assert worker.calls==['initial','check'] and worker.closed
    assert captured


@pytest.mark.parametrize('dry_run',[False,True])
def test_backend_survives_supervisor_boundary_with_approval(tmp_path,local_model,dry_run):
    from forensic_assistant.investigation_ai import supervision
    from forensic_assistant.investigation_ai.state import Budget
    from test_v4_worker import make_case,config
    path=tmp_path/'case.db'
    make_case(path)
    before=path.read_bytes()
    decisions=[]
    client=ModelBackend('http://127.0.0.1:'+str(local_model.server_port))
    result=supervision.run(config(path),'PowerShell',tmp_path/'runs',
        client=client,dry_run=dry_run,budget=Budget(steps=1),
        approval=lambda *a:decisions.append(a) or False)
    assert bool(decisions) is (not dry_run)
    assert result['state']['accepted_calls']==0
    assert result['model_metadata'][0]['provider']=='local'
    assert path.read_bytes()==before



def test_cloud_worker_exits_despite_sdk_background_threads():
    import subprocess,sys
    from forensic_assistant.investigation_ai.lifecycle import WorkerJob
    script="""import sys,threading,time,types,runpy
threading.Thread(target=lambda:time.sleep(60),daemon=False).start()
response=types.SimpleNamespace(choices=[types.SimpleNamespace(finish_reason='stop',message=types.SimpleNamespace(content='{}'))])
sys.modules['litellm']=types.SimpleNamespace(completion=lambda **kwargs:response)
runpy.run_module('forensic_assistant.ai.cloud_worker',run_name='__main__')
"""
    process=subprocess.Popen([sys.executable,'-B','-c',script],stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={**runtime.clean_environment(),'OPENAI_API_KEY':'synthetic-only'})
    job=None
    try:
        job=WorkerJob(process.pid) if os.name=='nt' else None
        output,error=process.communicate(json.dumps(dict(provider='openai',model='synthetic',
            messages=[{'role':'user','content':'synthetic'}],timeout=2)).encode(),timeout=5)
        assert process.returncode==0 and not error
        assert json.loads(output)=={'text':'{}','usage':{}}
    finally:
        if job:job.close()
        if process.poll() is None:process.kill()
        process.wait(timeout=5)

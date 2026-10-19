"""Owned supervisor tests with a tiny synthetic server, never llama.cpp/model files."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import pytest
from forensic_assistant.ai import runtime, settings


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    fake=tmp_path/'fake.py'
    fake.write_text('''import json,sys
from http.server import HTTPServer,BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  data=json.dumps({'data':[{'id':'synthetic.gguf'}]}).encode()
  self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
HTTPServer(('127.0.0.1',int(sys.argv[1])),Handler).serve_forever()
''')
    entry=tmp_path/'manager.py'
    entry.write_text('''import sys,json
from forensic_assistant.ai import runtime
payload=json.loads(sys.stdin.read())
sys.stdin.close()
config=payload.get('config',payload)
cancel=payload.get('cancel',sys.argv[3] or None)
runtime.argv=lambda config,port:[sys.executable,sys.argv[1],str(port)]
runtime.serve(config,idle_seconds=float(sys.argv[2]),cancel=cancel)
''')
    entry.write_text("import sys; sys.path.insert(0, %r)\n" % str(Path(__file__).resolve().parents[1]) + entry.read_text())
    children=[]
    def start(idle=5, port=0, startup=5, model='synthetic.gguf', cancel=''):
        config={**settings.defaults(),'model_path':str(tmp_path/model),'port':port,'startup_seconds':startup}
        proc=subprocess.Popen([sys.executable,'-B',str(entry),str(fake),str(idle),cancel],stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        proc.config = config
        children.append(proc)
        proc.stdin.write(json.dumps(config).encode());proc.stdin.close()
        return proc
    start.entry=entry
    start.fake=fake
    yield start
    for proc in children:
        if proc.poll() is None:
            try:runtime.request(runtime.state(),'stop')
            except (OSError,ValueError):pass
            try:proc.wait(timeout=7)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=3)


def ready(proc):
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        assert proc.poll() is None, 'synthetic supervisor exited'
        saved=runtime.state()
        if saved:
            try:
                if runtime.request(saved,'status')['runtime']=='running':return saved
            except (OSError,ValueError):pass
        time.sleep(.05)
    pytest.fail('supervisor readiness timeout')


def test_foreign_session_is_never_owned(manager):
    proc=manager()
    saved=ready(proc)
    assert runtime.status(proc.config)['runtime']=='stopped'  # Port 0: no external discovery.
    runtime.close()
    assert proc.poll() is None
    runtime.request(saved,'stop')
    assert proc.wait(timeout=5)==0
    assert runtime.state() is None


def test_idle_shutdown_and_success_resets_timer(manager):
    proc=manager(idle=1.5)
    saved=ready(proc)
    lease=runtime.request(saved,'begin',seconds=4)['lease']
    time.sleep(1.6)
    assert proc.poll() is None  # Never stop an active bounded request.
    runtime.request(saved,'end',lease=lease,success=True)
    time.sleep(.5)
    assert proc.poll() is None
    assert proc.wait(timeout=4)==0
    assert runtime.state() is None


def test_collision_does_not_kill_occupant(manager):
    with socket.socket() as occupant:
        occupant.bind(('127.0.0.1',0));occupant.listen()
        proc=manager(port=occupant.getsockname()[1])
        assert proc.wait(timeout=5)!=0
        assert occupant.fileno()>=0
        assert runtime.state() is None


def test_bad_token_or_stale_pid_never_terminates_process(manager):
    proc=manager()
    saved=ready(proc)
    spoofed={**saved,'pid':os.getpid(),'token':'0'*64}
    with pytest.raises(ValueError):runtime.request(spoofed,'stop')
    assert proc.poll() is None
    # The owner is addressed by authenticated control, never by stored PID.
    assert runtime.request({**saved,'pid':os.getpid()},'status')['owned'] is True


def test_runtime_missing_files_no_process(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    monkeypatch.setattr(subprocess,'Popen',lambda *a,**k:pytest.fail('unexpected child'))
    with pytest.raises(ValueError,match='not configured'):
        runtime.ensure(settings.defaults())


def test_startup_timeout_closes_owned_listener(manager):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0))
        port=probe.getsockname()[1]
    proc=manager(port=port,startup=1,model='never-ready.gguf')
    assert proc.wait(timeout=5)!=0
    assert runtime.state() is None
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',port))


def test_startup_cancellation_closes_owned_listener(manager):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0))
        port=probe.getsockname()[1]
    proc=manager(port=port,model='never-ready.gguf',cancel='cancel-test')
    deadline=time.monotonic()+5
    while not settings.root().exists() and time.monotonic()<deadline:
        time.sleep(.05)
    (settings.root()/'cancel-test').touch()
    assert proc.wait(timeout=5)==0
    assert runtime.state() is None
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',port))



def test_session_reuse_stop_and_exit(manager, tmp_path, monkeypatch):
    config={**settings.defaults(),'port':0,'model_path':str(tmp_path/'synthetic.gguf'),'startup_seconds':5}
    monkeypatch.setattr(runtime,'argv',lambda config,port:[sys.executable,str(manager.fake),str(port)])
    try:
        saved=runtime.ensure(config)
        assert runtime.ensure(config)['instance']==saved['instance']
        assert runtime.status(config)['ownership']=='Locard-managed'
        lease=runtime.request(saved,'begin',seconds=5)['lease']
        with pytest.raises(ValueError):runtime.stop()
        runtime.request(saved,'end',lease=lease,success=True)
        runtime.stop()
        assert runtime.state() is None
        newer=runtime.ensure(config)
        assert newer['instance']!=saved['instance']
        runtime.close()
        assert runtime.state() is None
        with pytest.raises(OSError):runtime.request(newer,'status')
    finally:runtime.close()


def test_process_exit_cleans_server_and_state(manager,tmp_path):
    config={**settings.defaults(),'port':0,'model_path':str(tmp_path/'synthetic.gguf'),'startup_seconds':5}
    code="""import json,sys
from forensic_assistant.ai import runtime
runtime.argv=lambda config,port:[sys.executable,sys.argv[1],str(port)]
saved=runtime.ensure(json.loads(sys.argv[2]))
print(json.dumps(saved))
"""
    result=subprocess.run([sys.executable,'-B','-c',code,str(manager.fake),json.dumps(config)],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    saved=json.loads(result.stdout)
    assert runtime.state() is None
    with pytest.raises(OSError):runtime.request(saved,'status')
    assert runtime.IDLE_SECONDS==900


def test_two_model_requests_reuse_owned_runtime(manager,tmp_path,monkeypatch):
    from forensic_assistant.ai import backend
    config={**settings.defaults(),'port':0,'model_path':str(tmp_path/'synthetic.gguf'),'startup_seconds':5}
    monkeypatch.setattr(runtime,'argv',lambda config,port:[sys.executable,str(manager.fake),str(port)])
    calls=[]
    class SyntheticClient:
        def __init__(self,endpoint,timeout):
            calls.append(endpoint);self.last_metadata={}
        def complete(self,messages,schema):return '{"synthetic":true}'
    monkeypatch.setattr(backend,'LocalClient',SyntheticClient)
    try:
        saved=runtime.ensure(config)
        for _ in range(2):
            client=backend.ModelBackend(config=config)
            assert client.complete([{'role':'user','content':'synthetic'}])=='{"synthetic":true}'
            assert client.managed['instance']==saved['instance']
        assert len(calls)==2 and calls[0]==calls[1]
        assert runtime.status({**config,'extra_options':['--flash-attn','on']})['restart_required']
    finally:runtime.close()


def test_cancelled_owned_startup_cleans_worker(manager,tmp_path,monkeypatch):
    config={**settings.defaults(),'port':0,'model_path':str(tmp_path/'never-ready.gguf'),'startup_seconds':5}
    monkeypatch.setattr(runtime,'argv',lambda config,port:[sys.executable,str(manager.fake),str(port)])
    def interrupt():raise KeyboardInterrupt()
    monkeypatch.setattr(runtime,'state',interrupt)
    with pytest.raises(KeyboardInterrupt):runtime.ensure(config)
    assert runtime._worker is None and runtime._saved is None


@pytest.mark.skipif(os.name!='nt',reason='Windows launcher containment')
def test_launcher_exit_cleans_runtime(manager,tmp_path):
    import base64,shutil
    shell=shutil.which('powershell')
    if not shell:pytest.skip('Windows PowerShell unavailable')
    config={**settings.defaults(),'port':0,'model_path':str(tmp_path/'synthetic.gguf'),'startup_seconds':5}
    client=tmp_path/'session.py'
    client.write_text("import sys;sys.path.insert(0,%r)\n" % str(Path(__file__).resolve().parents[1])+'''import json
from forensic_assistant.ai import runtime
runtime.argv=lambda config,port:[sys.executable,sys.argv[1],str(port)]
saved=runtime.ensure(json.loads(sys.argv[2]))
print(json.dumps(runtime.request(saved,'status')))
''')
    def literal(value):return "'"+str(value).replace("'","''")+"'"
    helper=Path(__file__).resolve().parents[1]/'scripts/windows-process.ps1'
    code='. '+literal(helper)+'; $r=Invoke-LocardProcess -Interactive -Executable '+literal(sys.executable)+' -Arguments @('+','.join(map(literal,['-B',client,manager.fake,json.dumps(config)]))+'); exit $r.ExitCode'
    encoded=base64.b64encode(code.encode('utf-16le')).decode()
    result=subprocess.run([shell,'-NoProfile','-NonInteractive','-EncodedCommand',encoded],capture_output=True,text=True,timeout=25)
    assert result.returncode==0,result.stderr
    value=json.loads(result.stdout)
    assert runtime.state() is None
    port=int(value['endpoint'].rsplit(':',1)[1])
    with socket.socket() as probe:probe.bind(('127.0.0.1',port))


@pytest.mark.skipif(os.name!='nt',reason='Windows job cleanup')
def test_cleanup_failure_is_surfaced(manager,tmp_path,monkeypatch):
    config={**settings.defaults(),'port':0,'model_path':str(tmp_path/'synthetic.gguf'),'startup_seconds':5}
    monkeypatch.setattr(runtime,'argv',lambda config,port:[sys.executable,str(manager.fake),str(port)])
    original=runtime.WorkerJob
    class FailingJob:
        def __init__(self,pid):self.job=original(pid)
        def close(self):
            self.job.close()
            raise OSError('synthetic cleanup verification failure')
    monkeypatch.setattr(runtime,'WorkerJob',FailingJob)
    saved=runtime.ensure(config)
    with pytest.raises(runtime.CleanupError,match='CLEANUP_LIMITATION'):runtime.close()
    assert runtime._worker is None
    with pytest.raises(OSError):runtime.request(saved,'status')

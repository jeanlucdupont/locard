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
config=payload.get('config',payload)
cancel=payload.get('cancel',sys.argv[3] or None)
runtime.argv=lambda config,port:[sys.executable,sys.argv[1],str(port)]
runtime.serve(config,idle_seconds=float(sys.argv[2]),cancel=cancel)
''')
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
            try:runtime.stop()
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


def test_separate_clients_reuse_and_owned_stop(manager):
    proc=manager()
    saved=ready(proc)
    assert runtime.ensure(proc.config)['instance']==saved['instance']
    for _ in range(2):
        result=subprocess.run([sys.executable,'-B','-c',
            'from forensic_assistant.ai.runtime import status; import json; print(json.dumps(status()))'],
            capture_output=True,text=True,timeout=5,check=True)
        value=json.loads(result.stdout)
        assert value['runtime']=='running' and value['owned'] is True
        assert value['endpoint'].startswith('http://127.0.0.1:')
        assert proc.poll() is None
    assert runtime.state()['instance']==saved['instance']
    runtime.stop()
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
    with pytest.raises(ValueError,match='missing'):
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



def test_auto_start_survives_requesting_cli_exit_and_reuses(manager,tmp_path):
    model=tmp_path/'synthetic.gguf'
    model.write_bytes(b'synthetic only')
    config={**settings.defaults(),'executable':sys.executable,'model_path':str(model),'port':0,'startup_seconds':10}
    client=tmp_path/'client.py'
    client.write_text("""import json,sys,subprocess
from forensic_assistant.ai import runtime
original=subprocess.Popen
def spawn(command,**kwargs):
 return original([sys.executable,'-B',sys.argv[1],sys.argv[2],'15',''],**kwargs)
runtime.subprocess.Popen=spawn
saved=runtime.ensure(json.loads(sys.argv[3]))
print(saved['instance'])
""")
    command=[sys.executable,'-B',str(client),str(manager.entry),str(manager.fake),json.dumps(config)]
    try:
        first=subprocess.run(command,capture_output=True,text=True,timeout=15,check=True)
        assert runtime.status()['runtime']=='running'
        second=subprocess.run(command,capture_output=True,text=True,timeout=15,check=True)
        assert first.stdout.strip()==second.stdout.strip()==runtime.state()['instance']
    finally:
        if runtime.state():runtime.stop()
    assert runtime.state() is None



def test_interrupted_startup_closes_config_pipe_and_waits(tmp_path,monkeypatch):
    import io
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    monkeypatch.setattr(runtime,'argv',lambda *a:[])
    class Pipe(io.BytesIO):
        def write(self,data):raise KeyboardInterrupt()
    class Process:
        stdin=Pipe()
        waited=False
        def wait(self,timeout):
            assert self.stdin.closed
            assert list(settings.root().glob('cancel-*'))
            self.waited=True
        def poll(self):return 0 if self.waited else None
    process=Process()
    monkeypatch.setattr(runtime.subprocess,'Popen',lambda *a,**k:process)
    with pytest.raises(KeyboardInterrupt):runtime.ensure(settings.defaults())
    assert process.waited and not list(settings.root().glob('cancel-*'))

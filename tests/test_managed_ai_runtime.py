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
        assert value['runtime_reported_models']==['synthetic.gguf']
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



def test_auto_start_survives_requesting_cli_exit_and_reuses(manager,tmp_path):
    model=tmp_path/'synthetic.gguf'
    model.write_bytes(b'synthetic only')
    config={**settings.defaults(),'executable':sys.executable,'model_path':str(model),'port':0,'startup_seconds':10}
    client=tmp_path/'client.py'
    client.write_text("""import json,sys,subprocess
from forensic_assistant.ai import runtime
original=subprocess.Popen
def spawn(command,**kwargs):
 return original([command[0],'-B',sys.argv[1],sys.argv[2],'15',''],**kwargs)
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

@pytest.mark.skipif(os.name != 'nt', reason='Windows launcher Job Object boundary')
@pytest.mark.parametrize('entry_launcher,cached_legacy', [(False,False),(True,False),(True,True)])
def test_supervisor_breaks_away_from_launcher_job(manager, tmp_path, entry_launcher, cached_legacy):
    import base64
    import shutil
    shell = shutil.which('powershell')
    if not shell: pytest.skip('Windows PowerShell unavailable')
    model = tmp_path/'synthetic.gguf'; model.write_bytes(b'synthetic')
    config = {**settings.defaults(), 'executable':sys.executable, 'model_path':str(model), 'port':0, 'startup_seconds':10}
    config_file = tmp_path/'config-input.json'; config_file.write_text(json.dumps(config))
    client = tmp_path/'client.py'
    client.write_text('''import json,sys,subprocess
from forensic_assistant.ai import runtime
original=subprocess.Popen
def spawn(command,**kwargs):
 assert kwargs['close_fds'] is True
 assert kwargs['creationflags'] & subprocess.CREATE_NO_WINDOW
 assert kwargs['creationflags'] & subprocess.CREATE_BREAKAWAY_FROM_JOB
 return original([command[0],'-B',sys.argv[1],sys.argv[2],'30',''],**kwargs)
runtime.subprocess.Popen=spawn
saved=runtime.ensure(json.load(open(sys.argv[3])))
print(saved['instance'])
''')
    client.write_text("import sys; sys.path.insert(0, %r)\n" % str(Path(__file__).resolve().parents[1]) + client.read_text())
    interpreter = os.environ.get("LOCARD_TEST_PYTHON", sys.executable)
    executable = interpreter
    arguments = ['-B',client,manager.entry,manager.fake,config_file]
    if entry_launcher:
        # Match pip's real console entry-point executable, including its job.
        import io, zipfile
        from pip._vendor import distlib
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('__main__.py', client.read_text())
        executable = tmp_path/'locard-fixture.exe'
        launcher = Path(distlib.__file__).parent/'t64.exe'
        executable.write_bytes(launcher.read_bytes() + ('#!'+interpreter+'\n').encode() + archive.getvalue())
        arguments = [manager.entry,manager.fake,config_file]
    def literal(value): return "'" + str(value).replace("'", "''") + "'"
    root = Path(__file__).resolve().parents[1]
    code = '. '+literal(root/'scripts/windows-process.ps1')+'; $r=Invoke-LocardProcess -Interactive -Executable '+literal(executable)+' -Arguments @('+','.join(map(literal, arguments))+'); exit $r.ExitCode'
    if cached_legacy:
        old = (root/'scripts/windows-process.cs').read_text().replace('if(!cancelOnSignal) limits.basic.flags |= 0x800;', '')
        code = 'Add-Type -TypeDefinition '+literal(old)+'; '+code
    encoded=base64.b64encode(code.encode('utf-16le')).decode()
    try:
        first=subprocess.run([shell,'-NoProfile','-NonInteractive','-EncodedCommand',encoded], capture_output=True,text=True,timeout=25)
        assert first.returncode == 0, first.stderr
        saved=runtime.state()
        assert saved and runtime.request(saved,'status')['runtime']=='running'
        second=subprocess.run([shell,'-NoProfile','-NonInteractive','-EncodedCommand',encoded],capture_output=True,text=True,timeout=25)
        assert second.returncode == 0, second.stderr
        assert first.stdout.strip() == second.stdout.strip() == saved['instance']
        assert runtime.state()['instance'] == saved['instance']
        assert runtime.request(saved,'status')['active_configuration'] == saved['active_configuration']
        assert saved['active_configuration']['context'] == 4096
    finally:
        if runtime.state(): runtime.stop()


def test_two_model_requests_reuse_owned_runtime(manager, monkeypatch):
    from forensic_assistant.ai import backend
    proc = manager(idle=10)
    saved = ready(proc)
    calls = []
    class SyntheticClient:
        def __init__(self, endpoint, timeout):
            calls.append(endpoint)
            self.last_metadata = {}
        def complete(self, messages, schema): return '{"synthetic":true}'
    monkeypatch.setattr(backend, 'LocalClient', SyntheticClient)
    for _ in range(2):
        client = backend.ModelBackend(config=proc.config)
        assert client.complete([{'role':'user','content':'synthetic'}]) == '{"synthetic":true}'
        assert client.managed['instance'] == saved['instance']
    assert len(calls) == 2 and calls[0] == calls[1]
    assert runtime.state()['instance'] == saved['instance'] and proc.poll() is None
    changed = {**proc.config, 'extra_options':['--flash-attn','on']}
    assert runtime.status(changed)['restart_required'] is True
    assert runtime.status(proc.config)['restart_required'] is False

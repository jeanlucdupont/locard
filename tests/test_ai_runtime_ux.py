"""Synthetic local runtime UX/security boundaries; no real AI server or evidence."""
import json
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from types import SimpleNamespace
import pytest
from forensic_assistant.ai import runtime, settings, cli, options, diagnostics
from forensic_assistant.ai.backend import ModelBackend, restart_confirmation


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))


@pytest.fixture
def endpoint():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            data = {'status': 'ok'} if self.path == '/health' else {'data': [{'id': 'synthetic.gguf'}]}
            body = json.dumps(data).encode()
            self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    server = HTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    yield server
    server.shutdown(); thread.join(); server.server_close()


def test_external_discovery_reuse_stop_and_logs(endpoint, monkeypatch):
    config = {**settings.defaults(), 'port': endpoint.server_port}
    settings.save(config)
    monkeypatch.setattr(runtime, 'ensure', lambda *a: pytest.fail('external must not start a child'))
    monkeypatch.setattr(runtime, 'stop', lambda: pytest.fail('external must not be stopped'))
    current = runtime.status(config)
    assert current['ownership'] == 'external' and current['runtime'] == 'running'
    assert 'idle_timeout_seconds' not in current
    client = ModelBackend(config=config).prepare()
    assert client.managed is None and client.endpoint == current['endpoint']
    for command in ('start', 'stop', 'logs'):
        result = cli.dispatch(SimpleNamespace(ai_command=command, json=False))
        if command == 'stop': assert 'Locard will not stop it' in result['message']
        if command == 'logs': assert 'external runtime logs' in result['logs']
    assert runtime.external(config)['runtime'] == 'running'


def test_stale_state_normalizes_stopped(monkeypatch):
    monkeypatch.setattr(runtime, 'state', lambda: {'pid': os.getpid()})
    assert runtime.status({**settings.defaults(), 'port': 0})['runtime'] == 'stopped'


@pytest.mark.parametrize('text', ['--host 0.0.0.0', '--host=0.0.0.0', '-m other.gguf', '--model=x', '--port 20',
    '--model-url https://example.test', '--api-key secret', 'cmd.exe /c', '-c 4096 & echo bad',
    '--flash-attn "on', '-c 4096 -c 8192', '--threads 2;whoami', '--flash-attn $(whoami)'])
def test_unsafe_options_rejected(text):
    with pytest.raises(ValueError): options.parse(text)


def test_options_canonical_defaults_and_identity(tmp_path):
    exe = tmp_path/'llama-server.exe'; exe.write_bytes(b'synthetic')
    model = tmp_path/'model.gguf'; model.write_bytes(b'synthetic')
    config = {**settings.defaults(), 'executable': str(exe), 'model_path': str(model)}
    original = runtime.argv(config, 8080)
    assert original[original.index('-ngl')+1] == '99' and original[original.index('-c')+1] == '4096'
    fields, extra = options.parse('-ngl "50" -c 8192 --flash-attn=on --threads 4')
    changed = {**config, **fields, 'extra_options': extra}
    command = runtime.argv(changed, 8080)
    assert command.count('-ngl') == command.count('-c') == 1
    assert command[command.index('-ngl')+1] == '50'
    assert command[-4:] == ['--flash-attn', 'on', '--threads', '4']
    assert runtime.identity(config) != runtime.identity(changed)
    assert settings.validate({k:v for k,v in config.items() if k != 'extra_options'})['extra_options'] == []


@pytest.mark.parametrize('accept', [True, False])
def test_managed_restart_confirmation(accept, monkeypatch):
    config = settings.defaults(); calls = []
    monkeypatch.setattr(runtime, 'status', lambda c: {'runtime':'running', 'ownership':'Locard-managed', 'restart_required':True})
    monkeypatch.setattr(runtime, 'stop', lambda: calls.append('stop'))
    monkeypatch.setattr(runtime, 'ensure', lambda *a: calls.append('start') or {'instance':'new'})
    monkeypatch.setattr(runtime, 'request', lambda *a: {'endpoint':'http://127.0.0.1:4567'})
    prompts = []
    with restart_confirmation(lambda p: prompts.append(p) or ('' if accept else 'n')):
        if accept:
            assert ModelBackend(config=config).prepare().managed == {'instance':'new'}
        else:
            with pytest.raises(ValueError, match='left running'): ModelBackend(config=config).prepare()
    assert calls == (['stop','start'] if accept else [])
    assert prompts == ['Restart the managed AI runtime now? [Y/n]: ']


def test_safe_bounded_logs(tmp_path):
    import io
    diagnostics.drain(io.BytesIO(b'error SECRET evidence prompt\nwarning PRIVATE credential\n'*1000))
    result = diagnostics.tail()
    assert 'SECRET' not in result and 'PRIVATE' not in result
    assert result.count('reported an error') == 1
    assert (settings.root()/'llama-server.log').stat().st_size < 32768


@pytest.mark.parametrize('field,target', [('executable','llama-server.exe file'), ('model_path','.gguf model file')])
def test_folder_messages(tmp_path, field, target):
    exe=tmp_path/'llama.exe'; exe.write_bytes(b'synthetic')
    model=tmp_path/'model.gguf'; model.write_bytes(b'synthetic')
    config={**settings.defaults(),'executable':str(exe),'model_path':str(model),field:str(tmp_path)}
    assert settings.local_configuration(config)['configuration_detail'] == 'The selected path must point to the '+target+', not a folder.'


def test_render_ownership_restart_and_no_json_color(monkeypatch):
    from forensic_assistant import terminal
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    value={'provider':'Local','runtime':'running','ownership':'Locard-managed','restart_required':True}
    assert '\x1b[' in cli.render(value)
    plain=cli.render(value, SimpleNamespace(json=True))
    assert '\x1b[' not in plain and 'restart required' in plain and 'Ownership: Locard-managed' in plain
    monkeypatch.setattr(terminal, 'capable', lambda stream: False)
    assert '\x1b[' not in cli.render(value)


def test_external_incompatible_health_not_reused(endpoint, monkeypatch):
    monkeypatch.setattr(runtime, 'model_identity', lambda port: [])
    assert runtime.external({**settings.defaults(), 'port':endpoint.server_port}) is None


def test_missing_path_specific_message(tmp_path):
    exe=tmp_path/'llama-server.exe'; exe.write_bytes(b'synthetic')
    config={**settings.defaults(), 'executable':str(exe), 'model_path':str(tmp_path/'missing.gguf')}
    assert settings.local_configuration(config)['configuration_detail'] == 'GGUF model file was not found at that location.'
    config['executable']=str(tmp_path/'missing.exe')
    assert settings.local_configuration(config)['configuration_detail'] == 'llama-server.exe was not found at that location.'


def test_configure_extra_options_conflicts_and_persistence(tmp_path, monkeypatch):
    from forensic_assistant.cli import build_parser
    monkeypatch.setattr(runtime, 'external', lambda config: None)
    def args(*words): return build_parser().parse_args(['ai','configure',*words])
    cli.dispatch(args('--extra-options','-ngl 50 -c 8192 --flash-attn on'))
    saved=settings.load()
    assert saved['gpu_layers']==50 and saved['context']==8192 and saved['extra_options']==['--flash-attn','on']
    before=(settings.root()/'config.json').read_bytes()
    with pytest.raises(ValueError, match='dedicated setting'):
        cli.dispatch(args('--context','4096','--extra-options','-c 8192'))
    assert (settings.root()/'config.json').read_bytes()==before
    cli.dispatch(args('--extra-options',''))
    assert settings.load()['extra_options']==[] and settings.load()['context']==8192


def test_restart_stops_indicator_before_prompt():
    from forensic_assistant.ai.backend import RESTART
    order=[]
    indicator=SimpleNamespace(stop=lambda:order.append('stop'))
    with restart_confirmation(lambda prompt:order.append('prompt') or 'n', indicator):
        assert RESTART.get()() is False
    assert order==['stop','prompt']


def test_status_configured_and_active_options(monkeypatch):
    config={**settings.defaults(), 'gpu_layers':50, 'context':1024, 'extra_options':['--flash-attn','on']}
    monkeypatch.setattr(runtime, 'status', lambda c: {'runtime':'stopped'})
    stopped=cli.status(config)
    text=cli.render(stopped)
    assert 'GPU layers: 50' in text and 'Context size: 1024' in text and 'Extra options: --flash-attn on' in text
    assert 'Active context' not in text and 'active_options' not in stopped
    active=runtime.active_configuration({**config,'context':2048},8080)
    active.update(token='SECRET', evidence='PRIVATE', instance='CONTROL')
    monkeypatch.setattr(runtime, 'status', lambda c: dict(runtime='running', owned=True, ownership='Locard-managed', restart_required=True, active_configuration=active))
    changed=cli.status(config);text=cli.render(changed)
    assert 'Configured context size: 1024' in text and 'Active context size: 2048' in text and 'restart required' in text
    assert not any(secret in json.dumps(changed)+text for secret in ('SECRET','PRIVATE','CONTROL','config_identity'))
    monkeypatch.setattr(runtime, 'status', lambda c: dict(runtime='running', owned=True, ownership='Locard-managed', restart_required=False, active_configuration=runtime.active_configuration(config,8080)))
    text=cli.render(cli.status(config))
    assert 'Context size: 1024' in text and 'restart required' not in text


def test_external_options_remain_configured_only(endpoint):
    config={**settings.defaults(), 'port':endpoint.server_port, 'context':1024}
    result=cli.status(config);text=cli.render(result)
    assert 'Configured options' in text and 'Context size: 1024' in text
    assert 'active_options' not in result and 'Active context' not in text
    assert 'restart required' not in text and 'manually to apply' not in text


def test_quit_closes_session_owned_runtime(tmp_path, monkeypatch):
    from test_interactive_shell import Input, case
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    closed = []
    monkeypatch.setattr(runtime, 'close', lambda: closed.append(True))
    monkeypatch.setattr(runtime, 'external', lambda config: None)
    assert Shell(State(None), Input(str(case(tmp_path)), 'quit'), no_color=True).run() == 0

    assert closed == [True]


def test_external_survives_shell_exit(endpoint,tmp_path):
    from test_interactive_shell import Input, case
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    config={**settings.defaults(),'port':endpoint.server_port}
    settings.save(config)
    assert Shell(State(None),Input(str(case(tmp_path)),'quit'),no_color=True).run()==0
    assert runtime.external(config)['ownership']=='external'

"""Owned persistent llama.cpp supervisor; control uses authenticated loopback JSON.

No PID read from disk is ever terminated. Only the supervisor's Popen/job handles
can stop a child. Direct clients communicate with the owner, not the server PID.
"""
from contextlib import contextmanager
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time

from . import settings
from forensic_assistant.investigation_ai.storage import local_path, DirectoryGuard
from forensic_assistant.investigation_ai.lifecycle import WorkerJob, CleanupError

IDLE_SECONDS = 900


def clean_environment():
    # No provider credentials, proxy overrides or SDK telemetry settings in daemon.
    keep = ('SYSTEMROOT', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'LOCALAPPDATA', 'USERPROFILE',
            'APPDATA', 'PROGRAMFILES', 'PROGRAMFILES(X86)', 'COMSPEC')
    return {k: v for k, v in os.environ.items() if k.upper() in keep}


@contextmanager
def lock(path):
    local_path(path)
    with path.open('a+b') as stream:
        if stream.tell() == 0:
            stream.write(b'0'); stream.flush()
        stream.seek(0)
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def identity(config):
    return hashlib.sha256(json.dumps({k: config[k] for k in
        ('executable', 'model_path', 'context', 'gpu_layers', 'port')}, sort_keys=True).encode()).hexdigest()


def argv(config, port):
    settings.require_local(config)
    executable, model = (local_path(config[k]) for k in ('executable', 'model_path'))
    if not executable.is_file() or not model.is_file():
        raise ValueError('Local AI executable/model missing. Use ai configure --executable PATH --model-path PATH; no downloads are automatic.')
    if os.name == 'nt' and executable.suffix.lower() != '.exe':
        raise ValueError('Local runtime executable must be an .exe file')
    return [str(executable), '-m', str(model), '-ngl', str(config['gpu_layers']),
            '-c', str(config['context']), '--host', '127.0.0.1', '--port', str(port)]


def request(state, action, **fields):
    if (type(state) is not dict or state.get('format') != 1 or
        type(state.get('control_port')) is not int or not 1 <= state['control_port'] <= 65535 or
        type(state.get('token')) is not str or len(state['token']) != 64):
        raise ValueError('Invalid local runtime state')
    connection = http.client.HTTPConnection('127.0.0.1', state['control_port'], timeout=3)
    try:
        connection.request('POST', '/', json.dumps(dict(action=action, **fields)),
                           {'Authorization': state['token'], 'Content-Type': 'application/json'})
        response = connection.getresponse()
        data = response.read(65537)
        if response.status != 200 or len(data) > 65536:
            raise ValueError('Local runtime control unavailable')
        result = json.loads(data)
        if result.get('instance') != state.get('instance'):
            raise ValueError('Local runtime owner mismatch')
        return result
    finally:
        connection.close()


def state():
    path = settings.root() / 'runtime.json'
    return settings.read(path) if path.exists() else None


def status():
    saved = state()
    if not saved:
        return {'runtime': 'stopped', 'idle_timeout_seconds': IDLE_SECONDS}
    try:
        result = request(saved, 'status')
        return {k: v for k, v in result.items() if k != 'instance'}
    except (OSError, ValueError, http.client.HTTPException):
        return {'runtime': 'stale or unavailable', 'idle_timeout_seconds': IDLE_SECONDS}


def stop():
    saved = state()
    if not saved:
        return {'runtime': 'stopped'}
    try:
        result = request(saved, 'stop')
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            current = state()
            if not current or current.get('instance') != saved['instance']:
                return {'runtime': 'stopped'}
            time.sleep(.05)
        raise CleanupError('CLEANUP_LIMITATION: owned runtime shutdown could not be confirmed')
    except (OSError, ValueError, http.client.HTTPException):
        raise ValueError('Managed runtime is unavailable; no process was terminated by PID.') from None


def ensure(config, phase=None):
    settings.validate(config)
    deadline = time.monotonic() + config['startup_seconds']
    with settings.private_root() as root:
        while True:
            try:
                with lock(root / 'startup.lock'):
                    saved = state()
                    if saved:
                        try:
                            current = request(saved, 'status')
                        except (OSError, ValueError, http.client.HTTPException):
                            current = None
                        if current:
                            if current.get('config_identity') != identity(config):
                                raise ValueError('Managed runtime uses different settings. Run ai stop before changing the running model.')
                            return saved
                    argv(config, config['port'])  # Validate before starting a supervisor.
                    if phase: phase('Starting local AI...')
                    flags = (subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP) if os.name == 'nt' else 0
                    process = subprocess.Popen([sys.executable, '-B', '-m', 'forensic_assistant.ai.runtime'],
                        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        env=clean_environment(), creationflags=flags, start_new_session=os.name != 'nt',
                        cwd=str(Path(__file__).resolve().parents[2]))
                    cancellation = root / ('cancel-' + secrets.token_hex(16))
                    ready = False
                    try:
                        process.stdin.write(json.dumps({'config': config, 'cancel': cancellation.name}).encode())
                        process.stdin.close()
                        if phase: phase('Waiting for local AI...')
                        while time.monotonic() < deadline:
                            if process.poll() is not None:
                                raise ValueError('Local AI startup failed. Check executable/model settings and whether the configured port is occupied.')
                            latest = state()
                            if latest and latest != saved:
                                try:
                                    current = request(latest, 'status')
                                    if current.get('config_identity') == identity(config) and current.get('runtime') == 'running':
                                        ready = True
                                        return latest
                                except (OSError, ValueError, http.client.HTTPException):
                                    pass
                            time.sleep(.1)
                        raise ValueError('Local AI startup timed out')
                    finally:
                        if not ready:
                            if not process.stdin.closed:
                                process.stdin.close()
                            # Cooperative cancellation lets the supervisor close its
                            # own job even during model loading; never kill a saved PID.
                            cancellation.touch(exist_ok=False)
                            try:
                                process.wait(timeout=8)
                            except subprocess.TimeoutExpired:
                                raise CleanupError('CLEANUP_LIMITATION: local startup cleanup could not be confirmed') from None
                            finally:
                                if process.poll() is not None:
                                    cancellation.unlink(missing_ok=True)
            except BlockingIOError:
                pass
            except OSError as exc:
                if getattr(exc, 'winerror', None) not in (33, 36):
                    raise
            if time.monotonic() >= deadline:
                raise ValueError('Another local AI startup is still in progress')
            time.sleep(.1)


def model_identity(port):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
    try:
        connection.request('GET', '/v1/models')
        response = connection.getresponse()
        raw = response.read(65537)
        if response.status != 200 or len(raw) > 65536:
            return []
        return [item['id'] for item in json.loads(raw).get('data', [])[:64]
                if type(item) is dict and type(item.get('id')) is str and len(item['id']) <= 1024]
    except (OSError, ValueError, TypeError, AttributeError, http.client.HTTPException):
        return []
    finally:
        connection.close()


def model_ready(port, model):
    return Path(model).name in [name.replace('\\', '/').split('/')[-1] for name in model_identity(port)]


def serve(config, *, idle_seconds=IDLE_SECONDS, cancel=None):
    # idle_seconds is a test injection only; production CLI has no timeout override.
    with settings.private_root() as root, lock(root / 'supervisor.lock'):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', config['port']))
            port = probe.getsockname()[1]
        cancellation = local_path(root / cancel) if cancel else None
        def cancelled():
            return cancellation is not None and cancellation.exists()
        token, instance = secrets.token_hex(32), secrets.token_hex(16)
        child = None
        job = None
        published = False
        leases = {}
        reported_models = []
        last_use = time.monotonic()
        stopping = False
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                nonlocal last_use, stopping
                self.connection.settimeout(2)
                if not hmac.compare_digest(self.headers.get('Authorization', ''), token):
                    self.send_error(403); return
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 4096: raise ValueError()
                    body = json.loads(self.rfile.read(length))
                    action = body['action']
                    result = dict(instance=instance, runtime='running', owned=True,
                        endpoint=f'http://127.0.0.1:{port}', model=Path(config['model_path']).name,
                        idle_timeout_seconds=IDLE_SECONDS, config_identity=identity(config),
                        runtime_reported_models=reported_models)
                    if action == 'begin':
                        seconds = body.get('seconds')
                        if type(seconds) not in (int, float) or not 0 < seconds <= 600: raise ValueError()
                        lease = secrets.token_hex(16)
                        leases[lease] = time.monotonic() + seconds + 5
                        result['lease'] = lease
                    elif action == 'end':
                        lease = body.get('lease')
                        if lease not in leases: raise ValueError()
                        leases.pop(lease)
                        if body.get('success') is True: last_use = time.monotonic()
                    elif action == 'stop':
                        if leases: raise ValueError()
                        stopping = True
                        result['runtime'] = 'stopping'
                    elif action != 'status': raise ValueError()
                    data = json.dumps(result).encode()
                    self.send_response(200); self.send_header('Content-Length', str(len(data))); self.end_headers()
                    self.wfile.write(data)
                except (ValueError, KeyError, TypeError, OSError):
                    self.send_error(400)
        class Server(HTTPServer):
            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(2)
                return connection, address
        server = Server(('127.0.0.1', 0), Handler)
        server.timeout = .25
        try:
            if cancelled(): return
            child = subprocess.Popen(argv(config, port), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=clean_environment(),
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            job = WorkerJob(child.pid) if os.name == 'nt' else None
            deadline = time.monotonic() + config['startup_seconds']
            while not model_ready(port, config['model_path']):
                if cancelled(): return
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError('Local model did not become ready')
                time.sleep(.1)
            if cancelled(): return
            reported_models = model_identity(port)
            settings.write(root / 'runtime.json', dict(format=1, token=token, instance=instance,
                control_port=server.server_port, pid=child.pid, started=time.time()))
            published = True
            last_use = time.monotonic()
            while not stopping and child.poll() is None and not cancelled():
                now = time.monotonic()
                leases = {key: expiry for key, expiry in leases.items() if expiry > now}
                if not leases and now - last_use >= idle_seconds: break
                server.handle_request()
        finally:
            server.server_close()
            if job: job.close()
            if child and child.poll() is None:
                child.terminate()
            if child: child.wait(timeout=5)
            if published and (state() or {}).get('instance') == instance:
                local_path(root / 'runtime.json').unlink()


if __name__ == '__main__':
    try:
        value = json.loads(sys.stdin.buffer.read(65537))
        import re
        if not re.fullmatch(r'cancel-[0-9a-f]{32}', value['cancel']):
            raise ValueError('Invalid cancellation identifier')
        serve(settings.validate(value['config']), cancel=value['cancel'])
    except BaseException:
        sys.exit(1)

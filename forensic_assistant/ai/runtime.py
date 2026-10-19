"""Session-owned llama.cpp monitor; control uses authenticated loopback JSON.

No PID read from disk is ever terminated. Only this process's Popen/job handles
can stop a child. Bounded workers use authenticated control, not the server PID.
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
import threading
import logging

from . import settings
from forensic_assistant.investigation_ai.storage import local_path, DirectoryGuard
from forensic_assistant.investigation_ai.lifecycle import WorkerJob, CleanupError

IDLE_SECONDS = 900


# Only this process may own/stop this runtime. Disk metadata is not ownership.
_worker = None
_cancel = None
_saved = None
_finished = None
_failure = []


def close():
    global _worker, _cancel, _saved, _finished
    if _worker is None:
        return
    _cancel.set()
    deadline = time.monotonic() + 15
    while not _finished.is_set() and time.monotonic() < deadline:
        try:
            _finished.wait(timeout=min(.25, max(0, deadline-time.monotonic())))
        except KeyboardInterrupt:
            # A second Ctrl+C cannot abandon owned-process cleanup.
            continue
    if not _finished.is_set():
        raise CleanupError('CLEANUP_LIMITATION: session AI runtime cleanup could not be confirmed')
    _worker.join(timeout=1)
    _worker = _cancel = _saved = _finished = None
    if _failure and isinstance(_failure[0], CleanupError):
        raise _failure[0]


def _exit_cleanup():
    try:
        close()
    except CleanupError:
        print('CLEANUP_LIMITATION: session AI runtime cleanup could not be confirmed', file=sys.stderr)


import atexit
atexit.register(_exit_cleanup)


def clean_environment():
    # No provider credentials, proxy overrides or SDK telemetry settings in the managed child.
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
    config = settings.validate(config)
    return hashlib.sha256(json.dumps({k: config[k] for k in
        ('executable', 'model_path', 'context', 'gpu_layers', 'port', 'extra_options')}, sort_keys=True).encode()).hexdigest()


def active_configuration(config, port):
    config = settings.validate(config)
    return dict(gpu_layers=config['gpu_layers'], context=config['context'],
                extra_options=list(config['extra_options']), port=port,
                executable_identity=hashlib.sha256(config['executable'].encode()).hexdigest(),
                model_path_identity=hashlib.sha256(config['model_path'].encode()).hexdigest(),
                config_identity=identity(config))


def argv(config, port):
    settings.require_local(config)
    executable, model = (local_path(config[k]) for k in ('executable', 'model_path'))
    if not executable.is_file() or not model.is_file():
        raise ValueError('Local AI executable/model missing. Use ai configure --executable PATH --model-path PATH; no downloads are automatic.')
    if os.name == 'nt' and executable.suffix.lower() != '.exe':
        raise ValueError('Local runtime executable must be an .exe file')
    return [str(executable), '-m', str(model), '-ngl', str(config['gpu_layers']),
            '-c', str(config['context']), '--host', '127.0.0.1', '--port', str(port)] + settings.validate(config)['extra_options']


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


def external(config):
    """Read-only, numeric-loopback health/API probe. Never infer ownership."""
    port = config['port']
    if not port:
        return None
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=.5)
    try:
        connection.request('GET', '/health')
        response = connection.getresponse()
        raw = response.read(4097)
        if response.status != 200 or len(raw) > 4096 or json.loads(raw).get('status') != 'ok':
            return None
    except (OSError, ValueError, AttributeError, RecursionError, http.client.HTTPException):
        return None
    finally:
        connection.close()
    models = model_identity(port)
    if not models:
        return None
    return dict(runtime='running', owned=False, ownership='external',
                endpoint=f'http://127.0.0.1:{port}', runtime_reported_models=models,
                configuration_differs=bool(config['model_path']) and Path(config['model_path']).name not in
                    [name.replace('\\', '/').split('/')[-1] for name in models],
                configuration_detail='Active performance options are unknown for this external runtime.')


def status(config=None):
    config = settings.load() if config is None else config
    saved = _saved
    if saved:
        try:
            result = request(saved, 'status')
            return {**{k: v for k, v in result.items() if k != 'instance'},
                    'ownership': 'Locard-managed',
                    'restart_required': result.get('config_identity') != identity(config)}
        except (OSError, ValueError, http.client.HTTPException):
            logging.getLogger(__name__).debug('Stale or unavailable authenticated runtime state')
    return external(config) or {'runtime': 'stopped', 'idle_timeout_seconds': IDLE_SECONDS}


def acquire(config, phase=None, confirm=None):
    current = status(config)
    if current.get('ownership') == 'external':
        return current['endpoint'], None
    if current.get('restart_required'):
        if confirm is None or not confirm():
            raise ValueError('Configured changes are not active; the current managed runtime was left running.')
        stop()
    saved = ensure(config, phase)
    return request(saved, 'status')['endpoint'], saved


def stop():
    if _saved and _worker and _worker.is_alive():
        request(_saved, 'stop')  # Active leases still prevent explicit shutdown.
    close()
    return {'runtime': 'stopped'}


def ensure(config, phase=None):
    global _worker, _cancel, _saved, _finished
    config = settings.validate(config)
    if _worker is not None:
        if _worker.is_alive() and _saved:
            if request(_saved, 'status').get('config_identity') != identity(config):
                raise ValueError('Managed runtime uses different settings. Run ai stop first.')
            return _saved
        close()
    argv(config, config['port'])
    if phase: phase('Starting local AI...')
    _cancel = threading.Event()
    _finished = threading.Event()
    _failure.clear()
    instance = secrets.token_hex(16)
    def monitor():
        try:
            serve(config, cancelled_event=_cancel, instance_id=instance)
        except BaseException as exc:
            _failure.append(exc)
        finally:
            _finished.set()
    _worker = threading.Thread(target=monitor, daemon=True, name='Locard session AI runtime')
    _worker.start()
    ready = False
    try:
        deadline = time.monotonic() + config['startup_seconds']
        while time.monotonic() < deadline:
            if not _worker.is_alive():
                raise ValueError('Local AI startup failed. Check executable/model settings and port availability. See ai logs.')
            latest = state()
            if latest and latest.get('instance') == instance:
                current = request(latest, 'status')
                if current.get('runtime') == 'running':
                    _saved = latest
                    ready = True
                    return latest
            time.sleep(.05)
        raise ValueError('Local AI startup timed out')
    finally:
        if not ready:
            close()


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
    except (OSError, ValueError, TypeError, AttributeError, RecursionError, http.client.HTTPException):
        return []
    finally:
        connection.close()


def model_ready(port, model):
    return Path(model).name in [name.replace('\\', '/').split('/')[-1] for name in model_identity(port)]


def serve(config, *, idle_seconds=IDLE_SECONDS, cancel=None, cancelled_event=None, instance_id=None):
    # idle_seconds is a test injection only; production CLI has no timeout override.
    with settings.private_root() as root, lock(root / 'supervisor.lock'):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', config['port']))
            port = probe.getsockname()[1]
        cancellation = local_path(root / cancel) if cancel else None
        def cancelled():
            return (cancelled_event is not None and cancelled_event.is_set()) or (cancellation is not None and cancellation.exists())
        token, instance = secrets.token_hex(32), instance_id or secrets.token_hex(16)
        child = None
        reader = None
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
                    result['active_configuration'] = active_configuration(config, port)
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
            from . import diagnostics
            diagnostics.record('starting')
            child = subprocess.Popen(argv(config, port), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, env=clean_environment(),
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            job = WorkerJob(child.pid) if os.name == 'nt' else None
            reader = threading.Thread(target=diagnostics.drain, args=(child.stdout,), daemon=True)
            reader.start()
            deadline = time.monotonic() + config['startup_seconds']
            while not model_ready(port, config['model_path']):
                if cancelled(): return
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError('Local model did not become ready')
                time.sleep(.1)
            if cancelled(): return
            reported_models = model_identity(port)
            settings.write(root / 'runtime.json', dict(format=1, token=token, instance=instance,
                control_port=server.server_port, pid=child.pid, started=time.time(),
                active_configuration=active_configuration(config, port)))
            published = True
            diagnostics.record('ready')
            last_use = time.monotonic()
            while not stopping and child.poll() is None and not cancelled():
                now = time.monotonic()
                leases = {key: expiry for key, expiry in leases.items() if expiry > now}
                if not leases and now - last_use >= idle_seconds: break
                server.handle_request()
        finally:
            cleanup_failed = False
            for action in (server.server_close, lambda: job.close() if job else None,
                           lambda: child.terminate() if child and child.poll() is None else None,
                           lambda: child.wait(timeout=5) if child else None):
                try:
                    action()
                except Exception:
                    cleanup_failed = True
            if reader:
                reader.join(timeout=5)
                cleanup_failed = cleanup_failed or reader.is_alive()
            elif child and child.stdout:
                child.stdout.close()
            if cleanup_failed:
                raise CleanupError('CLEANUP_LIMITATION: session AI runtime cleanup could not be confirmed')
            from . import diagnostics
            try:
                if published and (state() or {}).get('instance') == instance:
                    local_path(root / 'runtime.json').unlink()
            except (OSError, ValueError):
                raise CleanupError('CLEANUP_LIMITATION: runtime state cleanup could not be confirmed') from None
            diagnostics.record('stopped' if published else 'failed')

"""Readiness levels use synthetic inputs and denied or mocked networking."""
import builtins
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import tomllib
from types import SimpleNamespace

import httpx
import pytest

from forensic_assistant.ai import readiness, settings, cli, connectivity
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.cli import build_parser


def config(provider='openai'):
    return {**settings.defaults(), 'provider': provider, 'model': 'unknown-future-model', 'cloud_acknowledged': True}


@pytest.fixture(autouse=True)
def isolation(monkeypatch, tmp_path):
    readiness.reset()
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
    monkeypatch.setenv('OPENAI_API_KEY', 'synthetic-private-key')
    def forbidden(*a, **kw):
        pytest.fail('network/model request forbidden')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(ModelBackend, '_cloud', forbidden)
    yield
    readiness.reset()


def test_standard_dependencies_and_branding():
    project = tomllib.loads(Path('pyproject.toml').read_text())['project']
    assert 'litellm==1.106.0' in project['dependencies']
    assert 'openai==2.53.0' in project['dependencies']
    assert 'jsonschema>=4.18,<5' in project['dependencies']
    assert project['optional-dependencies']['cloud'] == []
    assert not any(name in ' '.join(project['dependencies']) for name in ('torch', 'llama-cpp', 'sentence-transformers'))
    assert 'AI-Assisted Forensics' in project['description']
    banner = Path('forensic_assistant/resources/banner.txt').read_text(encoding='utf-8')
    assert 'AI-Assisted Forensics' in banner and 'Local AI-Assisted Forensics' not in banner


def test_quick_no_sdk_import_or_model_request(monkeypatch):
    import importlib.util
    monkeypatch.setattr(importlib.util, 'find_spec', lambda name: object())
    original = builtins.__import__
    def guarded(name, *a, **kw):
        assert name.split('.')[0] not in ('openai', 'litellm')
        return original(name, *a, **kw)
    monkeypatch.setattr(builtins, '__import__', guarded)
    started = time.perf_counter()
    value = readiness.check(config())
    elapsed = time.perf_counter()-started
    assert elapsed < 1.0  # Generous local-only regression ceiling, not a latency promise.
    assert value['provider_readiness'] == 'configured'
    assert value['connection_readiness'] == value['model_readiness'] == 'not checked'
    assert value['api_key'] == 'configured' and value['model'] == 'unknown-future-model'
    assert 'synthetic-private-key' not in json.dumps(value)
    assert readiness.status(config()) == {'provider_readiness': 'unchecked'}
    print('QUICK_SECONDS', elapsed)


def test_missing_key_and_bad_configuration(monkeypatch):
    monkeypatch.delenv('OPENAI_API_KEY')
    assert readiness.check(config())['api_key'] == 'not configured'
    for bad in ({}, None, {**config(), 'model': 'https://invalid'}, {**config(), 'provider': 'bad'}):
        result = readiness.check(bad)
        assert result['readiness_category'] == 'invalid_configuration'
        assert result['connection_readiness'] == 'not checked'


def test_default_cli_is_quick_and_full_requires_authorization(monkeypatch):
    settings.save(config())
    assert cli.dispatch(build_parser().parse_args(['ai', 'check']))['diagnostic_level'] == 'quick'
    assert cli.dispatch(build_parser().parse_args(['ai', 'status']))['diagnostic_level'] == 'quick'
    with pytest.raises(ValueError, match='authorization'):
        cli.dispatch(build_parser().parse_args(['ai', 'check', '--full', '--json']))
    with pytest.raises(ValueError, match='authorization'):
        readiness.full_diagnostic(config())
    seen = []
    monkeypatch.setattr(readiness, 'full_diagnostic', lambda c, **kw: seen.append(kw) or {})
    cli.dispatch(build_parser().parse_args(['ai', 'check', '--full', '--authorize-diagnostic', '--json']))
    assert seen == [dict(authorized=True, force=True)]


@pytest.mark.parametrize('code,expected', [(200, 'reachable/authenticated'), (401, 'authentication failure'), (403, 'access denied'), (429, 'rate limited'), (500, 'provider failure'), (302, 'request rejected')])
def test_non_generative_adapter(code, expected):
    seen = []
    def handle(request):
        seen.append(request)
        assert request.method == 'GET' and request.url.path == '/v1/models'
        assert not request.content and 'unknown-future-model' not in str(request.url)
        return httpx.Response(code)
    assert connectivity.probe('openai', 'synthetic', 1, transport=httpx.MockTransport(handle)) == expected
    assert len(seen) == 1


@pytest.mark.parametrize('error,expected', [(httpx.ConnectError, 'network failure'), (httpx.ReadTimeout, 'timeout')])
def test_connectivity_transport_failures(error, expected):
    def handle(request):
        raise error('secret must never be shown')
    assert connectivity.probe('openai', 'synthetic', 1, transport=httpx.MockTransport(handle)) == expected


@pytest.mark.parametrize('provider', ['local', 'anthropic', 'gemini', 'deepseek', 'xai'])
def test_unsupported_never_generates(provider, monkeypatch):
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **k: pytest.fail('worker started'))
    value = settings.defaults() if provider == 'local' else config(provider)
    result = connectivity.check(value)
    assert result['connection_readiness'] == 'not supported'
    assert result['model_readiness'] == 'not checked'


def test_parent_deadline_and_cleanup(monkeypatch):
    events = []
    class Process:
        pid = 123
        returncode = None
        def communicate(self, data, timeout):
            assert 0 < timeout <= 1
            assert 'synthetic-private-key' not in data.decode()
            events.append('attempt')
            raise subprocess.TimeoutExpired('mock', timeout)
        def poll(self): return self.returncode
        def kill(self): events.append('kill'); self.returncode = -1
        def wait(self, timeout): events.append('wait')
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **kw: Process())
    monkeypatch.setattr(connectivity, 'WorkerJob', lambda pid: SimpleNamespace(close=lambda: events.append('close')))
    result = connectivity.check(config(), timeout=1)
    assert result['connection_readiness'] == 'timeout'
    assert events.count('attempt') == 1 and events[-2:] == ['kill', 'wait']


def test_preparation_never_runs_diagnostic_and_handoff_remains_bound(monkeypatch):
    parent = ModelBackend(config=config())
    parent.prepare()
    worker = ModelBackend.restore(parent.descriptor())
    worker.prepare()
    changed = parent.descriptor()
    changed['config'] = {**changed['config'], 'model': 'different'}
    with pytest.raises(Exception):
        ModelBackend.restore(changed).prepare()


def test_connectivity_cancellation_closes_owned_worker(monkeypatch):
    events = []
    class Process:
        pid = 123
        returncode = None
        def communicate(self, *a, **kw): raise KeyboardInterrupt()
        def poll(self): return self.returncode
        def kill(self): events.append('kill'); self.returncode = -1
        def wait(self, timeout): events.append('wait')
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **kw: Process())
    monkeypatch.setattr(connectivity, 'WorkerJob', lambda pid: SimpleNamespace(close=lambda: events.append('close')))
    with pytest.raises(KeyboardInterrupt):
        connectivity.check(config())
    assert events[-2:] == ['kill', 'wait']


def test_import_and_version_without_sdk_or_credentials():
    code = '''
import builtins, os, socket
original = builtins.__import__
def guarded(name, *a, **kw):
    if name.split('.')[0] in ('openai','litellm'): raise AssertionError('SDK import')
    return original(name, *a, **kw)
def forbidden(*a, **kw): raise AssertionError('Network')
builtins.__import__ = guarded
socket.socket.connect = socket.create_connection = socket.getaddrinfo = forbidden
for name in list(os.environ):
    if name.endswith('_API_KEY'): del os.environ[name]
from forensic_assistant.cli import main
main(['--version'])
'''
    result = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert 'Locard' in result.stdout


def test_synthetic_before_after_measurement(monkeypatch):
    calls = []
    def complete(self, messages, schema, **kw):
        calls.append(messages)
        value = {'status': 'ok'} if schema == readiness.SCHEMA else json.loads(messages[0]['content'].split('format: ', 1)[1])
        return {'text': json.dumps(value)}
    monkeypatch.setattr(ModelBackend, '_cloud', complete)
    start = time.perf_counter()
    assert readiness.full_diagnostic(config(), authorized=True)['locard_compatibility'] == 'ready'
    full = time.perf_counter()-start
    assert len(calls) == 4
    calls.clear()
    start = time.perf_counter()
    result = readiness.check(config())
    quick = time.perf_counter()-start
    assert not calls and result['connection_readiness'] == 'not checked'
    print('SYNTHETIC_READINESS_MEASUREMENT', dict(previous_full_seconds=full, quick_seconds=quick,
                                               previous_requests=4, quick_requests=0))

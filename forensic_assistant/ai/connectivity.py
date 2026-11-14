"""Explicit, non-generative connectivity with a parent-enforced wall deadline."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from . import settings, runtime
from .capabilities import CONNECTIVITY_CHECKS
from forensic_assistant.investigation_ai.lifecycle import WorkerJob

TIMEOUT = 10
OUTCOMES = {'reachable/authenticated', 'authentication failure', 'access denied',
            'network failure', 'timeout', 'not supported', 'missing dependency',
            'rate limited', 'request rejected', 'provider failure'}


def probe(provider, key, timeout, *, transport=None):
    """Worker adapter; never sends a prompt, model request, or evidence."""
    if CONNECTIVITY_CHECKS.get(provider) != 'models_list':
        return 'not supported'
    import httpx
    try:
        # GET /v1/models tests credentials/reachability, not model capability.
        # Do not download or expose the model inventory; only inspect status.
        with httpx.Client(timeout=httpx.Timeout(timeout, connect=min(3, timeout)),
                          follow_redirects=False, trust_env=False, transport=transport) as client:
            with client.stream('GET', 'https://api.openai.com/v1/models',
                               headers={'Authorization': 'Bearer '+key}) as response:
                code = response.status_code
                if code == 200:
                    return 'reachable/authenticated'
                if code == 401:
                    return 'authentication failure'
                if code == 403:
                    return 'access denied'
                if code == 429:
                    return 'rate limited'
                return 'provider failure' if code >= 500 else 'request rejected'
    except httpx.TimeoutException:
        return 'timeout'
    except httpx.HTTPError:
        return 'network failure'


def check(config, *, timeout=TIMEOUT):
    config = settings.validate(config)
    if type(timeout) not in (int, float) or not 0 < timeout <= TIMEOUT:
        raise ValueError('Connectivity timeout must be within 10 seconds')
    provider = config['provider']
    base = dict(diagnostic_level='connectivity', provider=settings.PROVIDERS[provider][0],
                model=config['model'], model_readiness='not checked', locard_compatibility='not checked')
    if provider not in CONNECTIVITY_CHECKS:
        return dict(base, connection_readiness='not supported', provider_readiness='not checked')
    try:
        key = settings.key(provider)
    except ValueError:
        return dict(base, connection_readiness='not checked', provider_readiness='not configured', api_key='not configured')
    env = runtime.clean_environment()
    env[settings.PROVIDERS[provider][1]] = key
    started = time.monotonic()
    process = subprocess.Popen([sys.executable, '-B', '-m', __name__],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        cwd=str(Path(__file__).resolve().parents[2]), env=env,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    job = None
    outcome = 'network failure'
    try:
        job = WorkerJob(process.pid) if os.name == 'nt' else None
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise subprocess.TimeoutExpired('connectivity', timeout)
        raw, _ = process.communicate(json.dumps({'provider': provider, 'timeout': remaining}).encode(), timeout=remaining)
        if process.returncode == 0 and len(raw) <= 128:
            value = json.loads(raw)
            if value in OUTCOMES:
                outcome = value
    except subprocess.TimeoutExpired:
        outcome = 'timeout'
    except (ValueError, TypeError):
        outcome = 'network failure'
    finally:
        try:
            if job:
                job.close()
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
    return dict(base, connection_readiness=outcome, provider_readiness=outcome)


def main():
    try:
        request = json.loads(sys.stdin.buffer.read(4097))
        provider = request['provider']
        timeout = request['timeout']
        if provider not in CONNECTIVITY_CHECKS or type(timeout) not in (int, float) or not 0 < timeout <= TIMEOUT:
            raise ValueError()
        outcome = probe(provider, settings.key(provider), timeout)
    except ImportError:
        outcome = 'missing dependency'
    except Exception:
        outcome = 'network failure'
    print(json.dumps(outcome), flush=True)


if __name__ == '__main__':
    main()

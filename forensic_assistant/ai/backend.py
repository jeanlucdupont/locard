"""Inference selection only: callers retain retrieval, approval and validation."""
from contextvars import ContextVar
from contextlib import contextmanager
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import settings, runtime
from forensic_assistant.llm.client import LocalClient, LLMError
from forensic_assistant.investigation_ai.lifecycle import WorkerJob


STATUS = ContextVar('ai_status', default=None)
RESTART = ContextVar('ai_restart_confirmation', default=None)


@contextmanager
def restart_confirmation(read, indicator=None):
    def confirm():
        if indicator:
            indicator.stop()
        print('Local AI configuration changed.')
        return read('Restart the managed AI runtime now? [Y/n]: ').strip().lower() in ('', 'y', 'yes')
    token = RESTART.set(confirm if callable(read) else None)
    try:
        yield
    finally:
        RESTART.reset(token)

@contextmanager
def status_callback(callback):
    token = STATUS.set(callback)
    try:
        yield
    finally:
        STATUS.reset(token)


def waiting_label():
    name = settings.PROVIDERS[settings.load()['provider']][0]
    return 'Waiting for ' + ('local AI' if name == 'Local' else name) + '...'


def redact(text):
    for _, variable in settings.PROVIDERS.values():
        secret = os.environ.get(variable, '') if variable else ''
        if secret:
            text = text.replace(secret, '[REDACTED]')
    return text


class ModelBackend:
    def __init__(self, endpoint=None, timeout=120, *, config=None):
        if not 0 < timeout <= 600:
            raise ValueError('Timeout must be 1..600 seconds')
        self.config = settings.validate(config) if config is not None else settings.load()
        self.endpoint = endpoint
        if endpoint:
            from forensic_assistant.llm.client import endpoint_parts
            endpoint_parts(endpoint)
        self.timeout = timeout
        self.provider_name = 'local' if endpoint else self.config['provider']
        self.model_name = Path(self.config['model_path']).name if self.provider_name == 'local' else self.config['model']
        self.last_metadata = {}
        self.managed = None

    def identify(self):
        return dict(provider=self.provider_name, model=redact(self.model_name),
                    mode='local' if self.provider_name == 'local' else 'cloud',
                    identity_basis='Configured model; weights/provider execution not attested')

    def health(self):
        if self.provider_name == 'local':
            return runtime.status() if not self.endpoint else {'runtime': 'external endpoint', 'owned': False}
        return {'key_available': bool(os.environ.get(settings.PROVIDERS[self.provider_name][1]))}

    def supports_structured_output(self):
        # Model support is checked by the provider on each call; never drop schema.
        return 'required; provider/model must accept schema or request fails'

    def prepare(self, phase=None):
        if self.provider_name == 'local' and not self.endpoint:
            startup = {**self.config, 'startup_seconds': min(self.config['startup_seconds'], max(1, int(self.timeout)))}
            self.endpoint, self.managed = runtime.acquire(startup, phase, RESTART.get())
        elif self.provider_name != 'local':
            try:
                settings.key(self.provider_name)
            except ValueError:
                from .provider_diagnostics import record
                record(self.provider_name, self.model_name, 'configuration', 'missing_key')
                raise
        return self

    def descriptor(self):
        return dict(config=self.config, endpoint=self.endpoint, managed=self.managed,
                    provider=self.provider_name)

    @classmethod
    def restore(cls, value):
        result = cls(endpoint=value['endpoint'], timeout=120, config=value['config'])
        result.provider_name = value['provider']
        result.endpoint = value['endpoint']
        result.managed = value['managed']
        return result

    def complete(self, messages, schema=None):
        # Existing callers enforce narrower question/evidence bounds. This ceiling
        # also bounds IPC and rejects accidentally passing database-sized payloads.
        payload = json.dumps({'messages': messages, 'schema': schema}, ensure_ascii=True).encode()
        if len(payload) > 512 * 1024:
            raise LLMError('Model request exceeds the disclosure size limit')
        started = time.monotonic()
        self.prepare(STATUS.get())
        remaining = self.timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise LLMError('Model request timed out during startup')
        if STATUS.get():
            STATUS.get()("Waiting for " + ("local AI" if self.provider_name == "local" else settings.PROVIDERS[self.provider_name][0]) + "...")
        lease = None
        success = False
        try:
            if self.managed:
                lease = runtime.request(self.managed, 'begin', seconds=remaining)['lease']
            if self.provider_name == 'local':
                client = LocalClient(self.endpoint, remaining)
                text = client.complete(messages, schema)
                usage = client.last_metadata.get('usage', {})
            else:
                result = self._cloud(messages, schema, timeout=remaining)
                text, usage = result['text'], result['usage']
            self.last_metadata = {**self.identify(), 'usage': usage,
                                  'elapsed_seconds': round(time.monotonic() - started, 6)}
            success = True
            return redact(text)
        finally:
            if lease:
                try:
                    runtime.request(self.managed, 'end', lease=lease, success=success)
                except (OSError, ValueError):
                    # Lease expiry bounds orphaned clients, without stopping others.
                    pass

    def _cloud(self, messages, schema, *, timeout=None, handshake=False):
        from .provider_diagnostics import ProviderFailure, record
        started = time.monotonic()
        try:
            return self._cloud_request(messages, schema, timeout=timeout, handshake=handshake)
        except ProviderFailure as exc:
            record(self.provider_name, self.model_name, exc.stage, exc.category, time.monotonic()-started)
            raise
        except (OSError, ValueError):
            record(self.provider_name, self.model_name, 'provider_request', 'provider_failure', time.monotonic()-started)
            raise ProviderFailure('provider_failure') from None

    def _cloud_request(self, messages, schema, *, timeout=None, handshake=False):
        from .provider_diagnostics import ProviderFailure, REASONS, STAGES
        timeout = self.timeout if timeout is None else timeout
        from importlib.util import find_spec
        if find_spec('litellm') is None:
            raise ProviderFailure('missing_dependency', 'configuration')
        variable = settings.PROVIDERS[self.provider_name][1]
        env = runtime.clean_environment()
        env[variable] = settings.key(self.provider_name)
        env.update(LITELLM_LOCAL_MODEL_COST_MAP='True', LITELLM_TELEMETRY='False', DO_NOT_TRACK='1')
        request = dict(provider=self.provider_name, model=self.model_name, messages=messages,
                       schema=schema, timeout=timeout, handshake=handshake)
        process = subprocess.Popen([sys.executable, '-B', '-m', 'forensic_assistant.ai.cloud_worker'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
            cwd=str(Path(__file__).resolve().parents[2]),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        job = None
        try:
            job = WorkerJob(process.pid) if os.name == 'nt' else None
            output, _ = process.communicate(json.dumps(request).encode(), timeout=timeout)
            if process.returncode:
                raise ProviderFailure('provider_failure')
            if len(output) > 2 * 1024 * 1024:
                raise ValueError()
            result = json.loads(output)
            if type(result) is dict and set(result) == {'error', 'stage'}:
                raise ProviderFailure(result['error'] if result['error'] in REASONS else 'provider_failure',
                                      result['stage'] if result['stage'] in STAGES else 'provider_request')
            if set(result) != {'text', 'usage'}:
                raise ValueError()
            return result
        except subprocess.TimeoutExpired:
            raise ProviderFailure('timeout', 'timeout') from None
        except (ValueError, KeyError, TypeError):
            raise ProviderFailure('response_parse', 'response_parse') from None
        finally:
            if job: job.close()
            if process.poll() is None: process.kill()
            process.wait(timeout=5)


def backend(endpoint=None, timeout=120):
    return ModelBackend(endpoint, timeout)

"""Allowlisted cloud diagnostics. Never serialize provider exception text/payloads."""
import json
import os
import re
import time
from . import settings, diagnostics
from forensic_assistant.llm.client import LLMError

REASONS = {
    'ready': 'Synthetic response check passed',
    'missing_key': 'Required API key is missing',
    'missing_dependency': 'Optional cloud dependencies are not installed; use pip install "locard-forensics[cloud]"',
    'authentication': 'Authentication was not accepted by the provider',
    'permission': 'Provider permission was denied',
    'model_rejected': 'Model or requested endpoint was not accepted by the provider',
    'network': 'Connection failed',
    'timeout': 'Provider request timed out',
    'rate_limit': 'Provider rate limit reached',
    'provider_failure': 'Provider request failed',
    'request_rejected': 'Provider rejected the request',
    'unsupported_schema': 'Provider rejected structured-output parameters',
    'response_parse': 'Expected JSON object was not returned',
    'structured_validation': 'Response did not match the required structured contract',
    'grounding': 'Locard evidence-grounding validation rejected the proposed conclusion',
    'cancelled': 'Readiness check cancelled',
}
STAGES = {'configuration', 'handshake', 'provider_request', 'response_parse',
          'structured_validation', 'grounding', 'timeout'}


class ProviderFailure(LLMError):
    def __init__(self, category, stage='provider_request'):
        self.category = category if category in REASONS else 'provider_failure'
        self.stage = stage if stage in STAGES else 'provider_request'
        super().__init__(REASONS[self.category] + '. See ai logs.')


def classify(exc):
    if isinstance(exc, ProviderFailure):
        return exc.category
    name = type(exc).__name__
    code = getattr(exc, 'status_code', None)
    if name in ('Timeout', 'TimeoutError', 'APITimeoutError') or isinstance(exc, TimeoutError): return 'timeout'
    if name == 'AuthenticationError' or code == 401: return 'authentication'
    if name == 'PermissionDeniedError' or code == 403: return 'permission'
    if name == 'NotFoundError' or code == 404: return 'model_rejected'
    if name == 'RateLimitError' or code == 429: return 'rate_limit'
    if name in ('APIConnectionError', 'ConnectionError'): return 'network'
    if name == 'UnsupportedParamsError': return 'unsupported_schema'
    if code == 400: return 'request_rejected'
    return 'provider_failure'


def record(provider, model, stage, category, elapsed=0, *, operation="request"):
    if provider not in settings.PROVIDERS or provider == 'local': return
    stage = stage if stage in STAGES else 'provider_request'
    category = category if category in REASONS else 'provider_failure'
    model = model if type(model) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}', model) else '[invalid model]'
    for _, variable in settings.PROVIDERS.values():
        secret = os.environ.get(variable, '') if variable else ''
        if secret: model = model.replace(secret, '[REDACTED]')
    value = dict(utc=time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                 provider=settings.PROVIDERS[provider][0], model=model, stage=stage,
                 category=category, reason=REASONS[category], retries=0,
                 operation="handshake" if operation == "handshake" else "request",
                 elapsed_seconds=round(max(0, min(float(elapsed), 3600)), 3))
    try:
        diagnostics.append('provider.log', json.dumps(value, ensure_ascii=True) + '\n')
    except (OSError, ValueError):
        # Diagnostic failure must not change forensic/audit decisions.
        pass


def validation(client, stage):
    record(getattr(client, 'provider_name', None), getattr(client, 'model_name', ''), stage, stage)

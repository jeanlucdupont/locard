"""Allowlisted cloud diagnostics. Never serialize provider exception text/payloads."""
import json
import math
import os
import re
import time
from . import settings, diagnostics
from forensic_assistant.llm.client import LLMError

REASONS = {
    'output_truncated': 'Model output was truncated before a complete structured response was produced',
    'response_validated': 'Provider response passed canonical structural validation; grounding is checked separately',
    'compatibility_failed': "AI provider is connected, but the selected model is not compatible with Locard's required response format",
    'ready': 'Synthetic response check passed',
    'missing_credential': 'Required API key is missing',
    'missing_dependency': 'Optional cloud dependencies are not installed; use pip install "locard-forensics[cloud]"',
    'authentication_failed': 'Authentication failed',
    'authorization_failed': 'Provider denied access',
    'model_rejected': 'The configured model was not accepted by the provider',
    'invalid_request': 'Provider rejected an invalid request',
    'network_error': 'Connection failed',
    'timeout': 'Provider request timed out',
    'rate_limited': 'Provider rate limit was reached',
    'quota_or_billing': 'Provider quota or billing limit was reached',
    'provider_unavailable': 'Provider is unavailable',
    'provider_server_error': 'Provider service error',
    'unknown_provider_error': 'Provider request failed; no specific safe metadata available',
    'request_rejected': 'Provider rejected the request',
    'structured_output_unsupported': 'Provider rejected the required structured-output mode',
    'unsupported_schema': 'Provider rejected structured-output parameters',
    'unsupported_parameter': 'Provider rejected unsupported request parameters',
    'response_parse_failed': 'Expected JSON object was not returned',
    'structured_validation_failed': 'Response did not match the required structured contract',
    'grounding': 'Locard evidence-grounding validation rejected the proposed conclusion',
    'cancelled': 'Readiness check cancelled',
}
# Accept older internal diagnostic names without changing caller validation behavior.
ALIASES = dict(missing_key='missing_credential', authentication='authentication_failed',
               permission='authorization_failed', network='network_error', rate_limit='rate_limited',
               provider_failure='unknown_provider_error', response_parse='response_parse_failed',
               structured_validation='structured_validation_failed')
STAGES = {'provider_generation', 'configuration', 'handshake', 'provider_request', 'response_parse',
          'structured_validation', 'grounding', 'timeout'}
CODES = {
    'invalid_api_key': 'authentication_failed', 'authentication_error': 'authentication_failed',
    'permission_denied': 'authorization_failed', 'permission_error': 'authorization_failed',
    'access_denied': 'authorization_failed', 'model_not_found': 'model_rejected',
    'invalid_model': 'model_rejected', 'model_not_available': 'model_rejected',
    'model_access_denied': 'model_rejected', 'insufficient_quota': 'quota_or_billing',
    'billing_hard_limit_reached': 'quota_or_billing', 'billing_not_active': 'quota_or_billing',
    'insufficient_balance': 'quota_or_billing', 'quota_exceeded': 'quota_or_billing',
    'rate_limit_exceeded': 'rate_limited', 'rate_limit_error': 'rate_limited',
    'unsupported_response_format': 'unsupported_schema', 'invalid_json_schema': 'unsupported_schema',
    'unsupported_parameter': 'unsupported_parameter', 'invalid_parameter': 'invalid_request',
    'invalid_request_error': 'invalid_request', 'invalid_request': 'invalid_request',
    'not_found_error': 'request_rejected', 'server_error': 'provider_server_error',
    'api_error': 'provider_server_error', 'overloaded_error': 'provider_unavailable',
    'service_unavailable': 'provider_unavailable',
}
CLASSES = frozenset(('AuthenticationError', 'PermissionDeniedError', 'NotFoundError',
    'BadRequestError', 'UnprocessableEntityError', 'RateLimitError', 'APIConnectionError',
    'ConnectionError', 'ConnectError', 'Timeout', 'TimeoutError', 'APITimeoutError',
    'UnsupportedParamsError', 'InternalServerError', 'ServiceUnavailableError',
    'APIError', 'APIStatusError', 'BudgetExceededError'))


PARAMETERS = frozenset(('response_format', 'response_format.type', 'response_format.json_schema',
    'json_schema', 'max_tokens', 'max_completion_tokens', 'temperature', 'tools', 'tool_choice',
    'stream', 'timeout', 'model', 'messages', 'api_base', 'base_url'))
FEATURE_FLAGS = ('json_schema', 'tools', 'tool_choice', 'streaming', 'timeout', 'temperature',
                 'custom_endpoint', 'extra_headers')


def safe_features(value):
    if type(value) is not dict: return {}
    result = {key:value[key] for key in FEATURE_FLAGS if type(value.get(key)) is bool}
    for key, choices in (('structured_output', ('json_schema', 'anthropic_schema', 'gemini_schema', 'json_object', 'text', 'unset')),
                         ('max_token_parameter', ('max_tokens', 'max_completion_tokens', 'unset')),
                         ('provider_route', tuple(settings.PROVIDERS)),
                         ('provider_prefix', tuple(settings.PROVIDERS))):
        item = value.get(key)
        if type(item) is str and item in choices: result[key] = item
    if value.get('structured_output_mechanism') == 'provider_native_schema':
        result['structured_output_mechanism'] = 'provider_native_schema'
        for key in ('response_format', 'output_schema'):
            if type(value.get(key)) is bool: result[key] = value[key]
    return result


def request_features(kwargs):
    """Actual Locard-to-LiteLLM argument features, never contents or arbitrary keys."""
    response = kwargs.get('response_format')
    response = response if type(response) is dict else {}
    model = kwargs.get('model', '')
    mode = 'anthropic_schema' if 'output_config' in kwargs else 'gemini_schema' if 'response_json_schema' in kwargs else response.get('type', 'unset')
    native = {'structured_output_mechanism':'provider_native_schema', 'response_format':'response_format' in kwargs, 'output_schema':'output_config' in kwargs} if kwargs.get('custom_llm_provider') == 'anthropic' else {}
    return safe_features(dict(**native, structured_output=mode,
        json_schema=mode in ('json_schema', 'anthropic_schema', 'gemini_schema'), tools=bool(kwargs.get('tools')),
        tool_choice='tool_choice' in kwargs, streaming=kwargs.get('stream') is True,
        timeout='timeout' in kwargs, temperature='temperature' in kwargs,
        custom_endpoint=any(key in kwargs for key in ('api_base', 'base_url')),
        extra_headers='extra_headers' in kwargs,
        max_token_parameter=next((key for key in ('max_tokens', 'max_completion_tokens') if key in kwargs), 'unset'),
        provider_route=kwargs.get('custom_llm_provider'),
        provider_prefix=model.split('/', 1)[0] if type(model) is str else None))


def category_name(value):
    value = ALIASES.get(value, value) if type(value) is str else None
    return value if value in REASONS else 'unknown_provider_error'


def safe_metadata(value):
    """Revalidate at worker IPC, storage and human-rendering boundaries."""
    if type(value) is not dict: return {}
    result = {}
    from .anthropic_diagnostics import FIELDS, LABELS, CODES as ANTHROPIC_CODES
    for key, allowed in (('anthropic_error_category', LABELS), ('anthropic_error_code', ANTHROPIC_CODES), ('anthropic_provider_detail', {'unavailable'}), ('anthropic_feature', {'structured_outputs'})):
        if type(value.get(key)) is str and value[key] in allowed: result[key] = value[key]
    field = value.get('anthropic_request_field')
    if type(field) is str and field in FIELDS: result['anthropic_request_field'] = field
    from .gemini_usage import safe as safe_usage
    usage = safe_usage(value.get('gemini_usage'))
    if usage: result['gemini_usage'] = usage
    if value.get('gemini_canonical_validation') == 'passed': result['gemini_canonical_validation'] = 'passed'
    from .gemini_adapter import safe as gemini_safe
    gemini = gemini_safe(value.get('gemini_response'))
    if gemini: result['gemini_response'] = gemini
    from .validation_diagnostics import safe
    detail = safe(value.get('validation_diagnostics'))
    if detail: result['validation_diagnostics'] = detail
    tokens = value.get('max_output_tokens')
    if type(tokens) is int and 1 <= tokens <= 1024: result['max_output_tokens'] = tokens
    code = value.get('http_status')
    if type(code) is int and 100 <= code <= 599: result['http_status'] = code
    for key in ('provider_code', 'provider_type'):
        item = value.get(key)
        if type(item) is str and len(item) <= 64 and item in CODES:
            result[key] = item
    parameter = value.get('rejected_parameter')
    if type(parameter) is str and parameter in PARAMETERS: result['rejected_parameter'] = parameter
    limit = value.get('timeout_limit_seconds')
    if type(limit) in (int, float) and 0 <= limit <= 45:
        result['timeout_limit_seconds'] = round(limit, 3)
    features = safe_features(value.get('request_features'))
    if features: result['request_features'] = features
    from .schema_diagnostics import safe_profile, RULES
    for field in ('schema_profile', 'provider_schema_profile'):
        profile = safe_profile(value.get(field))
        if profile: result[field] = profile
    if type(value.get('schema_rule')) is str and value['schema_rule'] in RULES:
        result['schema_rule'] = value['schema_rule']
    name = value.get('exception_class')
    if type(name) is str and name in CLASSES: result['exception_class'] = name
    if value.get('retry_after_present') is True: result['retry_after_present'] = True
    delay = value.get('retry_after_seconds')
    if type(delay) is int and 0 <= delay <= 86400: result['retry_after_seconds'] = delay
    # Even a known literal must not expose an environment credential value.
    secrets = [os.environ.get(variable, '') for _, variable in settings.PROVIDERS.values() if variable]
    return {key:item for key,item in result.items()
            if not any(secret and secret in str(item) for secret in secrets)}


class ProviderFailure(LLMError):
    def __init__(self, category, stage='provider_request', *, metadata=None):
        self.category = category_name(category)
        self.stage = stage if stage in STAGES else 'provider_request'
        self.metadata = safe_metadata(metadata)
        super().__init__(REASONS[self.category] + '. See ai logs.')


def error_metadata(exc):
    if isinstance(exc, ProviderFailure): return exc.metadata
    response = getattr(exc, 'response', None)
    status = getattr(exc, 'status_code', None)
    if type(status) is not int: status = getattr(response, 'status_code', None)
    value = {'http_status':status, 'exception_class':type(exc).__name__,
             'provider_code':getattr(exc, 'code', None), 'provider_type':getattr(exc, 'type', None), 'rejected_parameter':getattr(exc, 'param', None)}
    body = getattr(exc, 'body', None)
    if type(body) is not dict:
        # Read only an already-buffered, bounded response. Never call network/read methods.
        try:
            raw = getattr(response, 'content', None)
            body = json.loads(raw) if type(raw) is bytes and len(raw) <= 16384 else None
        except (ValueError, UnicodeError, RecursionError, RuntimeError):
            body = None
    if type(body) is dict:
        error = body.get('error', body)
        if type(error) is dict:
            from .schema_diagnostics import rule
            value['schema_rule'] = rule(error.get('message'))
            if value['rejected_parameter'] is None: value['rejected_parameter'] = error.get('param')
            for field in ('code', 'type'):
                if value['provider_'+field] is None: value['provider_'+field] = error.get(field)
    headers = getattr(response, 'headers', None)
    if headers is not None:
        try:
            delay = headers.get('retry-after')
            if delay is None: delay = headers.get('Retry-After')
            if delay is not None:
                value['retry_after_present'] = True
                if type(delay) is str and re.fullmatch(r'[0-9]{1,5}', delay):
                    value['retry_after_seconds'] = int(delay)
        except (AttributeError, TypeError, ValueError): pass
    return safe_metadata(value)


def classify(exc):
    if isinstance(exc, ProviderFailure): return exc.category
    info = error_metadata(exc)
    status, name = info.get('http_status'), info.get('exception_class')
    if status == 401 or name == 'AuthenticationError': return 'authentication_failed'
    if status is not None and status >= 500: return 'provider_server_error'
    specific = CODES.get(info.get('provider_code'))
    if (specific in ('unsupported_parameter', 'unsupported_schema') or name == 'UnsupportedParamsError') and info.get('rejected_parameter') in ('response_format', 'response_format.type', 'response_format.json_schema', 'json_schema'):
        return 'structured_output_unsupported'
    if specific: return specific
    if status == 403 or name == 'PermissionDeniedError': return 'authorization_failed'
    specific = CODES.get(info.get('provider_type'))
    if specific and specific not in ('invalid_request', 'request_rejected'): return specific
    if status == 429 or name == 'RateLimitError': return 'rate_limited'
    if specific: return specific
    if name == 'BudgetExceededError': return 'quota_or_billing'
    if name in ('Timeout', 'TimeoutError', 'APITimeoutError') or isinstance(exc, TimeoutError): return 'timeout'
    if name in ('APIConnectionError', 'ConnectionError', 'ConnectError'): return 'network_error'
    if name == 'UnsupportedParamsError': return 'unsupported_parameter'
    if name == 'ServiceUnavailableError': return 'provider_unavailable'
    if name == 'InternalServerError': return 'provider_server_error'
    # A bare 404/NotFoundError cannot distinguish a model from an endpoint.
    if status is not None and 400 <= status < 500: return 'request_rejected'
    if name in ('BadRequestError', 'NotFoundError', 'UnprocessableEntityError'): return 'request_rejected'
    return 'unknown_provider_error'


def record(provider, model, stage, category, elapsed=0, *, operation="request", metadata=None, usage=None):
    if provider not in settings.PROVIDERS or provider == 'local': return
    stage = stage if stage in STAGES else 'provider_request'
    category = category_name(category)
    model = model if type(model) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}', model) else '[invalid model]'
    for _, variable in settings.PROVIDERS.values():
        secret = os.environ.get(variable, '') if variable else ''
        if secret: model = model.replace(secret, '[REDACTED]')
    value = dict(utc=time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                 provider=settings.PROVIDERS[provider][0], model=model, stage=stage,
                 category=category, reason=REASONS[category], retries=0,
                 operation=operation if operation in ("handshake", "investigation", "advisory") else "request",
                 status="success" if category in ("ready", "response_validated") else "failure",
                 elapsed_seconds=round(max(0, min(float(elapsed), 3600)), 3))
    value.update(safe_metadata(metadata))
    if type(usage) is dict:
        value['usage'] = {key: usage[key] for key in ('prompt_tokens', 'completion_tokens', 'total_tokens')
                          if type(usage.get(key)) is int and 0 <= usage[key] <= 10000000}
    try:
        diagnostics.append('provider.log', json.dumps(value, ensure_ascii=True) + '\n')
    except (OSError, ValueError):
        # Diagnostic failure must not change forensic/audit decisions.
        pass


def validation(client, stage):
    record(getattr(client, 'provider_name', None), getattr(client, 'model_name', ''), stage, stage)


def render(text):
    """Human projection of structured logs, including older category names."""
    from .backend import redact
    from forensic_assistant.retrieval.presentation import safe_text
    rows = []
    for line in text.splitlines():
        try: value = json.loads(line)
        except (ValueError, RecursionError): continue  # Rotation may cut the first line.
        if type(value) is not dict: continue
        category = category_name(value.get('category'))
        stamp = value.get('utc', '')
        if type(stamp) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC', stamp): stamp = 'Time unavailable'
        provider = value.get('provider')
        if provider not in [item[0] for item in settings.PROVIDERS.values()]: provider = 'Provider'
        model = value.get('model')
        if type(model) is not str or len(model) > 200: model = '[unavailable]'
        rows.append(stamp + ' — ' + provider)
        rows.append('  Model: ' + safe_text(redact(model)))
        rows.append('  Operation: ' + (value['operation'] if value.get('operation') in ('handshake', 'investigation', 'advisory') else 'request'))
        rows.append('  Status: ' + ('success' if category in ('ready', 'response_validated') else 'failure'))
        elapsed = value.get('elapsed_seconds')
        if type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 3600:
            rows.append('  Elapsed: ' + str(round(elapsed, 3)) + ' s')
        rows.append('  Stage: ' + (value['stage'] if type(value.get('stage')) is str and value['stage'] in STAGES else 'provider_request'))
        labels = {'anthropic_feature':'Provider feature', 'anthropic_error_category':'Provider error category', 'anthropic_error_code':'Provider error code', 'anthropic_provider_detail':'Provider detail', 'anthropic_request_field':'Request field', 'max_output_tokens':'Max output tokens', 'rejected_parameter':'Rejected parameter', 'http_status':'HTTP status', 'provider_code':'Provider code', 'provider_type':'Provider type',
                  'timeout_limit_seconds':'Timeout limit (seconds)', 'schema_rule':'Schema rule', 'exception_class':'Exception class', 'retry_after_present':'Retry-after present', 'retry_after_seconds':'Retry-after seconds'}
        for key, item in safe_metadata(value).items():
            if key == 'gemini_usage':
                rows.append('  Token usage:')
                for field, count in item.items(): rows.append('    ' + field.replace('_',' ').capitalize() + ': ' + str(count))
            elif key == 'gemini_canonical_validation':
                rows.append('  Canonical validation: passed')
            elif key == 'gemini_response':
                rows.append('  Gemini response diagnostics:')
                for field, state in item.items(): rows.append('    ' + field.replace('_',' ').capitalize() + ': ' + str(state))
            elif key == 'validation_diagnostics':
                rows.append('  Structural validation diagnostics:')
                for field in ('provider_structured_validation','translation_status','translation_rule','canonical_validation','phase','error_count'):
                    if field in item: rows.append('    ' + field.replace('_',' ').capitalize() + ': ' + str(item[field]))
                for error in item.get('errors',[]):
                    rows.append('    Rule: ' + error['validator_keyword'] + ' | Path: ' + error['canonical_path'])
            elif key in ('schema_profile', 'provider_schema_profile'):
                rows.append('  ' + ('Schema profile:' if key == 'schema_profile' else 'Provider schema profile:'))
                for feature, state in item.items(): rows.append('    ' + feature + ': ' + str(state))
            elif key == 'request_features':
                if 'structured_output' in item:
                    rows.append('  Structured mode: ' + item['structured_output'])
                rows.append('  Request features:')
                for feature, state in item.items(): rows.append('    ' + feature + ': ' + str(state).lower())
            elif key == 'anthropic_provider_detail':
                rows.append('  No safe field-level metadata available from LiteLLM/Anthropic response.')
            else: rows.append('  ' + labels[key] + ': ' + str(item))
        rows.extend(('  Category: ' + category, '  Reason: ' + REASONS[category], ''))
    return '\n'.join(rows).rstrip() if rows else 'No cloud provider diagnostics are available.'

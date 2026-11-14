"""Local-only default readiness and explicitly authorized synthetic diagnostics."""
import hashlib
import json
import os
import time
from . import settings
from .provider_diagnostics import ProviderFailure, REASONS, record

TIMEOUT = 15
STRUCTURED_TIMEOUT = 45
MESSAGES = [{'role':'user', 'content':'Return only this JSON object: {"status":"ok"}'}]
SCHEMA = {'type':'object', 'properties':{'status':{'type':'string', 'enum':['ok']}},
          'required':['status'], 'additionalProperties':False}
COMPAT_MESSAGES = [{'role': 'user', 'content': 'Return only this JSON object: {"status":"ok","message":"locard"}'}]
COMPAT_SCHEMA = {'type': 'object', 'properties': {
    'status': {'type': 'string', 'enum': ['ok']},
    'message': {'type': 'string', 'enum': ['locard']}},
    'required': ['status', 'message'], 'additionalProperties': False}
def openai_probes():
    from forensic_assistant.interactive.advisory import SCHEMA as advisory_schema
    from forensic_assistant.investigation_ai.contracts import schema, TOOLS
    grammar = schema(list(TOOLS))
    advisory = {'goal': None, 'assessment': ['Synthetic compatibility check.'], 'steps': [], 'cautions': []}
    tool = {'action': 'tool', 'tool': 'show_evidence', 'arguments': {
        'evidence_id': 'EVTX:' + 'a'*64 + ':Offset:1'}, 'reason': 'Synthetic compatibility check'}
    final = {'action': 'final', 'answer': {'observed': [], 'relationships': [],
             'detections': [], 'hypotheses': [], 'unknowns': [],
             'interpretations': [], 'answer_status': 'unresolved'}}
    for family, contract, expected in (('advisory', advisory_schema, advisory),
                                       ('investigation', grammar, tool), ('investigation', grammar, final)):
        yield family, contract, expected, [{'role': 'user', 'content':
            'Synthetic compatibility check; no case data or tools may be accessed. '
            'Return this proposal using the required transport format: ' + json.dumps(expected)}]


_cache = {}
_credentials = {}
COMPATIBILITY_REVISION = 1


def check(config, **_unused):
    """Quick: local configuration only; neither import an SDK nor probe a model."""
    from importlib.util import find_spec
    result = dict(diagnostic_level='quick', connection_readiness='not checked',
                  model_readiness='not checked', locard_compatibility='not checked')
    try:
        value = settings.validate(config)
    except (ValueError, TypeError, KeyError):
        return dict(result, provider='Unknown', model='not checked', api_key='not configured',
                    provider_readiness='not configured', configuration='configured_invalid',
                    readiness_category='invalid_configuration')
    provider = value['provider']
    variable = settings.PROVIDERS[provider][1]
    key = bool(os.environ.get(variable, '').strip()) if variable else None
    # Top-level module discovery does not execute the SDK or its dependencies.
    try:
        available = provider == 'local' or all(find_spec(name) is not None for name in ('litellm', 'openai', 'jsonschema'))
    except (ImportError, ValueError):
        available = False
    configured = bool(value['executable'] and value['model_path']) if provider == 'local' else key
    state = 'configured' if configured and available else 'not configured'
    model = value['model'] if provider != 'local' else 'user-selected GGUF'
    for _, name in settings.PROVIDERS.values():
        secret = os.environ.get(name, '') if name else ''
        if secret:
            model = model.replace(secret, '[REDACTED]')
    return dict(result, provider=settings.PROVIDERS[provider][0], model=model,
                api_key='not applicable' if key is None else 'configured' if key else 'not configured',
                integration='available' if available else 'missing dependency', provider_readiness=state,
                configuration='configured_ready' if state == 'configured' else 'credential_missing' if key is False else 'not_configured',
                configuration_detail=('Set '+variable+' before using AI.') if key is False else '',
                readiness_category='configured' if state == 'configured' else 'missing_key' if key is False else 'missing_dependency' if not available else 'not_configured')


def present(config, args=None, *, force=False):
    from .cli import render
    print(render(check(config), args))


def reset():
    _cache.clear()
    _credentials.clear()


def cache_key(config):
    from dataclasses import asdict
    from forensic_assistant import __version__
    from .capabilities import CAPABILITIES
    from .openai_schema import request_schema
    contracts = [SCHEMA, COMPAT_SCHEMA] + [p[1] for p in openai_probes()]
    shape = [request_schema(config['provider'], schema) for schema in contracts]
    public = [config['provider'], config['model'], asdict(CAPABILITIES[config['provider']]),
              __version__, COMPATIBILITY_REVISION, contracts, shape]
    if config['provider'] == 'anthropic':
        from .anthropic_strategy import VERSION, wire_schemas
        from .openai_schema import investigation
        public.append([VERSION,[wire_schemas(s) for s in contracts if investigation(s)]])
    return hashlib.sha256(json.dumps(public,sort_keys=True).encode()).hexdigest()


def credential_identity(config):
    # Private process-local invalidation only; never serialized in a descriptor/key/log.
    variable = settings.PROVIDERS[config['provider']][1]
    return hashlib.sha256(os.environ.get(variable, '').encode()).digest()


def export(config):
    value = status(config)
    if value.get('locard_compatibility') != 'ready':
        if value.get('provider_readiness') != 'unchecked':
            return None
        return {'key': cache_key(config), 'configuration_only': True}
    return {'key': cache_key(config), 'ready': True}


def accept(config, decision):
    return (type(decision) is dict and set(decision) == {'key','ready'}
            and decision['ready'] is True and decision['key'] == cache_key(config)) or (
                type(decision) is dict and set(decision) == {'key', 'configuration_only'}
                and decision['configuration_only'] is True and decision['key'] == cache_key(config))


def status(config):
    if config['provider'] == 'local': return {}
    key = cache_key(config)
    if _credentials.get(key) != credential_identity(config): return {'provider_readiness':'unchecked'}
    return _cache.get(key, {'provider_readiness':'unchecked'})


def invalidate(config):
    _cache.pop(cache_key(config), None)


def full_diagnostic(config, *, authorized=False, force=False, timeout=None, progress=None):
    if authorized is not True:
        raise ValueError("Full diagnostic sends potentially billable synthetic requests; explicit authorization required")
    config = settings.validate(config)
    if config['provider'] == 'local':
        return dict(diagnostic_level='full', provider='Local', provider_readiness='not supported',
                    connection_readiness='not checked', model_readiness='not checked', locard_compatibility='not checked')
    key = cache_key(config)
    if not force and status(config).get('provider_readiness') != 'unchecked': return _cache[key]
    started = time.monotonic()
    category, stage = 'ready', 'handshake'
    connection = model = 'unverified'
    from .capabilities import CAPABILITIES
    mode = CAPABILITIES[config['provider']].mode
    metadata = {'request_features': {'structured_output': mode}}
    compatibility = 'not_verified'
    family = None
    phase_started = started
    families = {'advisory_compatibility': 'not_verified', 'investigation_compatibility': 'not_verified'} if config['provider'] in ('openai', 'gemini', 'anthropic') else {}
    try:
        if not os.environ.get(settings.PROVIDERS[config['provider']][1], '').strip():
            raise ProviderFailure('missing_key', 'configuration')
        from .backend import ModelBackend
        from .response_contract import validate
        client = ModelBackend(config=config, timeout=TIMEOUT)
        limit = min(TIMEOUT, timeout) if timeout is not None else TIMEOUT
        from .schema_diagnostics import profiles
        metadata.update(profiles(config['provider'], SCHEMA))
        metadata['timeout_limit_seconds'] = limit
        if progress: progress('Checking AI provider...')
        response = client._cloud(MESSAGES, SCHEMA, timeout=limit, handshake=True)
        if time.monotonic()-phase_started > limit: raise ProviderFailure('timeout', 'timeout')
        connection = model = 'ready'
        validate(response['text'], SCHEMA)
        compatibility = 'failed'
        probes = openai_probes() if config['provider'] in ('openai', 'gemini', 'anthropic') else [
            (None, COMPAT_SCHEMA, {'status': 'ok', 'message': 'locard'}, COMPAT_MESSAGES)]
        for family, contract, expected, messages in probes:
            if family:
                families[family+'_compatibility'] = 'unavailable'
            remaining = min(STRUCTURED_TIMEOUT, timeout - (time.monotonic() - started)) if timeout is not None else STRUCTURED_TIMEOUT
            phase_started = time.monotonic()
            metadata.update(profiles(config['provider'], contract))
            metadata['timeout_limit_seconds'] = max(0, remaining)
            if progress: progress('Checking ' + (family or 'structured') + ' compatibility...')
            if remaining <= 0:
                raise ProviderFailure('timeout', 'timeout')
            response = client._cloud(messages, contract, timeout=remaining, handshake=True)
            if time.monotonic()-phase_started > remaining: raise ProviderFailure('timeout', 'timeout')
            value = validate(response['text'], contract)
            if value != expected:
                raise ProviderFailure('structured_validation', 'structured_validation')
            if family == 'advisory':
                families['advisory_compatibility'] = 'ready'
        if families:
            families['investigation_compatibility'] = 'ready'
        compatibility = 'ready'
    except ProviderFailure as exc:
        category, stage = exc.category, exc.stage
        metadata.update(exc.metadata)
        if category == 'timeout':
            compatibility = 'not confirmed'
            if family: families[family+'_compatibility'] = 'not confirmed'
        elif category in ('invalid_request', 'structured_output_unsupported', 'structured_validation_failed', 'response_parse_failed'):
            compatibility = 'failed'
        else:
            compatibility = 'not_verified'
    except KeyboardInterrupt:
        category = 'cancelled'
    except (OSError, ValueError):
        category, stage = 'unknown_provider_error', 'provider_request'
    from .backend import redact
    result = dict(diagnostic_level='full', provider=settings.PROVIDERS[config['provider']][0], model=redact(config['model']),
                  provider_readiness='ready' if category == 'ready' else 'unavailable',
                  readiness_reason=('Compatibility check timed out' if category == 'timeout' else REASONS[category]), readiness_stage=stage, readiness_category=category, connection_readiness=connection, model_readiness=model,
                  locard_compatibility=compatibility, structured_mode=mode, **families)
    if "http_status" in metadata: result["http_status"] = metadata["http_status"]
    record(config['provider'], config['model'], stage, category, time.monotonic()-phase_started, operation="handshake", metadata=metadata)
    _cache.clear()  # Current configuration only; no cross-session/key history.
    _credentials.clear()
    _credentials[key] = credential_identity(config)
    _cache[key] = result
    return result


def present_full(config, args=None, *, authorized=False, force=False):
    from forensic_assistant.terminal import Palette, enabled
    from forensic_assistant.terminal_activity import ActivityIndicator
    from forensic_assistant.retrieval.presentation import safe_text
    from .backend import redact
    if config['provider'] == 'local': return
    palette = Palette(enabled(args))
    print(palette('heading', 'Checking AI provider...'))
    with ActivityIndicator('Checking AI provider...', args=args) as activity:
        result = full_diagnostic(config, authorized=authorized, force=force, progress=activity.update)
    ready = result['provider_readiness'] == 'ready'
    print('  Provider: ' + settings.PROVIDERS[config['provider']][0])
    print('  Model: ' + safe_text(redact(config['model'])))
    variable = settings.PROVIDERS[config['provider']][1]
    missing = not os.environ.get(variable, '').strip()
    print('  API key: ' + ('missing' if missing else 'available'))
    if config['provider'] in ('openai', 'gemini', 'anthropic'):
        print('  Advisory compatibility: ' + result['advisory_compatibility'])
        print('  Investigation compatibility: ' + result['investigation_compatibility'])
    if ready:
        print('  Connection: OK\n  Model: accepted\n  Response check: OK')
        print('  Locard compatibility: ready (synthetic contract checked)')
    else:
        if result['connection_readiness'] == 'ready':
            print('  Connection: OK\n  Model: accepted\n  Locard compatibility: ' + result['locard_compatibility'])
            if result['locard_compatibility'] == 'failed':
                print("  AI provider is connected, but the selected model is not compatible with Locard's required response format.")
        summary = {'model_rejected':'Model: rejected', 'authentication_failed':'Authentication: failed',
                   'authorization_failed':'Access: denied'}.get(result['readiness_category'], result['readiness_reason'] + '.')
        print(palette('warning', '  ' + summary))
        if missing: print('  Set ' + variable + ' and retry.')
    print(palette('success' if ready else 'warning', 'Synthetic readiness check passed.' if ready else ('AI compatibility was not fully confirmed. Deterministic commands remain available.' if result['readiness_category'] == 'timeout' else 'AI compatibility check failed; deterministic commands remain available.' if result['locard_compatibility'] == 'failed' else 'AI provider unavailable; deterministic commands remain available.')))

"""Session-only cloud readiness using a fixed, evidence-free synthetic request."""
import hashlib
import json
import os
import time
from . import settings
from .provider_diagnostics import ProviderFailure, REASONS, record

TIMEOUT = 15
MESSAGES = [{'role':'user', 'content':'Return only this JSON object: {"status":"ok"}'}]
SCHEMA = {'type':'object', 'properties':{'status':{'type':'string', 'enum':['ok']}},
          'required':['status'], 'additionalProperties':False}
_cache = {}


def reset():
    _cache.clear()


def cache_key(config):
    variable = settings.PROVIDERS[config['provider']][1]
    key = os.environ.get(variable, '') if variable else ''
    return config['provider'], config['model'], hashlib.sha256(key.encode()).digest()


def status(config):
    if config['provider'] == 'local': return {}
    return _cache.get(cache_key(config), {'provider_readiness':'unchecked'})


def check(config, *, force=False):
    if config['provider'] == 'local': return {}
    key = cache_key(config)
    if not force and key in _cache: return _cache[key]
    started = time.monotonic()
    category, stage = 'ready', 'handshake'
    try:
        if not os.environ.get(settings.PROVIDERS[config['provider']][1], '').strip():
            raise ProviderFailure('missing_key', 'configuration')
        from .backend import ModelBackend
        response = ModelBackend(config=config, timeout=TIMEOUT)._cloud(MESSAGES, SCHEMA, timeout=TIMEOUT, handshake=True)
        try:
            def pairs(items):
                result = {}
                for name, value in items:
                    if name in result: raise ValueError()
                    result[name] = value
                return result
            text = response['text']
            if not isinstance(text, str) or len(text.encode()) > 4096: raise ValueError()
            value = json.loads(text, object_pairs_hook=pairs)
        except (ValueError, TypeError, KeyError, RecursionError):
            raise ProviderFailure('response_parse', 'response_parse') from None
        if type(value) is not dict or value != {'status':'ok'}:
            raise ProviderFailure('structured_validation', 'structured_validation')
    except ProviderFailure as exc:
        category, stage = exc.category, exc.stage
    except KeyboardInterrupt:
        category = 'cancelled'
    except (OSError, ValueError):
        category, stage = 'provider_failure', 'provider_request'
    result = dict(provider_readiness='ready' if category == 'ready' else 'unavailable',
                  readiness_reason=REASONS[category], readiness_stage=stage)
    record(config['provider'], config['model'], stage, category, time.monotonic()-started, operation="handshake")
    _cache.clear()  # Current configuration only; no cross-session/key history.
    _cache[key] = result
    return result


def present(config, args=None, *, force=False):
    from forensic_assistant.terminal import Palette, enabled
    from forensic_assistant.terminal_activity import ActivityIndicator
    from forensic_assistant.retrieval.presentation import safe_text
    from .backend import redact
    if config['provider'] == 'local': return
    palette = Palette(enabled(args))
    print(palette('heading', 'Checking AI provider...'))
    with ActivityIndicator('Checking AI provider...', args=args):
        result = check(config, force=force)
    ready = result['provider_readiness'] == 'ready'
    print('  Provider: ' + settings.PROVIDERS[config['provider']][0])
    print('  Model: ' + safe_text(redact(config['model'])))
    variable = settings.PROVIDERS[config['provider']][1]
    missing = not os.environ.get(variable, '').strip()
    print('  API key: ' + ('missing' if missing else 'available'))
    if ready:
        print('  Connection: OK\n  Model: accepted\n  Response check: OK')
    else:
        print(palette('warning', '  ' + result['readiness_reason'] + '.'))
        if missing: print('  Set ' + variable + ' and retry.')
    print(palette('success' if ready else 'warning', 'AI ready.' if ready else 'AI provider unavailable; deterministic commands remain available.'))

"""Fixed briefing diagnostic labels; never expose exception messages or payloads."""
from forensic_assistant.ai.provider_diagnostics import safe_metadata

MESSAGES = {
    'provider_schema_rejection': 'provider rejected the response schema',
    'provider_transport': 'provider connection failed or timed out',
    'provider_authentication': 'provider authentication or authorization failed',
    'provider_rate_limit': 'provider rate limit reached',
    'provider_failure': 'provider request failed',
    'response_parsing': 'response could not be parsed safely',
    'structural_validation': 'response failed local structural validation',
    'reconciliation': 'response items failed briefing source validation',
    'internal_failure': 'an internal error prevented interpretation',
}


def fail(packet, category, stage, **details):
    packet['ai_status'] = 'failed'
    packet['ai_error'] = dict(category=category, stage=stage, **details)
    packet['limitations'].append('AI interpretation failed: '+MESSAGES[category]+'. Deterministic leads remain available.')


def provider_failure(packet, exc):
    metadata = safe_metadata(exc.metadata)
    category = exc.category
    if category in ('unsupported_schema', 'structured_output_unsupported') or metadata.get('schema_rule'):
        kind = 'provider_schema_rejection'
    elif category in ('timeout', 'network_error'):
        kind = 'provider_transport'
    elif category in ('authentication_failed', 'authorization_failed', 'missing_credential'):
        kind = 'provider_authentication'
    elif category == 'rate_limited':
        kind = 'provider_rate_limit'
    elif category == 'response_parse_failed':
        kind = 'response_parsing'
    elif category == 'structured_validation_failed':
        kind = 'structural_validation'
    else:
        kind = 'provider_failure'
    details = {'provider_category': category}
    for source, target in (('http_status','http_status'), ('rejected_parameter','parameter'),
                           ('schema_rule','rule'), ('validation_diagnostics','validation')):
        if source in metadata:
            details[target] = metadata[source]
    fail(packet, kind, exc.stage, **details)


def local_rule(exc, parsing=False):
    # Match application-generated messages only; return fixed labels, never text.
    if parsing:
        return {'Duplicate JSON key':'duplicate_json_key', 'Nonfinite JSON value':'nonfinite_json',
                'Model response exceeds content limit':'response_size_limit',
                'Malformed structured response':'invalid_json'}.get(str(exc), 'invalid_json')
    for suffix, rule in ((': wrong type','type'), (': missing parameter','required'),
                         (': unknown parameter','additionalProperties'), (': duplicate items','uniqueItems'),
                         (': invalid item count','array_bounds'), (': invalid string length/content','string_content'),
                         (': value outside bounds','numeric_bounds'), (': unsupported value','enum')):
        if str(exc).endswith(suffix):
            return rule
    return 'canonical_contract'

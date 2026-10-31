"""Payload-free diagnostics for the existing SDK response acceptance boundary."""
LIMIT = 1024 * 1024
RULES = frozenset(('output_truncated', 'unexpected_finish_reason', 'unexpected_tool_call',
    'missing_response_message', 'missing_response_content', 'empty_response_content',
    'invalid_content_type', 'response_size_exceeded', 'invalid_response_envelope'))


def safe(value):
    if type(value) is not dict:
        return {}
    result = {}
    for key, allowed in {
        'rule': RULES,
        'finish_reason': {'stop','end_turn','length','tool_calls','function_call','content_filter','other'},
        'content_type': {'string','null','array','object','boolean','number','other'},
        'json_parse': {'not_attempted'}, 'canonical_validation': {'not_attempted'},
    }.items():
        if type(value.get(key)) is str and value[key] in allowed:
            result[key] = value[key]
    for key in ('tool_calls_present','function_call_present','content_bytes_capped'):
        if type(value.get(key)) is bool:
            result[key] = value[key]
    from forensic_assistant.briefing import OPENAI_OUTPUT_TOKENS
    for key, maximum in (('content_bytes',LIMIT+1),('output_token_limit',OPENAI_OUTPUT_TOKENS)):
        if type(value.get(key)) is int and 0 <= value[key] <= maximum:
            result[key] = value[key]
    return result


def content(result, kwargs):
    from .provider_diagnostics import ProviderFailure
    detail = {'json_parse':'not_attempted', 'canonical_validation':'not_attempted'}
    if type(kwargs.get('max_tokens')) is int:
        detail['output_token_limit'] = kwargs['max_tokens']

    def reject(rule):
        raise ProviderFailure('output_truncated' if rule=='output_truncated' else 'response_envelope_failed',
                              'response_envelope', metadata={'response_envelope':safe({**detail,'rule':rule})})

    missing = object()
    try:
        choices = getattr(result,'choices',missing)
        if choices is missing or choices is None or choices == []:
            reject('missing_response_message')
        choice = choices[0]
        message = getattr(choice,'message',missing)
        if message is missing or message is None:
            reject('missing_response_message')
        finish = getattr(choice,'finish_reason',missing)
        detail['finish_reason'] = finish if type(finish) is str and finish in (
            'stop','end_turn','length','tool_calls','function_call','content_filter') else 'other'
        detail['tool_calls_present'] = bool(getattr(message,'tool_calls',None))
        detail['function_call_present'] = bool(getattr(message,'function_call',None))
        text = getattr(message,'content',missing)
        if text is not missing:
            detail['content_type'] = {str:'string',type(None):'null',list:'array',dict:'object',bool:'boolean',int:'number',float:'number'}.get(type(text),'other')
            if isinstance(text,str):
                size=len(text.encode())
                detail.update(content_bytes=min(size,LIMIT+1),content_bytes_capped=size>LIMIT+1)
        if finish == 'length':reject('output_truncated')
        if finish not in ('stop','end_turn'):reject('unexpected_finish_reason')
        if detail['tool_calls_present'] or detail['function_call_present']:reject('unexpected_tool_call')
        if text is missing:reject('missing_response_content')
        if not isinstance(text,str):reject('invalid_content_type')
        if not text.strip():reject('empty_response_content')
        if detail['content_bytes']>LIMIT:reject('response_size_exceeded')
        return text
    except ProviderFailure:
        raise
    except Exception:
        reject('invalid_response_envelope')

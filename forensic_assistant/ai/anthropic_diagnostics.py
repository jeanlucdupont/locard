"""Allowlisted Anthropic request-error metadata, never provider message text."""
import json
FIELDS = frozenset(('output_config','output_config.format','output_config.format.schema','output_format','output_format.schema','response_format','max_tokens','model','tools','tool_choice','messages','temperature'))
TYPES = frozenset(('invalid_request_error','authentication_error','permission_error','not_found_error','rate_limit_error','api_error','overloaded_error'))

def extract(exc):
    body = getattr(exc,'body',None)
    if not isinstance(body,(dict,str,bytes)):
        body = getattr(getattr(exc,'response',None),'content',None)
    if isinstance(body,(str,bytes)):
        if len(body)>16384:return {}
        try:body=json.loads(body)
        except (ValueError,UnicodeError,RecursionError):return {}
    if type(body) is not dict:return {}
    error=body.get('error',body)
    if type(error) is not dict:return {}
    result={}
    if type(error.get('type')) is str and error['type'] in TYPES:result['provider_type']=error['type']
    for key in ('param','parameter'):
        value=error.get(key)
        if type(value) is str and value in FIELDS:result['anthropic_request_field']=value
    message=error.get('message')
    if type(message) is str and len(message)<=16384:
        # Only an exact known field before a colon; never store arbitrary prose.
        field=message.partition(':')[0]
        if field in FIELDS:result['anthropic_request_field']=field
    return result

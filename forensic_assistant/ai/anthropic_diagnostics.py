"""Allowlisted Anthropic request-error metadata, never provider message text."""
import json
FIELDS = frozenset(('output_config','output_config.format','output_config.format.schema','output_format','output_format.schema','response_format','max_tokens','model','tools','tool_choice','messages','temperature','output_schema','system'))
TYPES = frozenset(('invalid_request_error','authentication_error','permission_error','not_found_error','rate_limit_error','api_error','overloaded_error'))

LABELS = frozenset(('unsupported_parameter','unknown_parameter','invalid_parameter','invalid_model','unsupported_model_feature','unsupported_schema','invalid_schema','missing_beta_requirement','malformed_request','unsupported_feature'))
CODES = LABELS | frozenset(('invalid_request_error','model_not_found','invalid_model','unsupported_parameter'))

def decode(value):
    if type(value) is dict: return value
    if type(value) not in (str,bytes) or len(value)>16384: return None
    try:
        result=json.loads(value)
        return result if type(result) is dict else None
    except (ValueError,UnicodeError,RecursionError): return None

def classify_message(message):
    if type(message) is not str or len(message)>16384: return {}
    result={}
    field,sep,detail=message.partition(':')
    if sep and field in FIELDS:
        result['anthropic_request_field']=field
        exact={'extra inputs are not permitted':'unknown_parameter',
               'unsupported parameter':'unsupported_parameter',
               'invalid schema':'invalid_schema',
               'unsupported schema':'unsupported_schema',
               'field required':'invalid_parameter'}
        label=exact.get(detail.strip().lower())
        if label: result['anthropic_error_category']=label
    # Fixed phrases only. Never copy a parameter or prose out of the message.
    for prefix,label in (('Unknown parameter: ','unknown_parameter'),
                         ('Unsupported parameter: ','unsupported_parameter'),
                         ('Invalid parameter: ','invalid_parameter')):
        if message.startswith(prefix) and message[len(prefix):] in FIELDS:
            result.update(anthropic_request_field=message[len(prefix):],anthropic_error_category=label)
    if message == 'This model does not support structured outputs.':
        result['anthropic_error_category']='unsupported_model_feature'
    if message == 'Structured outputs require the structured-outputs-2025-11-13 beta header.':
        result.update(anthropic_error_category='missing_beta_requirement', anthropic_feature='structured_outputs')
    return result

def extract(exc):
    body=decode(getattr(exc,'body',None))
    if body is None:
        nested=getattr(exc,'error',None)
        if type(nested) is dict:body={'error':nested}
    if body is None:
        try:body=decode(getattr(getattr(exc,'response',None),'content',None))
        except (RuntimeError,ValueError):body=None
    message=getattr(exc,'message',None)
    if type(message) is str and len(message)<=16384:
        for prefix in ('litellm.BadRequestError: AnthropicException - ',
                       'litellm.BadRequestError: AnthropicError - '):
            if message.startswith(prefix):
                message=message[len(prefix):]
                if body is None:body=decode(message)
                break
    error=body.get('error',body) if type(body) is dict else {}
    if type(error) is not dict:error={}
    result={}
    for name,allowed,target in (('type',TYPES,'provider_type'),('code',CODES,'anthropic_error_code')):
        value=error.get(name,getattr(exc,name,None))
        if type(value) is str and value in allowed:result[target]=value
    for key in ('param','parameter'):
        value=error.get(key,getattr(exc,key,None))
        if type(value) is str and value in FIELDS:result['anthropic_request_field']=value
    code=result.get('anthropic_error_code')
    if code in LABELS:result['anthropic_error_category']=code
    elif code == 'model_not_found':result['anthropic_error_category']='invalid_model'
    for key,value in classify_message(error.get('message',message)).items():
        result.setdefault(key,value)
    if not any(k in result for k in ('anthropic_error_code','anthropic_request_field','anthropic_error_category')):
        result['anthropic_provider_detail']='unavailable'
    return result

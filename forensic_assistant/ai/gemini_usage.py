"""Numeric-only projections of LiteLLM Gemini usage; never retain provider payloads."""
FIELDS = ('prompt_tokens', 'completion_tokens', 'total_tokens', 'reasoning_tokens', 'cached_tokens')

def safe(value):
    if type(value) is not dict: return {}
    return {k:v for k,v in value.items() if k in FIELDS and type(v) is int and 0 <= v <= 10000000}

def extract(result):
    usage = getattr(result, 'usage', None)
    values = {k:getattr(usage,k,None) for k in FIELDS[:3]}
    values['reasoning_tokens'] = getattr(getattr(usage,'completion_tokens_details',None),'reasoning_tokens',None)
    values['cached_tokens'] = getattr(getattr(usage,'prompt_tokens_details',None),'cached_tokens',None)
    return safe(values)

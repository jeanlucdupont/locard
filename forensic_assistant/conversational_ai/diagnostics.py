"""Allowlisted shape diagnostics, never request/response content."""
import json

def safe(value):
    if type(value) is not dict:return {}
    out={}
    for key, choices in {
        'location':('configuration','dispatch','sdk_import','transport','extraction','validation','diagnostic','cli'),
        'transport':('litellm_openai_native',),
        'finish_reason':('stop','tool_calls','length','content_filter','function_call','missing','other'),
        'exception_class':('ValueError','TypeError','AttributeError','KeyError','IndexError','RuntimeError','ImportError','ModuleNotFoundError','Other'),
    }.items():
        if type(value.get(key)) is str and value[key] in choices:out[key]=value[key]
    for key,limit in {'tool_count':64,'schema_bytes':131072,'output_tokens':4096,'timeout_seconds':900,'prompt_tokens':10000000,'completion_tokens':10000000,'total_tokens':10000000}.items():
        if type(value.get(key)) in (int,float) and 0<=value[key]<=limit:out[key]=value[key]
    if type(value.get('tool_choice')) is bool:out['tool_choice']=value['tool_choice']
    return out

def shape(tools,output_tokens,timeout):
    return safe(dict(transport='litellm_openai_native',tool_count=len(tools),
        schema_bytes=len(json.dumps(tools,ensure_ascii=True).encode()),tool_choice=True,
        output_tokens=output_tokens,timeout_seconds=timeout))

def detail(location,exc=None,finish=None):
    value={'location':location}
    if exc is not None:
        name=type(exc).__name__
        value['exception_class']=name if name in ('ValueError','TypeError','AttributeError','KeyError','IndexError','RuntimeError','ImportError','ModuleNotFoundError') else 'Other'
    if finish is not None:value['finish_reason']=finish if finish in ('stop','tool_calls','length','content_filter','function_call') else 'other'
    return safe(value)

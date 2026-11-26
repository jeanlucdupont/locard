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
    for key,limit in {'tool_count':128,'advertised_tool_count':128,'returned_tool_call_count':100000,'assistant_content_bytes':10000000,'argument_bytes':10000000,'continuation_bytes':10000000,'schema_bytes':131072,'output_tokens':65536,'timeout_seconds':900,'prompt_tokens':10000000,'completion_tokens':10000000,'total_tokens':10000000}.items():
        if type(value.get(key)) in (int,float) and 0<=value[key]<=limit:out[key]=value[key]
    if type(value.get('tool_choice')) is bool:out['tool_choice']=value['tool_choice']
    for key in ('continuation_present','reasoning_present','replay_present'):
        if type(value.get(key)) is bool:out[key]=value[key]
    if value.get('assistant_content_type') in ('str','NoneType','list','dict','int','bool','float','other'):out['assistant_content_type']=value['assistant_content_type']
    if value.get('failed_rule') in RULES:out['failed_rule']=value['failed_rule']
    return out

def shape(tools,output_tokens,timeout):
    return safe(dict(transport='litellm_openai_native',advertised_tool_count=len(tools),
        schema_bytes=len(json.dumps(tools,ensure_ascii=True).encode()),tool_choice=True,
        output_tokens=output_tokens,timeout_seconds=timeout))

def detail(location,exc=None,finish=None):
    value={'location':location}
    if exc is not None:
        value['failed_rule']=getattr(exc,'code',None)
        name=type(exc).__name__
        value['exception_class']=name if name in ('ValueError','TypeError','AttributeError','KeyError','IndexError','RuntimeError','ImportError','ModuleNotFoundError') else 'Other'
    if finish is not None:value['finish_reason']=finish if finish in ('stop','tool_calls','length','content_filter','function_call') else 'other'
    return safe(value)

# Closed diagnostic vocabulary: never accept arbitrary exception text.
RULES=set("RESPONSE_TYPE_INVALID RESPONSE_FIELDS_INVALID RESPONSE_SIZE_EXCEEDED ASSISTANT_CONTENT_INVALID TOOL_CALL_STRUCTURE_INVALID TOOL_CALL_COUNT_EXCEEDED TOOL_CALL_ID_INVALID TOOL_CALL_ID_DUPLICATE TOOL_CALL_NAME_INVALID TOOL_CALL_ARGUMENTS_INVALID FINISH_REASON_INVALID FINISH_REASON_TOOL_MISMATCH USAGE_INVALID COST_INVALID CONTINUATION_FORMAT_INVALID CONTINUATION_SIZE_EXCEEDED CONTINUATION_FIELDS_INVALID CONTINUATION_CONTENT_MISMATCH CONTINUATION_TOOL_BINDING_MISMATCH CONTINUATION_JSON_INVALID".split())

def response_shape(message,finish):
    content=getattr(message,'content',None);calls=getattr(message,'tool_calls',None)
    fields=getattr(message,'provider_specific_fields',None)
    reasoning=getattr(message,'reasoning_items',None)
    payload={k:getattr(message,k,None) for k in ('reasoning_items','provider_specific_fields','phase')}
    continuation_size=None
    if any(payload.values()):
        try:
            raw=message.model_dump()
            raw={k:v for k,v in raw.items() if k in ('role','content','tool_calls','reasoning_items','provider_specific_fields','phase')}
            raw['role']='assistant'
            continuation_size=len(json.dumps(raw,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode())
        except (AttributeError,TypeError,ValueError):pass
    return safe(dict(assistant_content_type=type(content).__name__ if type(content).__name__ in ('str','NoneType','list','dict','int','bool','float') else 'other',
        assistant_content_bytes=len(content.encode(errors='replace')) if type(content) is str else 0,
        returned_tool_call_count=len(calls) if isinstance(calls,(list,tuple)) else 0,
        argument_bytes=sum(len(a.encode(errors='replace')) for c in (calls if isinstance(calls,(list,tuple)) else []) if type(a:=getattr(getattr(c,'function',None),'arguments',None)) is str),
        continuation_present=bool(fields or reasoning or payload['phase']),continuation_bytes=continuation_size if any(payload.values()) else 0,
        reasoning_present=bool(reasoning),replay_present=isinstance(fields,dict) and 'openai_responses_replay' in fields))

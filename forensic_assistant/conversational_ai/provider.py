"""Provider-neutral completion result and OpenAI native tool-call extraction."""
import json
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from forensic_assistant.investigation_ai.contracts import loads


# Defensive message limits, not a session investigation policy.
MAX_CALLS=128
MAX_CONTENT=128*1024
MAX_CONTINUATION=256*1024
MAX_RESPONSE=512*1024

class ValidationError(ValueError):
    def __init__(self,code):
        self.code=code
        super().__init__(code)

def reject(code):raise ValidationError(code)

def byte_size(value,code):
    try:return len(value.encode('utf-8'))
    except UnicodeError:reject(code)

def validate(value):
    if type(value) is not dict:reject('RESPONSE_TYPE_INVALID')
    if set(value)-{'continuation'}!={'text','tool_calls','finish_reason','usage','cost'}:reject('RESPONSE_FIELDS_INVALID')
    if type(value['text']) is not str or byte_size(value['text'],'ASSISTANT_CONTENT_INVALID')>MAX_CONTENT:reject('ASSISTANT_CONTENT_INVALID')
    if type(value['tool_calls']) is not list:reject('TOOL_CALL_STRUCTURE_INVALID')
    if len(value['tool_calls'])>MAX_CALLS:reject('TOOL_CALL_COUNT_EXCEEDED')
    if value['finish_reason'] not in ('stop','tool_calls'):reject('FINISH_REASON_INVALID')
    ids=set()
    for call in value['tool_calls']:
        if type(call) is not dict or set(call)!={'id','name','arguments'}:reject('TOOL_CALL_STRUCTURE_INVALID')
        if type(call['id']) is not str or not 1<=byte_size(call['id'],'TOOL_CALL_ID_INVALID')<=128:reject('TOOL_CALL_ID_INVALID')
        if call['id'] in ids:reject('TOOL_CALL_ID_DUPLICATE')
        if type(call['name']) is not str or not 1<=byte_size(call['name'],'TOOL_CALL_NAME_INVALID')<=80:reject('TOOL_CALL_NAME_INVALID')
        if type(call['arguments']) is not dict:reject('TOOL_CALL_ARGUMENTS_INVALID')
        try:raw=json.dumps(call['arguments'],allow_nan=False).encode()
        except (ValueError,TypeError):reject('TOOL_CALL_ARGUMENTS_INVALID')
        if len(raw)>16384:reject('TOOL_CALL_ARGUMENTS_INVALID')
        ids.add(call['id'])
    if bool(ids)!=(value['finish_reason']=='tool_calls'):reject('FINISH_REASON_TOOL_MISMATCH')
    if type(value['usage']) is not dict or set(value['usage'])-{'prompt_tokens','completion_tokens','total_tokens'} or any(type(v) is not int or not 0<=v<=10000000 for v in value['usage'].values()):reject('USAGE_INVALID')
    if value['cost'] is not None:reject('COST_INVALID')
    if 'continuation' in value:restore(assistant_message(value))
    if len(json.dumps(value,ensure_ascii=True).encode())>MAX_RESPONSE:reject('RESPONSE_SIZE_EXCEEDED')
    return value


def assistant_message(value):
    """Provider-neutral history: opaque continuation is never evidence."""
    message=dict(role='assistant',content=value['text'])
    if value['tool_calls']:
        message['tool_calls']=[dict(id=c['id'],type='function',function=dict(name=c['name'],arguments=json.dumps(c['arguments'],ensure_ascii=True,separators=(',',':')))) for c in value['tool_calls']]
    if 'continuation' in value:message['provider_continuation']=value['continuation']
    return message


def restore(message):
    """Bind retained transport history to the visible assistant/tool exchange."""
    if 'provider_continuation' not in message:return message
    state=message['provider_continuation']
    if type(state) is not dict or set(state)!={'format','payload'} or state['format']!='litellm-openai-history-v1':reject('CONTINUATION_FORMAT_INVALID')
    if type(state['payload']) is not str:reject('CONTINUATION_FORMAT_INVALID')
    if byte_size(state['payload'],'CONTINUATION_JSON_INVALID')>MAX_CONTINUATION:reject('CONTINUATION_SIZE_EXCEEDED')
    try:raw=loads(state['payload'],max_bytes=MAX_CONTINUATION)
    except (ValueError,TypeError):reject('CONTINUATION_JSON_INVALID')
    if type(raw) is not dict or raw.get('role')!='assistant' or set(raw)-{'role','content','tool_calls','reasoning_items','provider_specific_fields','phase'}:reject('CONTINUATION_FIELDS_INVALID')
    if raw.get('content') is not None and type(raw.get('content')) is not str:reject('CONTINUATION_FIELDS_INVALID')
    if (raw.get('content') or '')!=(message.get('content') or ''):reject('CONTINUATION_CONTENT_MISMATCH')
    def calls(items):
        if items is None:return []
        if type(items) is not list:reject('CONTINUATION_FIELDS_INVALID')
        return [(c['id'],c['type'],c['function']['name'],loads(c['function']['arguments'],max_bytes=16384)) for c in items]
    try:
        if calls(raw.get('tool_calls'))!=calls(message.get('tool_calls')):reject('CONTINUATION_TOOL_BINDING_MISMATCH')
    except ValidationError:raise
    except (KeyError,TypeError,ValueError):reject('CONTINUATION_FIELDS_INVALID')
    return raw


def generate(request,sdk):
    from forensic_assistant.ai.settings import key
    from forensic_assistant.ai.provider_diagnostics import classify,error_metadata
    from .diagnostics import detail
    location='configuration';finish=None;response_shape={}
    try:
        if request['provider']!='openai':raise ValueError('Unsupported conversational provider')
        credential=key('openai')
        location='transport'
        result=sdk.completion(model='openai/'+request['model'],custom_llm_provider='openai',api_key=credential,
            messages=[restore(m) for m in request['messages']],tools=request['conversation']['tools'],
            tool_choice=request['conversation'].get('tool_choice','auto'),
            stream=False,max_completion_tokens=request['conversation']['output_tokens'],
            timeout=request['timeout'],num_retries=0,drop_params=False)
        location='extraction'
        try:choice=result.choices[0];message=choice.message;finish=choice.finish_reason
        except (AttributeError,IndexError,TypeError):reject('RESPONSE_TYPE_INVALID')
        from .diagnostics import response_shape as describe
        response_shape=describe(message,finish)
        metadata={'conversation':{**detail(location,finish=finish),**response_shape}}
        usage=getattr(result,'usage',None)
        response_shape.update({k:getattr(usage,k) for k in ('prompt_tokens','completion_tokens','total_tokens') if type(getattr(usage,k,None)) is int and 0<=getattr(usage,k)<=10000000})
        metadata['conversation'].update(response_shape)
        if getattr(message,'refusal',None):raise ProviderFailure('provider_refusal','provider_generation',metadata=metadata)
        if finish=='length':raise ProviderFailure('output_truncated','provider_generation',metadata=metadata)
        if finish=='content_filter':raise ProviderFailure('provider_refusal','provider_generation',metadata=metadata)
        if finish not in ('stop','tool_calls'):
            metadata['conversation']['failed_rule']='FINISH_REASON_INVALID'
            raise ProviderFailure('conversation_finish','provider_generation',metadata=metadata)
        if not hasattr(message,'content'):reject('ASSISTANT_CONTENT_INVALID')
        calls=[]
        returned=getattr(message,'tool_calls',None)
        if returned is not None and type(returned) is not list:reject('TOOL_CALL_STRUCTURE_INVALID')
        if returned and len(returned)>MAX_CALLS:reject('TOOL_CALL_COUNT_EXCEEDED')
        for call in (returned or []):
            if getattr(call,'type',None)!='function':reject('TOOL_CALL_STRUCTURE_INVALID')
            try:arguments=loads(call.function.arguments,max_bytes=16384)
            except (ValueError,TypeError,AttributeError):reject('TOOL_CALL_ARGUMENTS_INVALID')
            calls.append(dict(id=getattr(call,'id',None),name=getattr(call.function,'name',None),arguments=arguments))
        location='validation'
        value=dict(text=message.content if message.content is not None else '',tool_calls=calls,finish_reason=finish,
            usage={k:getattr(usage,k) for k in ('prompt_tokens','completion_tokens','total_tokens') if type(getattr(usage,k,None)) is int},cost=None)
        # Preserve exact argument serialization and reasoning/phase/order fields:
        # LiteLLM's replay checksum binds these, not just parsed tool arguments.
        if getattr(message,'provider_specific_fields',None) or getattr(message,'reasoning_items',None) or getattr(message,'phase',None):
            try:raw=message.model_dump()
            except (TypeError,AttributeError,ValueError):reject('CONTINUATION_FIELDS_INVALID')
            if type(raw) is not dict:reject('CONTINUATION_FIELDS_INVALID')
            raw={k:v for k,v in raw.items() if k in ('role','content','tool_calls','reasoning_items','provider_specific_fields','phase')}
            raw['role']='assistant'
            try:payload=json.dumps(raw,ensure_ascii=True,allow_nan=False,separators=(',',':'))
            except (ValueError,TypeError):reject('CONTINUATION_JSON_INVALID')
            response_shape['continuation_bytes']=len(payload.encode())
            value['continuation']=dict(format='litellm-openai-history-v1',payload=payload)
        return validate(value)
    except ProviderFailure:raise
    except Exception as exc:
        category=classify(exc) if location=='transport' else 'missing_credential' if location=='configuration' else 'conversation_envelope'
        if location=='transport' and category=='unknown_provider_error' and type(exc) in (ValueError,TypeError,AttributeError,KeyError,RuntimeError):category='conversation_adapter'
        raise ProviderFailure(category,'timeout' if category=='timeout' else 'provider_request' if location=='transport' else 'configuration' if location=='configuration' else 'response_parse',
            metadata={**error_metadata(exc),'conversation':{**detail(location,exc,finish),**response_shape}}) from None


class ScriptedProvider:
    provider_name='openai'
    model_name='scripted'
    def __init__(self,steps):self.steps=iter(steps);self.calls=[]
    def converse(self,messages,tools,*,timeout,output_tokens):
        self.calls.append(messages)
        step=next(self.steps)
        return validate(step(messages) if callable(step) else step)

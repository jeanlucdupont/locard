"""Provider-neutral completion result and OpenAI native tool-call extraction."""
import json
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from forensic_assistant.investigation_ai.contracts import loads


def validate(value):
    if type(value) is not dict or set(value)-{'continuation'}!={'text','tool_calls','finish_reason','usage','cost'}:raise ValueError('Invalid conversational response')
    if type(value['text']) is not str or len(value['text'].encode())>32768 or type(value['tool_calls']) is not list or len(value['tool_calls'])>4:raise ValueError('Conversational response size')
    if value['finish_reason'] not in ('stop','tool_calls'):raise ValueError('Incomplete conversational response')
    ids=set()
    for call in value['tool_calls']:
        if type(call) is not dict or set(call)!={'id','name','arguments'} or type(call['id']) is not str or not 1<=len(call['id'])<=128 or call['id'] in ids or type(call['name']) is not str or len(call['name'])>80 or type(call['arguments']) is not dict:raise ValueError('Invalid conversational tool call')
        ids.add(call['id'])
    if bool(ids)!=(value['finish_reason']=='tool_calls'):raise ValueError('Tool completion status mismatch')
    if type(value['usage']) is not dict or set(value['usage'])-{'prompt_tokens','completion_tokens','total_tokens'} or any(type(v) is not int or not 0<=v<=10000000 for v in value['usage'].values()):raise ValueError('Invalid provider usage')
    if value['cost'] is not None:raise ValueError('Unverified monetary accounting')
    if 'continuation' in value:
        restore(assistant_message(value))
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
    if type(state) is not dict or set(state)!={'format','payload'} or state['format']!='litellm-openai-history-v1':raise ValueError('Unsupported provider continuation')
    if type(state['payload']) is not str:raise ValueError('Invalid provider continuation')
    raw=loads(state['payload'],max_bytes=32768)
    if type(raw) is not dict or raw.get('role')!='assistant' or set(raw)-{'role','content','tool_calls','reasoning_items','provider_specific_fields','phase'}:raise ValueError('Invalid assistant continuation')
    if (raw.get('content') or '')!=(message.get('content') or ''):raise ValueError('Continuation content changed')
    def calls(items):
        return [(c['id'],c['type'],c['function']['name'],loads(c['function']['arguments'],max_bytes=16384)) for c in (items or [])]
    if calls(raw.get('tool_calls'))!=calls(message.get('tool_calls')):raise ValueError('Continuation tool binding changed')
    return raw


def generate(request,sdk):
    from forensic_assistant.ai.settings import key
    from forensic_assistant.ai.provider_diagnostics import classify,error_metadata
    from .diagnostics import detail
    location='configuration';finish=None
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
        choice=result.choices[0];message=choice.message;finish=choice.finish_reason
        metadata={'conversation':detail(location,finish=finish)}
        usage=getattr(result,'usage',None)
        metadata['conversation'].update({k:getattr(usage,k) for k in ('prompt_tokens','completion_tokens','total_tokens') if type(getattr(usage,k,None)) is int and 0<=getattr(usage,k)<=10000000})
        if getattr(message,'refusal',None):raise ProviderFailure('provider_refusal','provider_generation',metadata=metadata)
        if finish=='length':raise ProviderFailure('output_truncated','provider_generation',metadata=metadata)
        if finish=='content_filter':raise ProviderFailure('provider_refusal','provider_generation',metadata=metadata)
        if finish not in ('stop','tool_calls'):raise ProviderFailure('conversation_finish','provider_generation',metadata=metadata)
        calls=[]
        for call in (getattr(message,'tool_calls',None) or []):
            if getattr(call,'type',None)!='function':raise ValueError('Invalid tool type')
            try:arguments=loads(call.function.arguments,max_bytes=16384)
            except (ValueError,TypeError):raise ProviderFailure('response_parse','response_parse',metadata=metadata) from None
            calls.append(dict(id=call.id,name=call.function.name,arguments=arguments))
        location='validation'
        value=dict(text=message.content if message.content is not None else '',tool_calls=calls,finish_reason=finish,
            usage={k:getattr(usage,k) for k in ('prompt_tokens','completion_tokens','total_tokens') if type(getattr(usage,k,None)) is int},cost=None)
        # Preserve exact argument serialization and reasoning/phase/order fields:
        # LiteLLM's replay checksum binds these, not just parsed tool arguments.
        if getattr(message,'provider_specific_fields',None) or getattr(message,'reasoning_items',None) or getattr(message,'phase',None):
            raw=message.model_dump()
            raw={k:v for k,v in raw.items() if k in ('role','content','tool_calls','reasoning_items','provider_specific_fields','phase')}
            raw['role']='assistant'
            value['continuation']=dict(format='litellm-openai-history-v1',payload=json.dumps(raw,ensure_ascii=True,allow_nan=False,separators=(',',':')))
        return validate(value)
    except ProviderFailure:raise
    except Exception as exc:
        category=classify(exc) if location=='transport' else 'missing_credential' if location=='configuration' else 'conversation_envelope'
        if location=='transport' and category=='unknown_provider_error' and type(exc) in (ValueError,TypeError,AttributeError,KeyError,RuntimeError):category='conversation_adapter'
        raise ProviderFailure(category,'timeout' if category=='timeout' else 'provider_request' if location=='transport' else 'configuration' if location=='configuration' else 'response_parse',
            metadata={**error_metadata(exc),'conversation':detail(location,exc,finish)}) from None


class ScriptedProvider:
    provider_name='openai'
    model_name='scripted'
    def __init__(self,steps):self.steps=iter(steps);self.calls=[]
    def converse(self,messages,tools,*,timeout,output_tokens):
        self.calls.append(messages)
        step=next(self.steps)
        return validate(step(messages) if callable(step) else step)

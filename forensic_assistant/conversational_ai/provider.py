"""Provider-neutral completion result and OpenAI native tool-call extraction."""
import json
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from forensic_assistant.investigation_ai.contracts import loads


def validate(value):
    if type(value) is not dict or set(value)!={'text','tool_calls','finish_reason','usage','cost'}:raise ValueError('Invalid conversational response')
    if type(value['text']) is not str or len(value['text'].encode())>32768 or type(value['tool_calls']) is not list or len(value['tool_calls'])>4:raise ValueError('Conversational response size')
    if value['finish_reason'] not in ('stop','tool_calls'):raise ValueError('Incomplete conversational response')
    ids=set()
    for call in value['tool_calls']:
        if type(call) is not dict or set(call)!={'id','name','arguments'} or type(call['id']) is not str or not 1<=len(call['id'])<=128 or call['id'] in ids or type(call['name']) is not str or len(call['name'])>80 or type(call['arguments']) is not dict:raise ValueError('Invalid conversational tool call')
        ids.add(call['id'])
    if bool(ids)!=(value['finish_reason']=='tool_calls'):raise ValueError('Tool completion status mismatch')
    if type(value['usage']) is not dict or set(value['usage'])-{'prompt_tokens','completion_tokens','total_tokens'} or any(type(v) is not int or not 0<=v<=10000000 for v in value['usage'].values()):raise ValueError('Invalid provider usage')
    if value['cost'] is not None:raise ValueError('Unverified monetary accounting')
    return value


def generate(request,sdk):
    if request['provider']!='openai':raise ValueError('Unsupported conversational provider')
    from forensic_assistant.ai.settings import key
    result=sdk.completion(model='openai/'+request['model'],custom_llm_provider='openai',api_key=key('openai'),
        messages=request['messages'],tools=request['conversation']['tools'],tool_choice='auto',
        stream=False,max_completion_tokens=request['conversation']['output_tokens'],
        timeout=request['timeout'],num_retries=0,drop_params=False)
    try:
        choice=result.choices[0];message=choice.message
        if getattr(message,'refusal',None):raise ProviderFailure('refusal','provider_generation')
        calls=[]
        for call in (getattr(message,'tool_calls',None) or []):
            if getattr(call,'type',None)!='function':raise ValueError('Invalid tool type')
            calls.append(dict(id=call.id,name=call.function.name,arguments=loads(call.function.arguments,max_bytes=16384)))
        usage=getattr(result,'usage',None)
        return validate(dict(text=message.content or '',tool_calls=calls,finish_reason=choice.finish_reason,
            usage={k:getattr(usage,k) for k in ('prompt_tokens','completion_tokens','total_tokens') if type(getattr(usage,k,None)) is int},cost=None))
    except (ValueError,TypeError,AttributeError,IndexError):raise ProviderFailure('response_parse','response_parse') from None


class ScriptedProvider:
    provider_name='openai'
    model_name='scripted'
    def __init__(self,steps):self.steps=iter(steps);self.calls=[]
    def converse(self,messages,tools,*,timeout,output_tokens):
        self.calls.append(messages)
        step=next(self.steps)
        return validate(step(messages) if callable(step) else step)

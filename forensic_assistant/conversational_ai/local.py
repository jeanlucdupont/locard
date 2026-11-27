"""Loopback llama.cpp native tools. No DNS, proxies, redirects or cloud SDK."""
import http.client
import json
import math
import os
import subprocess
import sys
from pathlib import Path
from forensic_assistant.llm.client import endpoint_parts
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from forensic_assistant.investigation_ai.contracts import loads
from .provider import validate, restore, ValidationError
from .local_schema import generation_catalog


def configuration(endpoint,model,context=32768,temperature=0.2,parallel=False):
    host,port=endpoint_parts(endpoint)
    if type(model) is not str or not 1<=len(model.encode())<=256 or any(ord(c)<32 for c in model):raise ValueError('Invalid local model identifier')
    if type(context) is not int or not 4096<=context<=131072:raise ValueError('Local context must be 4096..131072 tokens')
    if type(temperature) not in (int,float) or not math.isfinite(temperature) or not 0<=temperature<=2:raise ValueError('Invalid local temperature')
    if type(parallel) is not bool:raise ValueError('Invalid local tool mode')
    return dict(contract='local-conversation-v1',endpoint=f'http://[{host}]:{port}' if ':' in host else f'http://{host}:{port}',
        model=model,context_tokens=context,temperature=temperature,parallel_tools=parallel)


def checked(value):
    if type(value) is not dict or set(value)!={'contract','endpoint','model','context_tokens','temperature','parallel_tools'}:raise ValueError('Invalid local configuration')
    expected=configuration(value['endpoint'],value['model'],value['context_tokens'],value['temperature'],value['parallel_tools'])
    if value!=expected:raise ValueError('Noncanonical local configuration')
    return expected


def http_json(config,path,body=None,timeout=30):
    """Used inside a deadline-enforced child for inference; bounded response reads."""
    checked(config);host,port=endpoint_parts(config['endpoint'])
    conn=http.client.HTTPConnection(host,port,timeout=timeout)
    try:
        conn.request('GET' if body is None else 'POST',path,body=None if body is None else encoded(body),headers={'Content-Type':'application/json'})
        response=conn.getresponse();raw=response.read(1024*1024+1)
        if len(raw)>1024*1024:raise ProviderFailure('conversation_envelope','response_parse')
        if response.status!=200:
            category='provider_server_error' if response.status>=500 else 'model_rejected' if response.status==404 else 'request_rejected'
            detail={}
            try:
                envelope=loads(raw.decode(),max_bytes=1024*1024)
                error=envelope.get('error',{}) if isinstance(envelope,dict) else {}
                from .local_diagnostics import server_detail
                detail=server_detail(error)
                if detail['server_code'].startswith('grammar_'):category='local_grammar_rejected'
                elif detail['server_code']=='context_exhausted':category='local_context_exhausted'
            except (ValueError,TypeError,UnicodeError):pass
            raise ProviderFailure(category,'provider_request',metadata={'http_status':response.status,'local_transport':detail})
        return loads(raw.decode('utf-8'),max_bytes=1024*1024)
    except TimeoutError:raise ProviderFailure('timeout','timeout') from None
    except (OSError,http.client.HTTPException):raise ProviderFailure('network_error','provider_request') from None
    finally:conn.close()


def parse(value):
    supplied=value.get('usage') if type(value) is dict else None
    usage={k:v for k,v in supplied.items() if k in ('prompt_tokens','completion_tokens','total_tokens') and type(v) is int and 0<=v<=10000000} if type(supplied) is dict else {}
    metadata={'conversation':usage}
    try:
        if type(value) is not dict or type(value.get('choices')) is not list or len(value['choices'])!=1:raise ValueError()
        choice=value['choices'][0];message=choice['message'];finish=choice['finish_reason']
        if message.get('refusal') or finish=='content_filter':raise ProviderFailure('provider_refusal','provider_generation',metadata=metadata)
        if finish=='length':raise ProviderFailure('output_truncated','provider_generation',metadata=metadata)
        # Prose resembling a tool call never becomes an invocation.
        if type(message.get('content')) not in (str,type(None)):raise ValueError()
        if message.get('function_call') is not None:raise ProviderFailure('local_tool_protocol','response_parse')
        raw_calls=message.get('tool_calls')
        if raw_calls is None:raw_calls=[]
        if type(raw_calls) is not list:raise ValueError()
        calls=[]
        for call in raw_calls:
            if call.get('type')!='function':raise ValueError()
            fn=call['function']
            calls.append(dict(id=call['id'],name=fn['name'],arguments=loads(fn['arguments'],max_bytes=16384)))
        usage=value.get('usage') or {}
        if type(usage) is not dict:raise ValueError()
        return validate(dict(text=message.get('content') or '',tool_calls=calls,finish_reason=finish,
            usage={k:usage[k] for k in ('prompt_tokens','completion_tokens','total_tokens') if k in usage and usage[k] is not None},cost=None))
    except ProviderFailure:raise
    except (ValueError,KeyError,TypeError,AttributeError) as exc:
        code=exc.code if isinstance(exc,ValidationError) else 'LOCAL_NATIVE_ENVELOPE'
        raise ProviderFailure('conversation_envelope','response_parse',metadata={'conversation':{'failed_rule':code}}) from None


def encoded(value):return json.dumps(value,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode()


def body_for(config,messages,tools,output_tokens,tool_choice='auto'):
    return dict(model=config['model'],messages=[restore(m) for m in messages],tools=generation_catalog(tools),
        tool_choice=tool_choice,parallel_tool_calls=config['parallel_tools'],
        max_tokens=output_tokens,temperature=config['temperature'],stream=False,
        chat_template_kwargs={'enable_thinking':False})


def wire_overhead(config,output_tokens):
    return len(encoded(body_for(config,[],[],output_tokens)))-len(encoded(dict(messages=[],tools=[])))


def generate(request):
    config=checked(request['local'])
    if request.get('metadata') is True:
        value=http_json(config,'/v1/models',timeout=request['timeout'])
        return {'data':[{'id':m['id']} for m in value.get('data',[])[:128] if isinstance(m,dict) and type(m.get('id')) is str and len(m['id'].encode())<=256]}
    body=body_for(config,request['messages'],request['tools'],request['output_tokens'],request.get('tool_choice','auto'))
    return parse(http_json(config,'/v1/chat/completions',body,request['timeout']))


def dispatch(config,messages,tools,timeout,output_tokens,tool_choice='auto'):
    from forensic_assistant.session_recording import require,record
    checked(config)
    if not 0<timeout<=600:raise ValueError('Local timeout must be greater than zero and at most 600 seconds')
    if tool_choice not in ('auto','required','none'):raise ValueError('Invalid tool mode')
    if type(output_tokens) is not int or not 1<=output_tokens<=32768:raise ValueError('Invalid local output capacity')
    measured=len(encoded(body_for(config,messages,tools,output_tokens,tool_choice)))
    if measured>config['context_tokens']-output_tokens-2048:raise ProviderFailure('local_context_exhausted','configuration')
    require();record('provider_dispatch_boundary',dict(provider='local',model=config['model'],exposure='loopback attempt may follow'),required=True)
    request=dict(local=config,messages=messages,tools=tools,timeout=timeout,output_tokens=output_tokens,tool_choice=tool_choice)
    try:return run_client(request,timeout)
    except ProviderFailure as exc:
        exc.metadata['local_transport']={**exc.metadata.get('local_transport',{}),'request_bytes':measured,
            'timed_out':exc.category=='timeout','client_cleanup':'confirmed','server_cleanup':'unconfirmed','usage':'available' if any(k in exc.metadata.get('conversation',{}) for k in ('prompt_tokens','completion_tokens','total_tokens')) else 'unknown','inference_began':'unknown'}
        raise


def models(config,timeout=30):
    checked(config)
    if not 0<timeout<=600:raise ValueError('Invalid local metadata timeout')
    return run_client(dict(local=config,metadata=True,timeout=timeout),timeout)


def run_client(request,timeout):
    from forensic_assistant.ai.runtime import clean_environment
    from forensic_assistant.investigation_ai.lifecycle import WorkerJob
    raw=json.dumps(request,ensure_ascii=True,allow_nan=False).encode()
    if len(raw)>600*1024:raise ValueError('Local request capacity')
    process=subprocess.Popen([sys.executable,'-B','-m',__name__],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        cwd=str(Path(__file__).resolve().parents[2]),env=clean_environment(),creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    job=None
    try:
        job=WorkerJob(process.pid) if os.name=='nt' else None
        output,_=process.communicate(raw,timeout=timeout)
        if process.returncode or len(output)>1024*1024:raise ProviderFailure('conversation_envelope','response_parse')
        result=loads(output.decode(),max_bytes=1024*1024)
        if 'error' in result:raise ProviderFailure(result['error'],result['stage'],metadata=result.get('metadata'))
        return result if request.get('metadata') is True else validate(result)
    except subprocess.TimeoutExpired:raise ProviderFailure('timeout','timeout') from None
    finally:
        try:
            if job:job.close()
        finally:
            if process.poll() is None:process.kill()
            process.wait(timeout=5)


if __name__=='__main__':
    try:
        request=loads(sys.stdin.buffer.read(600*1024+1).decode(),max_bytes=600*1024)
        result=generate(request)
    except ProviderFailure as exc:result=dict(error=exc.category,stage=exc.stage,metadata=exc.metadata)
    except Exception:result=dict(error='conversation_envelope',stage='response_parse')
    sys.stdout.write(json.dumps(result,ensure_ascii=True,allow_nan=False))

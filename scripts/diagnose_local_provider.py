"""Harmless local native-tool diagnostic; --mock needs no installed model."""
import argparse
import json
import sys
import tempfile
import threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.conversational_ai.provider import assistant_message,ScriptedProvider
from forensic_assistant.conversational_ai.local import models


def wire(value):
    msg=assistant_message(value)
    return dict(choices=[dict(index=0,message=msg,finish_reason=value['finish_reason'])],usage=value['usage'])


class MockEndpoint:
    """Protocol fixture, not a real local model or reasoning-quality evaluation."""
    def __init__(self,respond):
        self.calls=[];self.respond=respond
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                raw=json.dumps({'data':[{'id':'synthetic'},{'id':'synthetic-local'}]}).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def do_POST(self):
                try:
                    size=int(self.headers.get('Content-Length','0'))
                    if size>600*1024:raise ValueError()
                    body=json.loads(self.rfile.read(size));owner.calls.append(body)
                    result=owner.respond(body)
                    raw=json.dumps(result).encode()
                    self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
                except (OSError,ValueError,StopIteration):self.close_connection=True
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.endpoint='http://127.0.0.1:'+str(self.server.server_port)
    def __enter__(self):self.thread.start();return self
    def __exit__(self,*args):self.server.shutdown();self.server.server_close();self.thread.join(3)


def simulated(directory,capacity=28000):
    from scripts.diagnose_investigative_memory import diagnostic
    scripted=[None]
    def respond(body):return wire(scripted[0].converse(body['messages'],body['tools'],timeout=30,output_tokens=2048))
    with MockEndpoint(respond) as server:
        def factory(steps):
            scripted[0]=ScriptedProvider(steps)
            client=ModelBackend.local_conversation(server.endpoint,'synthetic-local',capacity+4096)
            client.calls=scripted[0].calls
            return client
        result=diagnostic(directory,capacity,provider_factory=factory)
        result['provider']='Simulated loopback HTTP endpoint through production ModelBackend and supervised transport; no real model'
        result['protocol_requests']=len(server.calls)
        result['sequential_mode']=all(c['parallel_tool_calls'] is False for c in server.calls)
        from forensic_assistant.conversational_ai.local import encoded
        result['wire_body_sizes']=[len(encoded(c)) for c in server.calls]
        result['configured_context_tokens']=capacity+4096
        result['checks']['final_wire_budget']=max(result['wire_body_sizes'])<=capacity
        return result


def probe(client,timeout=180,output_tokens=512):
    binding=client.conversation_binding()
    result={'endpoint':binding['endpoint'],'model':client.model_name,'configured_context_tokens':binding['context_tokens'],
        'tokenizer':'Not queried; context sizing is a UTF-8 byte proxy with reserve, not an exact token guarantee',
        'cancellation':'Client child is contained on timeout/Ctrl+C; external server cancellation cannot be confirmed',
        'multiple_calls':'Not required; sequential native calls supported','checks':{}}
    metadata=models(binding,timeout=min(timeout,30))
    ids=[m.get('id') for m in metadata.get('data',[]) if isinstance(m,dict)]
    result['checks']['model_available']=client.model_name in ids
    if not result['checks']['model_available']:return result
    tools=[dict(type='function',function=dict(name='synthetic_echo',description='Return harmless diagnostic text.',parameters=dict(type='object',properties={'text':{'type':'string'}},required=['text'],additionalProperties=False)))]
    messages=[dict(role='system',content='This is a harmless tool protocol test, not an investigation.'),dict(role='user',content='Say ready.')]
    text=client.converse(messages,tools,timeout=timeout,output_tokens=output_tokens,tool_choice='none')
    result['checks']['text_response']=bool(text['text']) and not text['tool_calls']
    messages=[messages[0],dict(role='user',content='Call synthetic_echo with text locard-local-test. Do not describe a call in prose.')]
    call=client.converse(messages,tools,timeout=timeout,output_tokens=output_tokens,tool_choice='required')
    valid=bool(call['tool_calls']) and all(c['name']=='synthetic_echo' and c['arguments']=={'text':'locard-local-test'} for c in call['tool_calls'])
    result['checks']['native_tool_call']=valid
    if not valid:
        result['limitation']='Native tool protocol not demonstrated. Check model and llama.cpp --jinja; no prose parsed as tools.';return result
    messages.append(assistant_message(call))
    for c in call['tool_calls']:messages.append(dict(role='tool',tool_call_id=c['id'],content=json.dumps({'text':'locard-local-test'})))
    messages.append(dict(role='user',content='Summarize the returned harmless value in a sentence.'))
    final=client.converse(messages,tools,timeout=timeout,output_tokens=output_tokens,tool_choice='none')
    result['checks']['tool_continuation']=bool(final['text']) and not final['tool_calls']
    result['usage']=[v['usage'] for v in (text,call,final)]
    result['limitation']='Protocol success does not establish forensic reasoning quality. No forensic evidence sent.'
    return result



def full_catalog(client,timeout=180,output_tokens=512):
    """Compile the production catalog but execute no returned investigative tool."""
    import time
    from forensic_assistant.conversational_ai.contracts import catalog,arguments
    from forensic_assistant.conversational_ai.local import body_for,encoded
    from forensic_assistant.conversational_ai.local_schema import generation_catalog,REMOVED
    tools=catalog();binding=client.conversation_binding()
    result=dict(mode='full_catalog',endpoint=binding['endpoint'],model=binding['model'],checks={},requests=[],
        canonical_schema_bytes=len(encoded(tools)),generation_schema_bytes=len(encoded(generation_catalog(tools))),
        transformations=list(REMOVED),tools=len(tools),
        limitation='No tools executed. Mock success is not llama.cpp grammar acceptance; grammar acceptance is not investigative capability.')
    messages=[dict(role='system',content='Harmless synthetic protocol test. No case or workspace is open. Do not invent evidence.'),
        dict(role='user',content='Call memory with kind state only. This is a simulated empty memory; no forensic tools will execute.')]
    for phase in ('required','none'):
        measured=len(encoded(body_for(binding,messages,tools,output_tokens,phase)));started=time.monotonic()
        try:response=client.converse(messages,tools,timeout=timeout,output_tokens=output_tokens,tool_choice=phase)
        except Exception as exc:
            result['requests'].append(dict(status='failed',elapsed_seconds=time.monotonic()-started,request_bytes=measured,
                category=getattr(exc,'category','diagnostic_failed'),stage=getattr(exc,'stage','configuration'),
                diagnostic=getattr(exc,'metadata',{}),usage={k:v for k,v in getattr(exc,'metadata',{}).get('conversation',{}).items() if k in ('prompt_tokens','completion_tokens','total_tokens')} or 'unknown'))
            result['checks']['provider_response']=False;return result
        result['requests'].append(dict(status='response_received',http_status=200,elapsed_seconds=time.monotonic()-started,request_bytes=measured,usage=response['usage']))
        if phase=='required':
            try:
                for call in response['tool_calls']:arguments(call['name'],call['arguments'])
                result['checks']['canonical_arguments']=bool(response['tool_calls'])
            except ValueError:result['checks']['canonical_arguments']=False
            result['checks']['requested_harmless_call']=bool(response['tool_calls']) and all(c['name']=='memory' and c['arguments']=={'kind':'state'} for c in response['tool_calls'])
            if not all(result['checks'].values()):
                result['failure_stage']='argument_selection_or_validation';return result
            messages.append(assistant_message(response))
            for call in response['tool_calls']:messages.append(dict(role='tool',tool_call_id=call['id'],content='{"synthetic":true,"items":[]}'))
            messages.append(dict(role='user',content='Confirm the simulated empty result briefly.'))
        else:result['checks']['continuation']=bool(response['text']) and not response['tool_calls']
    return result


def successful(result):
    return ('error' not in result and all(result.get('checks',{}).values()) and
        result.get('outcome','COMPLETED')=='COMPLETED' and
        (not result.get('observations') or all(result['observations'].get(k,False) for k in ('original_inspection','verification','memory_retrieval','final_response'))))


def synthetic_investigation(directory,client,timeout=180,output_tokens=2048):
    """Real model, disposable evidence only. Explicit diagnostic request budget."""
    import hashlib
    from scripts.diagnose_investigative_memory import synthetic_case
    from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
    from forensic_assistant.conversational_ai.service import Session,Paused
    from forensic_assistant.conversational_ai.workspace import reconstruct
    path,sid,before=synthetic_case(directory)
    scope=authorize(path,[sid],'2020-01-01T00:00:00Z','2020-01-02T00:00:00Z',FAMILIES,'local',client.model_name,
        {'requests':12,'provider_seconds':timeout,'output_tokens':output_tokens},local=client.conversation_binding())
    session=Session(scope,client,lambda _:True,checkpoint_seconds=.01)
    reason='COMPLETED';answer={};failure={}
    try:
        answer=session.submit('Investigate this synthetic recorded activity without assuming compromise. Inspect originals and independently verify important fields. Use investigative memory to review search coverage and verification history. Distinguish observations, hypotheses and incomplete coverage in your final assessment.')
    except Paused as exc:
        reason=str(exc);cause=exc.__cause__
        failure=dict(category=getattr(cause,'category',None),stage=getattr(cause,'stage',None),diagnostic=getattr(cause,'metadata',{}))
    finally:session.close(reason)
    rebuilt=reconstruct(session.journal.path,Path(directory)/'reconstructed')
    return dict(provider='Actual configured local model; disposable synthetic case',diagnostic_request_ceiling=12,
        outcome=reason,failure=failure,endpoint=client.conversation_binding()['endpoint'],model=client.model_name,usage=session.used,workspace=rebuilt,interpretation=answer.get('interpretation'),
        checks=dict(case_unchanged=hashlib.sha256(path.read_bytes()).hexdigest()==before,worker_closed=session.worker.process.poll() is not None),
        observations=dict(original_inspection=session.used['original_rehydrations']>0,verification=rebuilt['counts']['verifications']>0,
            memory_retrieval=session.used['memory_operations']>0,context_consolidation=session.used['context_consolidations']>0,
            automatic_checkpoint=session.used['automatic_checkpoints']>0,final_response=bool(answer.get('interpretation'))),
        limitation='Diagnostic scope/request ceiling only, not a production quota. Inspect missing capabilities before real-case acceptance.')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mock',action='store_true');p.add_argument('--endpoint');p.add_argument('--model')
    p.add_argument('--context',type=int,default=32768);p.add_argument('--timeout',type=int,default=180)
    p.add_argument('--output-tokens',type=int,default=512);p.add_argument('--context-bytes',type=int,default=28000)
    p.add_argument('--full-catalog',action='store_true',help='Production tool grammar; no evidence access or tool execution')
    p.add_argument('--synthetic-investigation',action='store_true',help='Use the real local model on a disposable synthetic case (12-request diagnostic budget)')
    args=p.parse_args()
    if not args.mock and not (args.endpoint and args.model):p.error('Use --mock or --endpoint and --model')
    try:
        if args.mock:
            with tempfile.TemporaryDirectory(prefix='locard-local-protocol-') as tmp:result=simulated(tmp,args.context_bytes)
            result['journal']='Temporary synthetic journal removed after validation'
        else:
            client=ModelBackend.local_conversation(args.endpoint,args.model,args.context)
            if args.full_catalog:result=full_catalog(client,args.timeout,args.output_tokens)
            elif args.synthetic_investigation:
                with tempfile.TemporaryDirectory(prefix='locard-local-synthetic-') as tmp:result=synthetic_investigation(tmp,client,args.timeout,args.output_tokens)
            else:result=probe(client,args.timeout,args.output_tokens)
    except Exception as exc:
        result={'error':getattr(exc,'category','diagnostic_failed'),'stage':getattr(exc,'stage','configuration'),'no_fallback':True,'diagnostic':getattr(exc,'metadata',{})}
    print(json.dumps(result,indent=2))
    return 0 if successful(result) else 1


if __name__=='__main__':raise SystemExit(main())

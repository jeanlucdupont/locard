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


def fixture_prompt(body):
    # Mock-only rendering/counting, deliberately not a real tokenizer claim.
    return json.dumps({k:body.get(k) for k in ('messages','tools','tool_choice','chat_template_kwargs')},ensure_ascii=False)


def fixture_tokens(prompt):return max(1,(len(prompt.encode())+3)//4)


class MockEndpoint:
    """Protocol fixture, not a real local model or reasoning-quality evaluation."""
    def __init__(self,respond,*,tokenizer=False):
        self.calls=[];self.auxiliary=[];self.respond=respond;self.tokenizer=tokenizer
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                value={'data':[{'id':'synthetic'},{'id':'synthetic-local'}]}
                if self.path=='/props' and owner.tokenizer:value={'chat_template':'fixture-not-real-llama','default_generation_settings':{'n_ctx':32768}}
                raw=json.dumps(value).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def do_POST(self):
                try:
                    size=int(self.headers.get('Content-Length','0'))
                    if size>600*1024:raise ValueError()
                    body=json.loads(self.rfile.read(size))
                    if owner.tokenizer and self.path in ('/apply-template','/tokenize'):
                        owner.auxiliary.append((self.path,body))
                        result={'prompt':fixture_prompt(body)} if self.path=='/apply-template' else {'tokens':list(range(fixture_tokens(body['content'])))}
                    else:
                        owner.calls.append(body);result=owner.respond(body)
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
    def respond(body):
        result=wire(scripted[0].converse(body['messages'],body['tools'],timeout=30,output_tokens=2048))
        count=fixture_tokens(fixture_prompt(body))
        result['usage']={'prompt_tokens':count,'completion_tokens':5,'total_tokens':count+5}
        return result
    with MockEndpoint(respond,tokenizer=True) as server:
        def factory(steps):
            scripted[0]=ScriptedProvider(steps)
            client=ModelBackend.local_conversation(server.endpoint,'synthetic-local',capacity+4096)
            client.calls=scripted[0].calls
            return client
        result=diagnostic(directory,capacity,provider_factory=factory)
        result['provider']='Simulated loopback HTTP endpoint through production ModelBackend and supervised transport; no real model'
        result['protocol_requests']=len(server.calls)
        result['auxiliary_http_requests']=len(server.auxiliary)
        result['tokenizer']='Synthetic fixture counts; not real llama.cpp parity'
        result['checks']['auxiliary_measurement_exercised']=len(server.auxiliary)>0
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


def tokenization_probe(client,timeout=180,output_tokens=512):
    """Two explicitly requested harmless completions, never hidden in measurement."""
    import time,uuid
    from forensic_assistant.conversational_ai.local_context import ContextMeter
    from forensic_assistant.conversational_ai.contracts import catalog,arguments
    meter=ContextMeter(client.conversation_binding(),uuid.uuid4().hex);client._context_meter=meter
    tools=catalog();aux=[];rows=[]
    messages=[dict(role='system',content='Harmless synthetic parity test. Reply briefly. No forensic tool executes.'),
        dict(role='user',content='Synthetic café 日本語; C:\\Windows\\Temp\\sample.txt; EID:MFT:'+'a'*64+'; Registry HKLM\\Software\\Example; JSON "quoted"; memory: unverified reference only.')]
    histories=[messages,messages+[dict(role='assistant',content=None,tool_calls=[dict(id='synthetic-memory-1',type='function',function=dict(name='memory',arguments='{"kind":"state"}'))]),
        dict(role='tool',tool_call_id='synthetic-memory-1',content='{"synthetic":true,"items":[],"coverage":"incomplete"}'),dict(role='user',content='Acknowledge the synthetic incomplete memory result briefly.')]]
    for candidate in histories:
        measured=meter.measure(candidate,tools,output_tokens,256*1024,min(timeout,30),lambda path,body:aux.append(dict(route=path,bytes=0 if body is None else len(json.dumps(body).encode()))),choice='none')
        row={'measurement':measured};rows.append(row)
        if measured['input_tokens'] is None or not measured['fits']:break
        started=time.monotonic()
        try:
            response=client.converse(candidate,tools,timeout=timeout,output_tokens=output_tokens,tool_choice='none')
            row.update(parity=meter.observe(measured,response['usage']),usage=response['usage'],inference_seconds=time.monotonic()-started,native_response='valid')
            row['canonical_arguments']='valid' if response['tool_calls'] else 'not_applicable'
            try:
                for call in response['tool_calls']:arguments(call['name'],call['arguments'])
            except ValueError as exc:
                from forensic_assistant.conversational_ai.operation_diagnostics import failure_detail
                row['canonical_arguments']='invalid';row['argument_diagnostic']=failure_detail(exc)
            row['unexpected_tool_calls']=bool(response['tool_calls'])
        except Exception as exc:
            row.update(error=getattr(exc,'category','invalid_arguments'),stage=getattr(exc,'stage','response_validation'),diagnostic=getattr(exc,'metadata',{}));break
    client._context_meter=None
    return dict(mode='tokenization',endpoint=client.conversation_binding()['endpoint'],model=client.model_name,
        rows=rows,auxiliary=aux,checks={'initial_and_tool_parity':len(rows)==2 and all(r.get('parity',{}).get('difference')==0 for r in rows)},
        limitation='Two explicit harmless inference attempts at most. Mock token counts are fixtures. Parity is observed for these requests, not proof for every template or future server configuration.')


def successful(result):
    return ('error' not in result and all(result.get('checks',{}).values()) and
        result.get('outcome','COMPLETED')=='COMPLETED' and
        (not result.get('observations') or all(result['observations'].get(k,False) for k in ('original_inspection','verification','memory_retrieval','final_response'))))


def synthetic_investigation(directory,client,timeout=180,output_tokens=2048,request_budget=12,live_progress=False):
    """Real model, disposable evidence only. Explicit diagnostic request budget."""
    import hashlib
    from scripts.diagnose_investigative_memory import synthetic_case
    from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
    from forensic_assistant.conversational_ai.service import Session,Paused
    from forensic_assistant.conversational_ai.workspace import reconstruct
    path,sid,before=synthetic_case(directory)
    scope=authorize(path,[sid],'2020-01-01T00:00:00Z','2020-01-02T00:00:00Z',FAMILIES,'local',client.model_name,
        {'requests':request_budget,'provider_seconds':timeout,'output_tokens':output_tokens},local=client.conversation_binding())
    from forensic_assistant.conversational_ai.progress_display import ProgressDisplay
    display=ProgressDisplay(sys.stderr,log_path=Path(directory)/'progress.txt') if live_progress else None
    try:session=Session(scope,client,lambda _:True,checkpoint_seconds=.01,emit=display)
    except BaseException:
        if display:display.close()
        raise
    reason='COMPLETED';answer={};failure={}
    try:
        answer=session.submit('Investigate this synthetic recorded activity without assuming compromise. Inspect originals and independently verify important fields. Use investigative memory to review search coverage and verification history. Distinguish observations, hypotheses and incomplete coverage in your final assessment.',intent='broad')
    except Paused as exc:
        reason=str(exc);cause=exc.__cause__
        failure=dict(category=getattr(cause,'category',None),stage=getattr(cause,'stage',None),diagnostic=getattr(cause,'metadata',{}))
    finally:
        try:session.close(reason)
        finally:
            if display:display.close()
    rebuilt=reconstruct(session.journal.path,Path(directory)/'reconstructed')
    from forensic_assistant.conversational_ai.operation_diagnostics import operation_trace
    trace=operation_trace(session.journal.path)
    if reason=='REPEATED_TOOL_FAILURE':
        failure=dict(category='repeated_tool_failure',stage='tool_operations',diagnostic=trace['repeated_failure'])
    return dict(provider='Configured local provider on synthetic evidence',diagnostic_request_ceiling=request_budget,
        journal=str(session.journal.path),operation_trace=trace['operations'],provider_diagnostics=trace['provider_diagnostics'],
        timing=dict(workspace_persistence_seconds=session.persistence_seconds,forensic_worker_seconds=session.worker_seconds,
            inference_seconds=session.inference_seconds,measurement_seconds=session.used['measurement_seconds'],progress_assessment_seconds=session.used['progress_assessment_seconds'],
            other_active_seconds=max(0,session.used['active_seconds']-session.inference_seconds-session.worker_seconds-session.used['measurement_seconds']-session.persistence_seconds)),
        timing_limitation='Operation durations include validation and bookkeeping; inference includes transport, not pure generation. No generation throughput inferred.',
        outcome=reason,normal_termination=reason=='COMPLETED',provider_final_response=session.completion_assessment is not None,completion_assessment=session.completion_assessment,failure=failure,capacity=session.last_capacity,endpoint=client.conversation_binding()['endpoint'],model=client.model_name,usage=session.used,workspace=rebuilt,interpretation=answer.get('interpretation'),
        checks=dict(case_unchanged=hashlib.sha256(path.read_bytes()).hexdigest()==before,worker_closed=session.worker.process.poll() is not None),
        observations=dict(original_inspection=session.used['original_rehydrations']>0,verification=rebuilt['counts']['verifications']>0,
            memory_retrieval=session.used['memory_operations']>0,context_consolidation=session.used['context_consolidations']>0,
            automatic_checkpoint=session.used['automatic_checkpoints']>0,final_response=bool(answer.get('interpretation'))),
        limitation='Diagnostic scope/request ceiling only, not a production quota. Inspect missing capabilities before real-case acceptance.')


def retained(directory, run):
    """Fresh private synthetic output only. Never adopt an existing directory."""
    from forensic_assistant.investigation_ai.storage import DirectoryGuard,local_path
    from forensic_assistant.investigation_ai.snapshot import _private_mkdir
    path=local_path(Path(directory).absolute())
    with DirectoryGuard(path.parent):
        _private_mkdir(path)
        with DirectoryGuard(path):
            (path/'SYNTHETIC_ONLY.txt').write_text('Synthetic diagnostic artifacts, not original forensic evidence. May contain model output. Review before sharing.\n',encoding='utf-8')
            try:result=run(path)
            except Exception as exc:
                result=dict(error=getattr(exc,'category','diagnostic_failed'),stage=getattr(exc,'stage','diagnostic'),no_fallback=True,diagnostic=getattr(exc,'metadata',{}))
            for name,value in (('diagnostic.json',result),('operation-trace.json',result.get('operation_trace',[])),('provider-diagnostics.json',result.get('provider_diagnostics',[]))):
                with (path/name).open('x',encoding='utf-8') as stream:json.dump(value,stream,indent=2)
            return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mock',action='store_true');p.add_argument('--endpoint');p.add_argument('--model')
    p.add_argument('--context',type=int,default=32768);p.add_argument('--timeout',type=int,default=180)
    p.add_argument('--output-tokens',type=int,default=512);p.add_argument('--context-bytes',type=int,default=28000)
    p.add_argument('--tokenization',action='store_true',help='Harmless template/tokenizer diagnostic with two explicit inference parity requests')
    p.add_argument('--full-catalog',action='store_true',help='Production tool grammar; no evidence access or tool execution')
    p.add_argument('--synthetic-investigation',action='store_true',help='Use the real local model on a disposable synthetic case (12-request diagnostic budget)')
    p.add_argument('--output-dir',help='Fresh private retained synthetic output directory; never overwritten')
    p.add_argument('--diagnostic-requests',type=int,default=12,help='Synthetic investigation request budget only (default 12)')
    p.add_argument('--progress',action='store_true',help='Synthetic diagnostic liveness and counters on stderr; stdout remains JSON')
    args=p.parse_args()
    if args.progress and (not args.synthetic_investigation or args.mock):p.error('--progress requires --synthetic-investigation')
    if args.diagnostic_requests<1:p.error('Diagnostic request budget must be positive')
    if args.output_dir and (not args.synthetic_investigation or args.mock or args.tokenization or args.full_catalog):p.error('--output-dir requires --synthetic-investigation')
    if not args.mock and not (args.endpoint and args.model):p.error('Use --mock or --endpoint and --model')
    try:
        if args.mock:
            with tempfile.TemporaryDirectory(prefix='locard-local-protocol-') as tmp:result=simulated(tmp,args.context_bytes)
            result['journal']='Temporary synthetic journal removed after validation'
        else:
            client=ModelBackend.local_conversation(args.endpoint,args.model,args.context)
            if args.tokenization:result=tokenization_probe(client,args.timeout,args.output_tokens)
            elif args.full_catalog:result=full_catalog(client,args.timeout,args.output_tokens)
            elif args.synthetic_investigation:
                run=lambda tmp:synthetic_investigation(tmp,client,args.timeout,args.output_tokens,args.diagnostic_requests,args.progress)
                if args.output_dir:result=retained(args.output_dir,run)
                else:
                    with tempfile.TemporaryDirectory(prefix='locard-local-synthetic-') as tmp:result=run(tmp)
            else:result=probe(client,args.timeout,args.output_tokens)
    except Exception as exc:
        result={'error':getattr(exc,'category','diagnostic_failed'),'stage':getattr(exc,'stage','configuration'),'no_fallback':True,'diagnostic':getattr(exc,'metadata',{})}
    print(json.dumps(result,indent=2))
    return 0 if successful(result) else 1


if __name__=='__main__':raise SystemExit(main())

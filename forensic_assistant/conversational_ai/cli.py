"""Terminal adapter only; application service is UI independent."""
import json,sys
from .contracts import authorize,FAMILIES,DEFAULTS,catalog
from .service import Session,Paused
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.terminal import safe_span_text


def configure(commands):
    p=commands.add_parser('conversation-chat',help='Converse with an evidence-using AI investigator')
    p.add_argument('--local-endpoint',help='Explicit loopback llama.cpp HTTP endpoint; no cloud fallback')
    p.add_argument('--local-model',help='Exact server model identifier/alias')
    p.add_argument('--local-context',type=int,default=32768,help='Server context tokens; must match server allocation')
    p.add_argument('--local-temperature',type=float,default=0.2,help='Local sampling temperature 0..2')
    p.add_argument('--local-parallel-tools',action='store_true',help='Permit multiple native calls; execution remains sequential')
    p.add_argument('--checkpoint-seconds',type=int,default=600,help='Durable checkpoint interval; continues within approval by default')
    p.add_argument('--pause-at-checkpoint',action='store_true',help='Require analyst continuation at periodic checkpoints')
    p.add_argument('--progress-seconds',type=int,default=30,help='Elapsed activity reporting interval; not an execution deadline')
    p.add_argument('--source',action='append',help='Approved source ID; repeat for multiple sources')
    p.add_argument('--start',help='Inclusive approved UTC/offset timestamp')
    p.add_argument('--end',help='Exclusive approved UTC/offset timestamp')
    p.add_argument('--artifact',action='append',choices=FAMILIES,help='Approved family; default all supported families')
    p.add_argument('--max-seconds',type=int,default=DEFAULTS['active_seconds'],help='Active investigation seconds; excludes analyst idle time')
    p.add_argument('--max-requests',type=int,default=DEFAULTS['requests'],help='Session provider-request ceiling')
    p.add_argument('--max-operations',type=int,default=None,help='Optional session forensic/notebook operation budget')
    for option,key in [('max-tokens','tokens'),('max-records','records'),('max-disclosure-bytes','disclosure_bytes'),
                       ('provider-seconds','provider_seconds'),('tool-seconds','tool_seconds'),
                       ('request-bytes','request_bytes'),('result-bytes','result_bytes'),('output-tokens','output_tokens')]:
        p.add_argument('--'+option,type=int,default=DEFAULTS[key],help='Optional budget' if key in ('tokens','records','disclosure_bytes') else 'Optional forensic operation deadline; default waiting without deadline' if key=='tool_seconds' else 'Per-operation technical safeguard')


def _run(args,read=None,write=None,provider=None):
    read=read or input;write=write or print
    if not sys.stdin.isatty() and read is input:raise ValueError('Conversational investigation requires an interactive terminal')
    if not getattr(args,'local_endpoint',None) and (getattr(args,'local_model',None) or getattr(args,'local_parallel_tools',False) or getattr(args,'local_context',32768)!=32768 or getattr(args,'local_temperature',0.2)!=0.2):
        write('Local options require --local-endpoint. No provider request was made.');return 2
    if provider is None and getattr(args,'local_endpoint',None):
        try:provider=ModelBackend.local_conversation(args.local_endpoint,args.local_model,args.local_context,args.local_temperature,args.local_parallel_tools)
        except ValueError:
            write('Invalid local configuration: use an HTTP loopback endpoint, explicit model identifier, context 4096..131072 and temperature 0..2. Remote/LAN endpoints are not supported; no provider request was made.');return 2
    provider=provider or ModelBackend()
    if provider.provider_name=='local' and not hasattr(provider,'_conversation_local'):
        write('Local conversation requires --local-endpoint and --local-model for an already running tool-capable llama.cpp server. No model is started or downloaded.');return 2
    if provider.provider_name not in ('openai','local'):raise ValueError('Conversational provider unsupported; no automatic fallback.')
    write('Locard Conversational Investigator')
    write('Provider: '+safe_span_text(provider.provider_name)+' | Model: '+safe_span_text(provider.model_name))
    sources=args.source or [read('Approved source ID: ').strip()]
    start=args.start or read('Approved start (UTC/offset ISO timestamp): ').strip()
    end=args.end or read('Approved end (exclusive UTC/offset ISO timestamp): ').strip()
    question=read('What are you investigating?\nAnalyst> ').strip()
    scope=authorize(args.db,sources,start,end,args.artifact or list(FAMILIES),provider.provider_name,provider.model_name,
                    dict(active_seconds=args.max_seconds,requests=args.max_requests,operations=args.max_operations,
                         tokens=args.max_tokens,records=args.max_records,disclosure_bytes=args.max_disclosure_bytes,
                         provider_seconds=args.provider_seconds,tool_seconds=args.tool_seconds,request_bytes=args.request_bytes,
                         result_bytes=args.result_bytes,output_tokens=args.output_tokens),
                    local=provider.conversation_binding() if provider.provider_name=='local' else None)
    def approve(value):
        write(authorization_text(value))
        write('Read-only tools: '+', '.join(t['function']['name'] for t in catalog())+'.')
        write('Sensitive local notebook: '+safe_span_text(value['case']+'.conversations'))
        return read(('Approve this investigation and loopback model disclosure? [y/N] ' if value.get('local') else 'Approve this investigation and external disclosure? [y/N] ')).strip().lower() in ('y','yes')
    def emit(event):
        if event['kind']=='interpretation':write('AI interpretation — unverified\n'+safe_span_text(event['text']))
        elif event['kind']=='activity':write(safe_span_text(event['text']))
        elif event['kind']=='progress':
            state=event['status'];elapsed=event['elapsed_seconds'];operation=safe_span_text(event['operation'])
            if state=='started':write(operation+'...')
            else:
                write(operation+': '+state+f' ({elapsed:.1f} seconds).'+(f" {event['processed']} records; {event['groups']} groups." if 'processed' in event else ''))
                if state in ('slow','waiting'):write('Computational progress unavailable. Continue waiting or press Ctrl+C to interrupt.')
        elif event['kind']=='tool_failure':write('Operation unsuccessful: '+safe_span_text(event['code'])+'. No evidence result accepted.')
        elif event['kind']=='verified_observation':
            value=event['value'];write('Verified original-field observation\n'+safe_span_text(json.dumps(value,ensure_ascii=False)))
        elif event['kind']=='paused':
            write('Investigation paused: '+safe_span_text(event['reason'])+'. Completed work retained. No automatic retry.')
            if event['reason']=='READ_VIEW_UNAVAILABLE':write('The original read view is unavailable. No further evidence or AI requests will run. Use /status or /exit, then authorize a fresh session.')
            else:write('Redirect the investigation, /status or /exit.')
        elif event['kind']=='completed':
            write('Session outcome: '+safe_span_text(event['reason'])+('. Cleanup confirmed.' if event['cleanup_confirmed'] else '. CLEANUP_LIMITATION: process cleanup could not be confirmed.'))
    if getattr(args,'progress_seconds',30)<=0:raise ValueError('Progress interval must be positive')
    write('Checkpoint policy: '+('pause for analyst' if getattr(args,'pause_at_checkpoint',False) else 'automatic continuation')+' every '+str(getattr(args,'checkpoint_seconds',600))+' active seconds.')
    session=Session(scope,provider,approve,emit=emit,progress_interval=getattr(args,'progress_seconds',30),checkpoint_seconds=getattr(args,'checkpoint_seconds',600),pause_at_checkpoint=getattr(args,'pause_at_checkpoint',False))
    write('Controls: /status, /summary, /exit; Ctrl+C interrupts active work; completed work is retained. Natural language changes priorities.')
    write('Notebook session: '+session.journal.id)
    try:
        while True:
            if question in ('/exit','/cancel'):break
            if question=='/summary':question='Give an interim assessment distinguishing verified observations, interpretations, hypotheses, unknowns and coverage limitations.'
            if question=='/status':write(status_text(session.status()))
            elif question:
                try:session.submit(question)
                except Paused:pass
            question=read('Analyst> ').strip()
    except (KeyboardInterrupt,EOFError):
        session.close('CANCELLED');write('Interrupted. Completed notebook history retained. Start a fresh authorized session to continue.')
    except Exception:
        session.close('STOPPED_AFTER_FAILURE');write('Conversation stopped safely. Review the retained notebook; no automatic retry was performed.')
        raise
    finally:session.close()
    write('Conversation ended. Notebook: '+safe_span_text(str(session.journal.path)))
    return 0


def run(args,read=None,write=None,provider=None):
    from forensic_assistant.ai.provider_diagnostics import ProviderFailure
    from forensic_assistant.investigation_ai.runner import WorkerError
    from forensic_assistant.investigation_ai.lifecycle import CleanupError
    write=write or print
    try:return _run(args,read=read,write=write,provider=provider)
    except (ProviderFailure,WorkerError,CleanupError,ValueError,OSError) as exc:
        if isinstance(exc,ProviderFailure):message=str(exc)
        elif isinstance(exc,CleanupError):message='CLEANUP_LIMITATION: worker cleanup could not be confirmed.'
        else:message='Conversation stopped: '+type(exc).__name__+'. Review the retained notebook/session audit; no automatic retry.'
        write(safe_span_text(message))
        return 2
    except Exception as exc:
        from forensic_assistant.ai.provider_diagnostics import record
        from .diagnostics import detail
        if provider is not None:
            record(provider.provider_name,provider.model_name,'response_parse','conversation_adapter',operation='conversation',metadata={'conversation':detail('cli',exc)})
        else:
            from forensic_assistant.session_recording import record as audit
            audit('diagnostic',dict(component='conversation',category='internal_adapter_error',location='cli',exception_class=detail('cli',exc)['exception_class']),required=True)
        raise


def authorization_text(value):
    from pathlib import Path
    limits=value['limits']
    def budget(k):return 'No session limit' if limits[k] is None else str(limits[k])
    lines=['Proposed investigation', 'Case: '+Path(value['case']).parent.name,
           'Sources: '+', '.join(value['source_ids']), 'Time: '+value['start']+' through '+value['end']+' (end exclusive)',
           'Evidence: '+', '.join(value['families']), 'Access: Read-only',
           'AI provider: '+value['provider'], 'Model: '+value['model'],
           'Relevant scoped evidence and analyst context may be transmitted to the approved provider, including repeated history.',
           'No cumulative disclosure budget selected.' if limits['disclosure_bytes'] is None else 'Cumulative disclosure budget: '+str(limits['disclosure_bytes'])+' bytes of message content.',
           'Investigation duration (active seconds): '+budget('active_seconds'),'AI requests: '+budget('requests'),
           'Forensic operations: '+budget('operations'),'Tokens: '+budget('tokens'),'Distinct records: '+budget('records'),
           'Financial budget: Not configured; cost unavailable.',
           'Forensic operation deadline: '+('none (wait or interrupt)' if limits['tool_seconds'] is None else str(limits['tool_seconds'])+' seconds')+'. Technical safeguards remain active. Periodic checkpoints continue within approval unless pause-at-checkpoint was selected.',
           'Record eligibility follows the approved window; labeled out-of-window record context may also be disclosed.',
           'Ctrl+C cancels active work. Redirection is available at the next analyst prompt.']
    if value.get('local'):
        from .resources import request_capacity
        capacity,output,basis=request_capacity(value['model'],limits,value['local'])
        lines.extend(['Local endpoint: '+value['local']['endpoint']+' (loopback only; no proxy, redirects or cloud fallback)',
            'Configured context: '+str(value['local']['context_tokens'])+' tokens; output reserve: '+str(output),
            'Independent serialized request ceiling: '+str(capacity)+' bytes; '+basis,
            'Auxiliary template/tokenizer requests may repeat approved local evidence; charged separately, with no verification authority.',
            'Local server is analyst-owned; disconnecting Locard cannot confirm server-side generation cancellation.'])
    return safe_span_text('\n'.join(lines))


def status_text(value):
    return safe_span_text('Investigation activity\n'+'\n'.join('  '+label+': '+str(value.get(key,'unavailable')) for label,key in (
        ('Active seconds','active_seconds'),('Auxiliary context requests','auxiliary_requests'),('Auxiliary disclosure bytes','auxiliary_bytes'),('Context measurement seconds','measurement_seconds'),('Analyst idle seconds','idle_seconds'),('AI requests','requests'),
        ('Successful tools (including notes)','successful_operations'),('Successful forensic operations','successful_forensic_operations'),('Failed operations','failed_operations'),
        ('Workspace retrievals','memory_operations'),('Original inspection pages','original_rehydrations'),('Automatic checkpoints','automatic_checkpoints'),('Context consolidations','context_consolidations'),('Workspace items projected','workspace_items_projected'),
        ('Evidence retrieved','records_retrieved'),('Evidence disclosed','records_disclosed'),
        ('Reported input tokens','input_tokens'),('Reported output tokens','output_tokens'),('Reported total tokens','tokens'),
        ('Requests with unknown total usage','unknown_usage'),('Unknown input usage','unknown_input_usage'),('Unknown output usage','unknown_output_usage'),('Uncertain provider outcomes','uncertain_requests'),('Repeated evidence-result bytes','evidence_bytes'),('Repeated memory-result bytes','memory_result_bytes'),
        ('External message-content bytes','disclosure_bytes'),('Serialized request-content bytes','request_bytes'),('Optional budgets','optional_budgets')))+
        '\n  Estimated API cost: unavailable (not zero; no billing cap)')

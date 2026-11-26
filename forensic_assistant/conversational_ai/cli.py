"""Terminal adapter only; application service is UI independent."""
import json,sys
from .contracts import authorize,FAMILIES,DEFAULTS
from .service import Session
from forensic_assistant.ai.backend import ModelBackend
from forensic_assistant.terminal import safe_span_text


def configure(commands):
    p=commands.add_parser('conversation-chat',help='Converse with an evidence-using AI investigator')
    p.add_argument('--source',action='append',help='Approved source ID; repeat for multiple sources')
    p.add_argument('--start',help='Inclusive approved UTC/offset timestamp')
    p.add_argument('--end',help='Exclusive approved UTC/offset timestamp')
    p.add_argument('--artifact',action='append',choices=FAMILIES,help='Approved family; default all supported families')
    p.add_argument('--max-seconds',type=int,default=DEFAULTS['active_seconds'],help='Active investigation seconds; excludes analyst idle time')
    p.add_argument('--max-requests',type=int,default=DEFAULTS['requests'],help='Session provider-request ceiling')
    p.add_argument('--max-operations',type=int,default=DEFAULTS['operations'],help='Session forensic/notebook tool ceiling')


def _run(args,read=None,write=None,provider=None):
    read=read or input;write=write or print
    if not sys.stdin.isatty() and read is input:raise ValueError('Conversational investigation requires an interactive terminal')
    provider=provider or ModelBackend()
    if provider.provider_name!='openai':raise ValueError('Conversational provider unsupported; select OpenAI explicitly. No automatic cloud fallback.')
    write('Locard Conversational Investigator')
    write('Provider: '+safe_span_text(provider.provider_name)+' | Model: '+safe_span_text(provider.model_name))
    sources=args.source or [read('Approved source ID: ').strip()]
    start=args.start or read('Approved start (UTC/offset ISO timestamp): ').strip()
    end=args.end or read('Approved end (exclusive UTC/offset ISO timestamp): ').strip()
    question=read('What are you investigating?\nAnalyst> ').strip()
    scope=authorize(args.db,sources,start,end,args.artifact or list(FAMILIES),provider.provider_name,provider.model_name,
                    dict(active_seconds=args.max_seconds,requests=args.max_requests,operations=args.max_operations))
    def approve(value):
        write('Proposed investigation scope\n'+safe_span_text(json.dumps(value,ensure_ascii=False,indent=2)))
        write('Read-only tools: search_evidence, show_evidence, timeline, around, verify_observation, note.')
        write('Sensitive local notebook: '+safe_span_text(value['case']+'.conversations'))
        return read('Approve this investigation and external disclosure? [y/N] ').strip().lower() in ('y','yes')
    def emit(event):
        if event['kind']=='interpretation':write('AI interpretation — unverified\n'+safe_span_text(event['text']))
        elif event['kind']=='activity':write(safe_span_text(event['text']))
        elif event['kind']=='verified_observation':
            value=event['value'];write('Verified original-field observation\n'+safe_span_text(json.dumps(value,ensure_ascii=False)))
        elif event['kind']=='completed':
            write('Session outcome: '+safe_span_text(event['reason'])+('. Cleanup confirmed.' if event['cleanup_confirmed'] else '. CLEANUP_LIMITATION: process cleanup could not be confirmed.'))
    session=Session(scope,provider,approve,emit=emit)
    write('Controls: /summary, /exit; Ctrl+C cancels active work and closes this session. Natural language changes priorities.')
    write('Notebook session: '+session.journal.id)
    try:
        while True:
            if question in ('/exit','/cancel'):break
            if question=='/summary':question='Give an interim assessment distinguishing verified observations, interpretations, hypotheses, unknowns and coverage limitations.'
            if question:session.submit(question)
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

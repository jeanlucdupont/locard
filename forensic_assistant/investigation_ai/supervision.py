"""Lifecycle supervision of the existing controller, not a second tool engine.

The entire production investigation runs in a disposable process. A shared
monotonic deadline covers blocked Python/SQLite/model/transcript operations.
Only analyst approval is relayed to the owning terminal. No model dispatch here.
"""
from dataclasses import asdict
import json
import logging
from .diagnostics import LOG, PHASES
import multiprocessing
import os
import queue
import threading
import time
import uuid

from forensic_assistant import activity
from forensic_assistant.llm.client import LocalClient
from forensic_assistant.ai.backend import ModelBackend
from .state import Budget
from .timing import ExecutionClock, APPROVAL_SECONDS
from .lifecycle import WorkerJob

CLEANUP_SECONDS = 5.0


class SynthesisDeadline:
    """Request-specific parent timer; ordinary status traffic cannot renew it."""
    def __init__(self, model_deadline):
        self.model_deadline=model_deadline
        self.deadline=None
        self.ordinal=0
    def update(self, value, now):
        if not isinstance(value,dict):return
        if value.get('phase')=='synthesis':
            ordinal=value.get('ordinal');started=value.get('started')
            if type(ordinal) is not int or ordinal!=self.ordinal+1 or ordinal>2 or self.deadline is not None:
                raise ValueError('Invalid synthesis phase sequence')
            if type(started) not in (int,float) or not 0<=started<=now:raise ValueError('Invalid synthesis clock')
            self.ordinal=ordinal
            self.deadline=min(started+30,self.model_deadline)
        elif value.get('phase')=='synthesis_complete':
            if value.get('ordinal')!=self.ordinal or self.deadline is None:raise ValueError('Invalid synthesis completion')
            self.deadline=None
    def expired(self, now):
        return self.deadline is not None and now>=self.deadline
STARTUP_REASONS = frozenset(('AUTHORIZATION_EXPIRED','AUTHORIZATION_INVALID','AUTHORIZATION_CASE_CHANGED',
                           'PROVIDER_SCOPE_CHANGED','ADDITIONAL_SCOPE_REQUIRED','READ_VIEW_INCONSISTENT'))


class Launch:
    """Bound the caller's wait for OS process startup, without releasing its gate.

    A stuck launcher cannot be killed as a Python thread. If it does not settle
    during cleanup, the caller must raise CleanupError rather than resume a shell.
    A late child independently refuses its expired gate/deadline.
    """
    def __init__(self, process):
        self.done = threading.Event()
        self.error = None
        def launch():
            try:
                process.start()
            except BaseException as exc:
                self.error = exc
            finally:
                self.done.set()
        self.thread = threading.Thread(target=launch, daemon=True)

    def wait(self, deadline):
        while not self.done.wait(min(.05, max(0, deadline-time.monotonic()))):
            if time.monotonic() >= deadline:
                raise TimeoutError('Process startup deadline reached')
        if self.error is not None:
            raise self.error


def _child(connection, gate, request):
    # Do not perform IO or launch descendants before the parent contains us.
    if request['config'].get('_stage_a'):
        if not gate.wait(max(0, request['config']['_deadline']-time.monotonic())):
            return
        if time.monotonic() >= request['config']['_deadline']:
            return
        if request.get('_startup_cancelled') is not None and request['_startup_cancelled'].is_set():
            return
    else:
        gate.wait()
    if os.name != 'nt':
        os.setsid()
    from .controller import run
    if request['config'].get('_debug_startup'):
        logging.basicConfig(level=logging.WARNING, format='%(message)s')
        LOG.setLevel(logging.DEBUG)
    request['config']['_execution_clock'] = request['_execution_clock']
    request['config']['_approval_clock_managed'] = True
    request['config']['_startup_complete'] = lambda: connection.send_bytes(b'{"kind":"startup_complete"}')
    if request['config'].get('_stage_a'):
        request['config']['_stage_a_checkpoint'] = lambda value: connection.send_bytes(json.dumps({'kind':'stage_a_checkpoint','value':value}).encode())
    request['config']['_status'] = lambda phase: connection.send_bytes(json.dumps({'kind': 'status', 'phase': phase}).encode())
    from forensic_assistant.ai import raw_diagnostics
    raw_diagnostics.sink = lambda item: connection.send_bytes(json.dumps({'kind':'raw_diagnostic','entry':item}).encode())
    def approve(proposal, seconds):
        connection.send_bytes(json.dumps({'kind': 'approval', 'proposal': proposal}).encode())
        reply = json.loads(connection.recv_bytes(128))
        if type(reply) is not dict or set(reply) != {'approved', 'wait_seconds'} or type(reply['approved']) is not bool:
            raise ValueError('Invalid approval response')
        request['_execution_clock'].credit_wait(reply['wait_seconds'])
        return reply['approved']
    try:
        request['config']['_status']('audit_init')
        session = activity.Session(request['config']['case_path'])
        session.id = request['session_id']
        request['config']['_status']('provider_init')
        client = ModelBackend.restore(request['backend']) if request.get('backend') else LocalClient(request['endpoint'])
        with activity.bind(session):
            result = run(request['config'], request['question'], request['root'],
                         budget=Budget(**request['budget']),
                         client=client, dry_run=request['dry_run'],
                         approval=approve if request['approval'] else None)
        connection.send_bytes(json.dumps({'kind': 'result', 'result': result}).encode())
    except BaseException as exc:
        # No raw exception text/evidence is sent to the audit channel.
        from .lifecycle import CleanupError
        if isinstance(exc, CleanupError) and hasattr(exc, 'result'):
            connection.send_bytes(json.dumps({'kind': 'cleanup_failure', 'result': exc.result}).encode())
        else:
            reason = str(exc) if request['config'].get('_stage_a') and str(exc) in STARTUP_REASONS else None
            connection.send_bytes(json.dumps({'kind': 'error', 'type': type(exc).__name__,
                                             **({'reason':reason} if reason is not None else {})}).encode())
    finally:
        raw_diagnostics.clear()
        connection.close()


def _marker(request, result):
    """Bounded recovery process; never overwrite a chain or existing marker."""
    from .storage import DirectoryGuard, local_path
    from .transcript import ID
    identity = result['investigation_id']
    if not ID.fullmatch(identity):
        raise ValueError('Invalid investigation ID')
    path = local_path(request['root']) / identity
    # Only an already-created, matching investigation can receive a marker.
    with DirectoryGuard(path):
        manifest = local_path(path / 'manifest.json')
        with manifest.open('rb') as stream:
            raw = stream.read(65537)
        manifest_data = json.loads(raw)
        if len(raw) > 65536 or manifest_data['investigation_id'] != identity:
            raise ValueError('Investigation identity mismatch')
        pending = (manifest_data.get('tool_calls') or [{}])[-1]
        linkage = {}
        from .contracts import TOOLS
        if pending.get('tool') in TOOLS and type(pending.get('tool_call_number')) is int and 1 <= pending['tool_call_number'] <= 16:
            linkage = {k: pending[k] for k in ('tool', 'tool_call_number')}
        with (path / 'termination.json').open('xb') as stream:
            stream.write(json.dumps({'derived_data': True, 'investigation_id': identity,
                                     'termination': result['termination'],
                                     **({'startup_diagnostic':result['startup_diagnostic']} if request['config'].get('_stage_a') else {}),
                                     'transcript_complete': False, **linkage,
                                     'interrupted_tool_status': pending.get('status') if pending.get('status') in
                                     ('proposed', 'approved', 'policy_authorized', 'executed', 'rejected', 'failed') else 'unknown'}).encode())
            stream.flush()
            os.fsync(stream.fileno())
    session = activity.Session(request['config']['case_path'])
    session.id = request['session_id']
    if linkage and pending.get('status') in ('proposed', 'approved', 'policy_authorized'):
        session.record('TOOL_REJECTED' if pending['status'] == 'proposed' else 'TOOL_FAILED', 'failure',
                       investigation_id=identity, **linkage, reason='interrupted_outcome_unknown', required=True)
    session.record('INVESTIGATION_TERMINATION', 'failure', investigation_id=identity,
                   termination=result['termination'], transcript_complete=False, required=True)


def _recover(request, result):
    if time.monotonic() >= request.get('_cleanup_deadline', float('inf')):
        return
    try:
        _marker(request, result)
    except BaseException:
        try:
            session = activity.Session(request['config']['case_path'])
            session.id = request['session_id']
            session.record('INVESTIGATION_TERMINATION', 'failure', required=True,
                           investigation_id=result['investigation_id'], termination=result['termination'],
                           transcript_complete=False, recovery='unavailable')
        except BaseException:
            pass
        os._exit(2)  # Parent reports incomplete recovery, never an unbounded retry.


def _stop(process, job, deadline):
    if job:
        job.close_confirmed(seconds=max(0, deadline - time.monotonic()))
    elif process.is_alive():
        if os.name != 'nt':
            import signal
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.kill()
    process.join(timeout=max(0, deadline - time.monotonic()))
    return not process.is_alive()


def run(config, question, transcript_root, *, budget=None, client=None, dry_run=False, approval=None, status=None, prepared_backend=None, **testing):
    # Explicit dependency injection is retained for deterministic in-process tests.
    # Production clients cross the disposable-worker boundary by descriptor.
    if testing or (client is not None and not isinstance(client, (LocalClient, ModelBackend))):
        from .controller import run as controlled
        return controlled({**config, '_status': status}, question, transcript_root, budget=budget, client=client,
                          dry_run=dry_run, approval=approval, **testing)
    budget = budget or Budget()
    client = client or ModelBackend()
    if isinstance(client, ModelBackend) and client.provider_name != 'local':
        from forensic_assistant.ai.backend import STATUS
        if not config.get('_stage_a'):
            client.prepare(STATUS.get())  # Cloud certification precedes the forensic clock.
    started = config.get('_stage_a_started', time.monotonic()) if config.get('_stage_a') else time.monotonic()
    deadline = min(started + budget.seconds, config.get('_stage_a_deadline', float('inf'))) if config.get('_stage_a') else started + budget.seconds
    b2=config.get('_stage_a',{}).get('contract')=='investigation-s4-b2-authorization-v1'
    overall=deadline
    if b2:
        overall=min(overall,time.monotonic()+max(0,config['_stage_a']['expires']-time.time()))
        deadline=overall-5
    synthesis_clock=SynthesisDeadline(overall-20)
    finalizing=False
    context = multiprocessing.get_context('spawn')
    clock = ExecutionClock(started, deadline)
    identity = uuid.uuid4().hex
    client = client or ModelBackend()
    descriptor = None
    if isinstance(client, ModelBackend):
        # Persistent owner must start outside the disposable investigation job.
        client.config = {**client.config, 'startup_seconds': min(client.config['startup_seconds'], max(1, int(budget.seconds)))}
        from forensic_assistant.ai.backend import STATUS
        # Investigation dry-run still requests one model proposal; only tool
        # execution is suppressed. Its owner must also stay outside this job.
        if not config.get('_stage_a'):
            client.prepare(STATUS.get())
        if config.get('_stage_a') and prepared_backend is None:
            raise ValueError('Stage A requires a provider descriptor captured before authorization')
        descriptor = prepared_backend if prepared_backend is not None else client.descriptor()
        from forensic_assistant.llm.client import endpoint_parts
        client.host, client.port = endpoint_parts(client.endpoint or 'http://127.0.0.1:8080')
    host = '[' + client.host + ']' if ':' in client.host else client.host
    session = activity.CURRENT.get()
    request = dict(config={**config, '_deadline': deadline, '_started': started, '_investigation_id': identity},
                   question=question, root=str(transcript_root), budget=asdict(budget),
                   backend=descriptor, endpoint=f'http://{host}:{client.port}', dry_run=dry_run, approval=approval is not None,
                   session_id=session.id if session else str(uuid.uuid4()))
    request['_execution_clock'] = clock
    parent, child = context.Pipe()
    gate = context.Event()
    startup_cancelled = context.Event() if config.get('_stage_a') else None
    if startup_cancelled is not None:request['_startup_cancelled'] = startup_cancelled
    process = context.Process(target=_child, args=(child, gate, request))
    messages = queue.Queue(maxsize=4)
    job = None
    result = None
    stage_a_checkpoint = None
    reason = 'WORKER_START_FAILURE'
    startup_complete = False
    child_cleanup_failed = False
    current_phase = 'supervisor_start' if config.get('_stage_a') else 'preparing'
    launcher = None
    request['config']['_debug_startup'] = LOG.isEnabledFor(logging.DEBUG)
    def receive():
        try:
            while True:
                raw = parent.recv_bytes(4 * 1024 * 1024)
                messages.put(json.loads(raw), timeout=.1)
        except (EOFError, OSError, ValueError, queue.Full):
            pass
    try:
        spawn_started = time.perf_counter()
        if config.get('_stage_a'):
            if status is not None:status(current_phase)
            if clock.remaining() <= 0:raise TimeoutError('Authorization startup deadline reached')
            launcher = Launch(process)
            launcher.thread.start()
            launcher.wait(deadline)
        else:
            process.start()
        LOG.debug("investigate-ai startup stage=supervisor_start elapsed=%.6fs", time.perf_counter()-spawn_started)
        child.close()
        job = WorkerJob(process.pid) if os.name == 'nt' else None
        gate.set()
        reader = threading.Thread(target=receive, daemon=True)
        reader.start()
        decomposition_deadline = None
        s4 = isinstance(config.get('_stage_a'), dict) and config['_stage_a'].get('contract') in ('investigation-s4-authorization-v1','investigation-s4-b2-authorization-v1')
        while clock.remaining() > 0:
            if b2 and (synthesis_clock.expired(time.monotonic()) or (not finalizing and time.monotonic()>=overall-20)):
                reason='SYNTHESIS_TIMEOUT' if synthesis_clock.expired(time.monotonic()) else 'MODEL_PHASE_TIMEOUT'
                break
            if decomposition_deadline is not None and time.monotonic() >= decomposition_deadline:
                reason = 'DECOMPOSITION_TIMEOUT'
                break
            try:
                message = messages.get(timeout=min(.05, max(.001, clock.remaining())))
            except queue.Empty:
                if not process.is_alive():
                    break
                continue
            if message['kind'] == 'stage_a_checkpoint' and request['config'].get('_stage_a'):
                stage_a_checkpoint = message['value']
                continue
            if message['kind'] == 'raw_diagnostic':
                from forensic_assistant.ai import raw_diagnostics
                raw_diagnostics.capture(message.get('entry'))
                continue
            if message['kind'] == 'status':
                phase = message.get('phase')
                if b2 and isinstance(phase,dict):
                    synthesis_clock.update(phase,time.monotonic())
                    continue
                if b2 and phase=='finalization':finalizing=True
                if s4:
                    if phase == 'decomposition':
                        decomposition_deadline = min(overall-20 if b2 else deadline-15, time.monotonic() + 30)
                        current_phase = phase
                    elif phase != 'decomposition':
                        decomposition_deadline = None
                if type(phase) is str and phase in PHASES | {'preparing', 'model', 'validation', 'operation', 'finalizing', 'approval'}:
                    current_phase = phase
                    LOG.debug('investigate-ai stage=%s elapsed=%.6f remaining=%.6f',phase,time.monotonic()-started,clock.remaining())
                if status is not None and type(phase) is str and phase in PHASES | {
                    'preparing', 'model', 'validation', 'operation', 'finalizing', 'approval'
                }:
                    status(phase)
                continue
            if message['kind'] == 'startup_complete':
                startup_complete = True
                continue
            if message['kind'] == 'approval':
                if clock.remaining() <= 0:
                    break
                if status is not None:
                    status('approval')
                prior_wait = clock.analyst_wait
                with clock.approval_wait():
                    try:
                        approved = approval(message['proposal'], APPROVAL_SECONDS)
                    except (EOFError, TimeoutError):
                        approved = False
                if clock.remaining() <= 0:
                    break
                parent.send_bytes(json.dumps({'approved': bool(approved), 'wait_seconds': clock.analyst_wait-prior_wait}).encode())
            elif message['kind'] == 'cleanup_failure':
                result = message['result']
                child_cleanup_failed = True
                break
            elif message['kind'] == 'result':
                result = message['result']
                break
            else:
                if message.get('type') == 'CleanupError':
                    child_cleanup_failed = True
                reason = ('AUDIT_FAILURE' if message.get('type') == 'AuditError' else
                          'TRANSCRIPT_FAILURE' if message.get('type') in ('OSError', 'PermissionError', 'FileExistsError') else 'WORKER_FAILURE')
                if config.get('_stage_a') and message.get('reason') in STARTUP_REASONS:
                    reason=message['reason']
                break
        if clock.remaining() <= 0:
            reason = 'MAX_SECONDS' if startup_complete else 'STARTUP_TIMEOUT'
            LOG.debug('investigate-ai watchdog=overall category=%s elapsed=%.6fs remaining=0', reason, time.monotonic()-started)
            result = None
    except KeyboardInterrupt:
        reason = 'ANALYST_CANCELLED' if config.get('_stage_a') else 'USER_SCOPE_REACHED'
    except TimeoutError:
        reason = 'STARTUP_TIMEOUT'
    except (OSError, ValueError):
        reason = 'WORKER_FAILURE' if startup_complete else 'WORKER_START_FAILURE'
    finally:
        cleanup_deadline = min(overall,time.monotonic()+CLEANUP_SECONDS) if b2 else time.monotonic()+CLEANUP_SECONDS
        cleaned = True
        if startup_cancelled is not None:
            startup_cancelled.set()
            gate.set()  # Late launch can exit, but its revoked gate cannot authorize IO.
        if launcher is not None and not launcher.done.is_set():
            launcher.done.wait(max(0, cleanup_deadline-time.monotonic()))
            cleaned = launcher.done.is_set()
        if process.pid is not None and (launcher is None or launcher.done.is_set()):
            try:
                cleaned = _stop(process, job, min(cleanup_deadline, time.monotonic() + 1))
            except (OSError, RuntimeError):
                cleaned = False
                if process.is_alive():
                    process.kill()
                    process.join(timeout=max(0, min(cleanup_deadline - time.monotonic(), 1)))
        parent.close()
        child.close()
    if result is None:
        result = dict(investigation_id=identity, termination=reason, derived_data=True,
                      findings={}, evidence_fingerprint=None,
                      state={'accepted_calls': None}, transcript_complete=False,
                      limitations=['Investigation interrupted; partial transcript is not a completed investigation.'],
                      metrics={**clock.metrics(), 'timeout_cause': ('final_integrity_timeout' if current_phase in ('final_fingerprint', 'fingerprint') and startup_complete else 'execution_budget_exhausted') if reason in ('MAX_SECONDS', 'STARTUP_TIMEOUT') else None})
        if stage_a_checkpoint is not None:
            result.update(stage_a_checkpoint)
            result['limitations'].append('Previously committed Stage A deltas retained; no restart continuation.')
            from .narrative import build
            result['narrative']=build(result['findings'],result['state'])
        if config.get('_stage_a'):
            result['engine']=('incremental-s4-b2-v1' if b2 else 'incremental-s4-a-v1' if config['_stage_a'].get('contract') == 'investigation-s4-authorization-v1'
                              else 'incremental-stage-a-v1')
            result['startup_diagnostic']=dict(last_phase=current_phase,read_view_established=startup_complete,
                elapsed_seconds=round(time.monotonic()-started,3),cleanup_confirmed=cleaned)
        recovery = context.Process(target=_recover, args=(request, result))
        request['_cleanup_deadline'] = cleanup_deadline
        recovery_launcher = None
        result['termination_recorded'] = False
        if cleaned and time.monotonic() < cleanup_deadline:
            recovery_job = None
            try:
                if config.get('_stage_a'):
                    recovery_launcher = Launch(recovery)
                    recovery_launcher.thread.start()
                    recovery_launcher.wait(cleanup_deadline)
                else:
                    recovery.start()
                recovery_job = WorkerJob(recovery.pid) if os.name == 'nt' else None
                recovery.join(timeout=max(0, cleanup_deadline - time.monotonic() - .25))
                result['termination_recorded'] = recovery.exitcode == 0
            except (OSError, RuntimeError):
                result['termination_recorded'] = False
            finally:
                if recovery_launcher is not None and not recovery_launcher.done.is_set():
                    recovery_launcher.done.wait(max(0,cleanup_deadline-time.monotonic()))
                    cleaned = cleaned and recovery_launcher.done.is_set()
                if recovery.pid is not None and (recovery_launcher is None or recovery_launcher.done.is_set()):
                    try:
                        if recovery.is_alive():
                            recovery.kill()
                        if recovery_job:
                            recovery_job.close()
                        recovery.join(timeout=max(0, cleanup_deadline - time.monotonic()))
                        cleaned = cleaned and not recovery.is_alive()
                    except (OSError, RuntimeError):
                        cleaned = False
    if config.get('_stage_a'):
        result['startup_diagnostic'] = dict(last_phase=current_phase,read_view_established=startup_complete,
            elapsed_seconds=round(time.monotonic()-started,3),cleanup_confirmed=cleaned and not child_cleanup_failed)
        if not startup_complete:
            result['limitations'].append('Startup stopped at '+current_phase+'. The supervisor did not confirm a valid evidence read view; no successful retrieval or analysis is claimed. Review this phase before retrying.')
    if not cleaned or child_cleanup_failed:
        from .lifecycle import CleanupError
        error = CleanupError('CLEANUP_LIMITATION: cannot confirm investigation worker cleanup; exit the shell')
        result.setdefault('cleanup', {'status': 'CLEANUP_LIMITATION', 'stage': 'supervisor'})
        LOG.error('investigate-ai cleanup=CLEANUP_LIMITATION stage=supervisor')
        error.result = result
        raise error
    result['metrics'].update(clock.metrics())
    return result

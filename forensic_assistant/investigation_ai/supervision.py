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
from .state import Budget
from .lifecycle import WorkerJob

CLEANUP_SECONDS = 5.0


def _child(connection, gate, request):
    # Do not perform IO or launch descendants before the parent contains us.
    gate.wait()
    if os.name != 'nt':
        os.setsid()
    from .controller import run
    if request['config'].get('_debug_startup'):
        logging.basicConfig(level=logging.WARNING, format='%(message)s')
        LOG.setLevel(logging.DEBUG)
    request['config']['_startup_complete'] = lambda: connection.send_bytes(b'{"kind":"startup_complete"}')
    request['config']['_status'] = lambda phase: connection.send_bytes(json.dumps({'kind': 'status', 'phase': phase}).encode())
    session = activity.Session(request['config']['case_path'])
    session.id = request['session_id']
    def approve(proposal, seconds):
        connection.send_bytes(json.dumps({'kind': 'approval', 'proposal': proposal}).encode())
        return json.loads(connection.recv_bytes(16)) is True
    try:
        with activity.bind(session):
            result = run(request['config'], request['question'], request['root'],
                         budget=Budget(**request['budget']),
                         client=LocalClient(request['endpoint']), dry_run=request['dry_run'],
                         approval=approve if request['approval'] else None)
        connection.send_bytes(json.dumps({'kind': 'result', 'result': result}).encode())
    except BaseException as exc:
        # No raw exception text/evidence is sent to the audit channel.
        connection.send_bytes(json.dumps({'kind': 'error', 'type': type(exc).__name__}).encode())
    finally:
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
        job.close()
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


def run(config, question, transcript_root, *, budget=None, client=None, dry_run=False, approval=None, status=None, **testing):
    # Explicit dependency injection is retained for deterministic in-process tests.
    # The CLI always constructs the real loopback LocalClient.
    if testing or (client is not None and not isinstance(client, LocalClient)):
        from .controller import run as controlled
        return controlled({**config, '_status': status}, question, transcript_root, budget=budget, client=client,
                          dry_run=dry_run, approval=approval, **testing)
    budget = budget or Budget()
    started = time.monotonic()
    deadline = started + budget.seconds
    identity = uuid.uuid4().hex
    client = client or LocalClient()
    host = '[' + client.host + ']' if ':' in client.host else client.host
    session = activity.CURRENT.get()
    request = dict(config={**config, '_deadline': deadline, '_started': started, '_investigation_id': identity},
                   question=question, root=str(transcript_root), budget=asdict(budget),
                   endpoint=f'http://{host}:{client.port}', dry_run=dry_run, approval=approval is not None,
                   session_id=session.id if session else str(uuid.uuid4()))
    context = multiprocessing.get_context('spawn')
    parent, child = context.Pipe()
    gate = context.Event()
    process = context.Process(target=_child, args=(child, gate, request))
    messages = queue.Queue(maxsize=4)
    job = None
    result = None
    reason = 'WORKER_START_FAILURE'
    startup_complete = False
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
        process.start()
        LOG.debug("investigate-ai startup stage=supervisor_start elapsed=%.6fs", time.perf_counter()-spawn_started)
        child.close()
        job = WorkerJob(process.pid) if os.name == 'nt' else None
        gate.set()
        reader = threading.Thread(target=receive, daemon=True)
        reader.start()
        while time.monotonic() < deadline:
            try:
                message = messages.get(timeout=min(.05, max(.001, deadline - time.monotonic())))
            except queue.Empty:
                if not process.is_alive():
                    break
                continue
            if message['kind'] == 'status':
                phase = message.get('phase')
                if status is not None and type(phase) is str and phase in PHASES | {
                    'preparing', 'model', 'validation', 'operation', 'finalizing', 'approval'
                }:
                    status(phase)
                continue
            if message['kind'] == 'startup_complete':
                startup_complete = True
                continue
            if message['kind'] == 'approval':
                if status is not None:
                    status('approval')
                approved = approval(message['proposal'], max(0, deadline - time.monotonic()))
                if time.monotonic() >= deadline:
                    break
                parent.send_bytes(json.dumps(bool(approved)).encode())
            elif message['kind'] == 'result':
                result = message['result']
                break
            else:
                reason = ('AUDIT_FAILURE' if message.get('type') == 'AuditError' else
                          'TRANSCRIPT_FAILURE' if message.get('type') in ('OSError', 'PermissionError', 'FileExistsError') else 'WORKER_FAILURE')
                break
        if time.monotonic() >= deadline:
            reason = 'MAX_SECONDS' if startup_complete else 'STARTUP_TIMEOUT'
            LOG.debug('investigate-ai watchdog=overall category=%s elapsed=%.6fs remaining=0', reason, time.monotonic()-started)
            result = None
    except KeyboardInterrupt:
        reason = 'USER_SCOPE_REACHED'
    except (OSError, ValueError):
        reason = 'WORKER_FAILURE' if startup_complete else 'WORKER_START_FAILURE'
    finally:
        cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
        cleaned = True
        if process.pid is not None:
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
                      metrics={'elapsed_seconds': time.monotonic() - started})
        recovery = context.Process(target=_recover, args=(request, result))
        result['termination_recorded'] = False
        if cleaned and time.monotonic() < cleanup_deadline:
            recovery_job = None
            try:
                recovery.start()
                recovery_job = WorkerJob(recovery.pid) if os.name == 'nt' else None
                recovery.join(timeout=max(0, cleanup_deadline - time.monotonic() - .25))
                result['termination_recorded'] = recovery.exitcode == 0
            except (OSError, RuntimeError):
                result['termination_recorded'] = False
            finally:
                if recovery.pid is not None:
                    try:
                        if recovery.is_alive():
                            recovery.kill()
                        if recovery_job:
                            recovery_job.close()
                        recovery.join(timeout=max(0, cleanup_deadline - time.monotonic()))
                        cleaned = cleaned and not recovery.is_alive()
                    except (OSError, RuntimeError):
                        cleaned = False
    if not cleaned:
        from .lifecycle import CleanupError
        error = CleanupError('CLEANUP_LIMITATION: cannot confirm investigation worker cleanup; exit the shell')
        result['termination'] = 'CLEANUP_LIMITATION'
        error.result = result
        raise error
    result['metrics']['elapsed_seconds'] = time.monotonic() - started
    return result

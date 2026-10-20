"""Model proposals never dispatch directly: validate, authorize, bound, then execute."""
from dataclasses import asdict
from contextlib import nullcontext
from .timing import ExecutionClock, APPROVAL_SECONDS
from datetime import datetime, timezone
import hashlib
import time
import uuid
from forensic_assistant.detections.engine import available_rules
from forensic_assistant.llm.client import LocalClient, LLMError
from . import contracts
from .diagnostics import Profile, LOG
from .rejection import diagnostic
from .runner import ForensicWorker, WorkerError
from .state import State, Budget, encoded
from .transcript import Transcript, digest
from forensic_assistant import activity

def validate_anchor(state, name, args, rules):
    if name == 'detections' and args['rule_id'] not in rules:
        raise ValueError('Rule not in frozen registry')
    eid = args.get('evidence_id')
    if eid is None:
        return
    # Merely retrieving a record does not authorize the model to name it.
    if eid not in state.exposed:
        raise ValueError('Anchor was not exposed to the model')
    record = state.exposed[eid]
    if name == 'process_tree' and record.get('kind') != 'process':
        raise ValueError('Process anchor required')
    if name == 'session' and record.get('kind') != 'logon':
        raise ValueError('Successful logon anchor required')

def run(config, question, transcript_root, **kwargs):
    # Production supervision supplies its own parent-owned directory so a killed
    # controller cannot strand the copy. Direct callers own it for this call.
    if config.get('_snapshot_dir'):
        return _run(config, question, transcript_root, **kwargs)
    from .snapshot import SnapshotDirectory
    with SnapshotDirectory() as snapshot:
        return _run({**config, '_snapshot_dir': str(snapshot.path)}, question, transcript_root, **kwargs)


def _run(
    config,
    question,
    transcript_root,
    *,
    budget=None,
    client=None,
    dry_run=False,
    approval=None,
    worker_factory=ForensicWorker
):
    if not isinstance(question, str) or not question.strip() or len(question.encode()) > 1000:
        raise ValueError('Question must be 1..1000 UTF-8 bytes')
    budget = budget or Budget()
    started = config.get('_started', time.monotonic())
    clock = config.get('_execution_clock') or ExecutionClock(started, config.get('_deadline', started + budget.seconds))
    status = config.get('_status') or (lambda phase: None)
    status('preparing')
    profile = Profile(lambda: clock.deadline)
    startup_complete = False
    state = State(budget)
    rules = [r.rule_id for r in available_rules()]
    config = {**config, 'rule_ids': rules}
    from forensic_assistant.ai.backend import backend
    client = client or backend()
    investigation_id = config.get('_investigation_id') or uuid.uuid4().hex
    with profile.phase('audit_init'):
        activity.event('INVESTIGATION_START', required=True, investigation_id=investigation_id)
    with profile.phase('transcript_init'):
        transcript = Transcript(
            transcript_root,
            {
                'started_utc': datetime.now(timezone.utc).isoformat(),
                'question': question,
                'budgets': asdict(budget),
                'tools': list(contracts.TOOLS),
                'rule_ids': rules,
                'dry_run': dry_run,
                'date_hint': config.get('date_hint')
            },
            investigation_id=investigation_id
        )
    worker = None
    fingerprint = None
    integrity = {}
    integrity_status = 'not_checked'
    integrity_reason = 'No baseline fingerprint available'
    integrity_elapsed = 0.0
    failed_lookup = {}
    final = None
    termination = 'INSUFFICIENT_EVIDENCE'
    feedback = ''
    model_metadata = []
    tool_time = model_time = 0.0
    timeout_cause = None
    prompt_sizes = []
    proposed_action = None
    call_number = 0
    call_metadata = None
    def audit(action, outcome='success', **data):
        activity.event(action, outcome, required=True, investigation_id=transcript.id, **data)
    def decision(status):
        if call_metadata is not None:
            call_metadata['status'] = status
            LOG.debug('lookup=%s status=%s', call_metadata['tool'], status)
            transcript._manifest()
    def rejection_record(decoded, stage, error):
        record = diagnostic(transcript.id, state.steps,
                            call_number if call_metadata is not None else None,
                            decoded, stage, error)
        if call_metadata is not None:
            # The existing decision() write persists this beside its audit linkage.
            call_metadata['diagnostic'] = record
        return record
    def remaining():
        return clock.remaining()
    def call(name, args=None):
        nonlocal fingerprint, tool_time, integrity, timeout_cause, integrity_status, integrity_reason, integrity_elapsed
        if remaining() <= 0:
            raise WorkerError('INVESTIGATION_TIMEOUT')
        checked_at = time.monotonic()
        if name == 'check':
            integrity_status, integrity_reason = 'check_failed', 'Final verification did not complete'
        try:
            if name == 'check':
                status('final_fingerprint')
            if isinstance(worker, ForensicWorker):
                worker.deadline = clock.deadline
            with profile.phase('final_fingerprint' if name == 'check' else 'initial_operation' if name == 'initial' else 'tool'):
                response = worker.call(
                    name,
                    args,
                    fingerprint=fingerprint,
                    known_ids=state.exposed,
                    # Full-case startup and completion hashes share the global deadline.
                    seconds=remaining() if name in ('initial', 'check') else min(budget.tool_seconds, remaining()),
                    question=question
                )
        except WorkerError as exc:
            if name == 'check':
                integrity_elapsed += time.monotonic()-checked_at
                integrity_status = 'changed' if 'EVIDENCE_STATE_CHANGED' in str(exc) else 'check_timed_out' if exc.timed_out or 'TIMEOUT' in str(exc) else 'check_failed'
                integrity_reason = {'changed':'Live case fingerprint changed', 'check_timed_out':'Final verification exceeded its deadline', 'check_failed':'Final verification worker could not complete the check'}[integrity_status]
            if exc.timed_out or 'TIMEOUT' in str(exc):
                timeout_cause = 'final_integrity_timeout' if name == 'check' else 'execution_budget_exhausted' if remaining() <= 0 else 'tool_timeout'
            if exc.integrity is not None:
                integrity = exc.integrity
            raise
        if response.get('integrity') is not None:
            integrity = response['integrity']
        if response.get('database_changes') != 0 or response.get('schema') not in (3, 4, 5):
            raise WorkerError('Evidence read-only/schema validation failed')
        if fingerprint is not None and response['fingerprint'] != fingerprint:
            raise WorkerError('EVIDENCE_STATE_CHANGED')
        if name != 'check':
            try:
                contracts.validate_output(response['result'])
            except ValueError as exc:
                raise WorkerError(str(exc)) from exc
        if name == 'check':
            integrity_status, integrity_reason = 'matched', 'Live case fingerprint matched'
            integrity_elapsed += time.monotonic()-checked_at
        fingerprint = response['fingerprint']
        tool_time += response['elapsed_seconds']
        return response
    try:
        with profile.phase('worker_start'):
            if remaining() <= 0:
                raise WorkerError('INVESTIGATION_TIMEOUT', stage='worker_start', timed_out=True)
            worker = worker_factory({k: v for k, v in {**config, '_deadline': clock.deadline}.items() if k not in ('_startup_complete', '_execution_clock', '_approval_clock_managed')})
        initial = call('initial')
        transcript.manifest.update(
            schema=initial['schema'],
            evidence_fingerprint=fingerprint,
            semantic_identity=initial.get('semantic_identity'),
            embedding_identity=initial.get('model_identity')
        )
        transcript.append('initial', initial)
        state.ingest(initial['result'])
        state.semantic += int(initial['result'].get('semantic_used', False))
        state.path.append({'operation': 'initial', 'new_records': len(state.records)})
        semantic_available = initial.get('semantic_available', False)
        if state.records:
            for step in range(budget.steps):
                state.steps = step + 1
                if remaining() <= 0:
                    termination = 'BUDGET_EXHAUSTED'
                    break
                names = state.applicable(semantic_available, rules)
                status('exposure')
                with profile.phase('exposure'):
                    messages, exposed, size = state.prompt(question, names, rules, feedback)
                    grammar = contracts.schema(names, state.browser_available)
                    if len(encoded(grammar).encode()) > 32768:
                        raise ValueError('Grammar byte budget exceeded')
                    transcript.append(
                        'exposure',
                        {
                            'step': state.steps,
                            'content': exposed,
                            'prompt_bytes': size,
                            'prompt_sha256': digest(messages),
                            'tools': names
                        }
                    )
                    state.disclose(exposed)
                prompt_sizes.append(size)
                if remaining() <= 0:
                    termination = 'MAX_SECONDS'
                    break
                # LocalClient applies a wall-clock socket watchdog as well as I/O timeouts.
                client.timeout = min(budget.tool_seconds, remaining())
                if step == 0:
                    profile.send('pre_model', 'complete', time.perf_counter() - profile.started)
                    startup_complete = True
                    if config.get('_startup_complete'):
                        config['_startup_complete']()
                status('model')
                model_started = time.monotonic()
                try:
                    from forensic_assistant.ai.backend import model_operation
                    with profile.phase('model_request'), model_operation('investigation'):
                        raw = client.complete(messages, grammar)
                except (LLMError, OSError, ValueError) as exc:
                    if remaining() <= 0:
                        timeout_cause = 'execution_budget_exhausted'
                    elif getattr(exc, 'category', None) == 'timeout' or 'timed out' in str(exc).lower():
                        timeout_cause = 'provider_request_timeout'
                    termination = 'MAX_SECONDS' if remaining() <= 0 else 'MODEL_FAILURE'
                    break
                finally:
                    model_time += time.monotonic() - model_started
                metadata = getattr(client, 'last_metadata', {})
                if metadata:
                    model_metadata.append(metadata)
                if remaining() <= 0:
                    termination = 'BUDGET_EXHAUSTED'
                    break
                try:
                    status('validation')
                    call_metadata = None
                    decoded = None
                    validation_stage = 'proposal_parsing'
                    with profile.phase('validation'):
                        decoded = contracts.loads(raw)
                    if isinstance(decoded, dict) and decoded.get('action') == 'tool':
                        state.requested += 1
                        call_number += 1
                        call_metadata = dict(tool_call_number=call_number,
                                             tool=decoded.get('tool') if type(decoded.get('tool')) is str and decoded['tool'] in contracts.TOOLS else 'invalid',
                                             proposed_arguments_sha256=digest(decoded.get('arguments')), status='proposed')
                        LOG.debug('lookup=%s status=proposed', call_metadata['tool'])
                        transcript.manifest.setdefault('tool_calls', []).append(call_metadata)
                        transcript._manifest()
                        audit('TOOL_PROPOSED', **{k: v for k, v in call_metadata.items() if k != 'status'})
                    validation_stage = 'proposal_validation'
                    with profile.phase('validation'):
                        proposal = contracts.request(raw, names)
                    if proposal['action'] == 'final':
                        validation_stage = 'final_grounding'
                        with profile.phase('validation'):
                            rendered = state.render(proposal['answer'])
                        if dry_run:
                            proposed_action = proposal
                            transcript.append('dry_run_proposal', proposal)
                            termination = 'USER_SCOPE_REACHED'
                            break
                        call('check')
                        final = rendered
                        termination = 'ANSWER_SUPPORTED' if any(rendered[k] for k in (
                            'observed',
                            'deterministically_correlated',
                            'corroborated',
                            'detections'
                        )) else 'INSUFFICIENT_EVIDENCE'
                        transcript.append('validated_final', proposal)
                        break
                    name, args = proposal['tool'], proposal['arguments']
                    call_metadata['arguments_sha256'] = digest(args)
                    if args.get('artifact') == 'browser' and not state.browser_available:
                        raise ValueError('Browser evidence is unavailable in this case')
                    validation_stage = 'anchor_validation'
                    with profile.phase('validation'):
                        validate_anchor(state, name, args, rules)
                    normalized = contracts.normalized_call(name, args)
                    if normalized in state.calls:
                        rejection_record(decoded, 'loop_validation', 'Repeated normalized tool call')
                        decision('rejected')
                        audit('TOOL_REJECTED', 'failure', tool_call_number=call_number, tool=name, reason='repeated_call')
                        transcript.append('loop_rejected', proposal)
                        termination = 'TOOL_LOOP'
                        break
                    if state.accepted >= budget.calls or (name == 'semantic_search' and state.semantic >= budget.semantic):
                        rejection_record(decoded, 'budget_validation', 'Tool-call budget exhausted')
                        decision('rejected')
                        audit('TOOL_REJECTED', 'failure', tool_call_number=call_number, tool=name, reason='call_budget')
                        termination = 'BUDGET_EXHAUSTED'
                        break
                    if dry_run:
                        proposed_action = proposal
                        transcript.append('dry_run_proposal', proposal)
                        termination = 'USER_SCOPE_REACHED'
                        decision('dry_run_not_executed')
                        break
                    if approval is not None:
                        status('approval')
                    if remaining() <= 0:
                        termination = 'MAX_SECONDS'
                        break
                    approved = True
                    if approval is not None:
                        # In production the terminal-owning supervisor supplies the exact wait credit.
                        pause = nullcontext() if config.get('_approval_clock_managed') else clock.approval_wait()
                        with pause:
                            try:
                                approved = approval(proposal, APPROVAL_SECONDS)
                            except (EOFError, TimeoutError):
                                approved = False
                    if not approved:
                        rejected_diagnostic = rejection_record(decoded, 'analyst_approval', 'Analyst rejected or approval timed out')
                        decision('rejected')
                        audit('TOOL_REJECTED', 'cancelled', tool_call_number=call_number, tool=name)
                        transcript.append('rejected', {'step': state.steps, 'tool_call_number': call_number,
                                                      'reason': 'Analyst rejected or approval timed out', 'request': proposal,
                                                      'diagnostic': rejected_diagnostic})
                        termination = 'MAX_SECONDS' if remaining() <= 0 else 'USER_REJECTED'
                        break
                    if remaining() <= 0:
                        termination = 'BUDGET_EXHAUSTED'
                        break
                    decision('approved' if approval is not None else 'policy_authorized')
                    audit('TOOL_APPROVED', tool_call_number=call_number, tool=name,
                          arguments_sha256=digest(args),
                          approval='analyst' if approval is not None else 'configured_policy')
                    state.calls.add(normalized)
                    state.accepted += 1
                    if name == 'semantic_search':
                        state.semantic += 1
                    transcript.append('accepted', {'step': state.steps, 'tool_call_number': call_number, 'proposal': proposal})
                    status('operation')
                    lookup_started = time.monotonic()
                    decision('started')
                    try:
                        response = call(name, args)
                    except WorkerError as exc:
                        failure_diagnostic = rejection_record(decoded, 'worker_execution', exc)
                        category = 'timeout' if exc.timed_out or 'TIMEOUT' in str(exc) else 'failed'
                        failed_lookup = dict(failed_lookup_tool=name, failed_lookup_category=category,
                                             failed_lookup_reason='Lookup execution timed out' if category == 'timeout' else 'Forensic worker execution or result validation failed')
                        call_metadata.update(outcome=category, failure_stage=exc.stage or 'worker_execution', elapsed_seconds=time.monotonic()-lookup_started, **failed_lookup)
                        LOG.debug('lookup=%s status=%s category=%s stage=%s elapsed=%.6f', name, category, failure_diagnostic['category'], call_metadata['failure_stage'], call_metadata['elapsed_seconds'])
                        decision('failed')
                        audit('TOOL_FAILED', 'failure', tool_call_number=call_number, tool=name)
                        raise
                    from .tools import AROUND_LIMITATIONS
                    unresolved = name == 'around' and any(v in AROUND_LIMITATIONS for v in response['result']['limitations'])
                    outcome = 'unresolved' if unresolved else 'completed' if response['result']['returned_count'] else 'completed_empty'
                    call_metadata.update(outcome=outcome, elapsed_seconds=time.monotonic()-lookup_started, returned_count=response['result']['returned_count'])
                    LOG.debug('lookup=%s status=%s elapsed=%.6f records=%d', name, outcome, call_metadata['elapsed_seconds'], call_metadata['returned_count'])
                    decision('executed')
                    audit('TOOL_EXECUTED', tool_call_number=call_number, tool=name,
                          arguments_sha256=digest(args),
                          result_count=response['result']['returned_count'])
                    transcript.append(
                        'result',
                        {
                            'step': state.steps,
                            'tool_call_number': call_number,
                            'operation': name,
                            'response': response,
                            'result_sha256': digest(response['result'])
                        }
                    )
                    new = state.ingest(response['result'])
                    state.path.append({
                        'operation': name,
                        'new_records': new,
                        'returned_records': response['result']['returned_count'],
                        'outcome': outcome
                    })
                    feedback = str(new) + ' NEW EVIDENCE' if new else 'NO NEW EVIDENCE'
                    if unresolved:
                        feedback = 'Previous around lookup is unresolved: ' + '; '.join(response['result']['limitations']) + '. This is a limitation, not evidence. Do not repeat the identical lookup or broaden across hosts; choose another grounded allowed lookup or conclude unresolved.'
                    if state.no_new >= 3:
                        termination = 'NO_NEW_EVIDENCE'
                        break
                    if len(state.records) >= budget.records:
                        termination = 'BUDGET_EXHAUSTED'
                        break
                except WorkerError:
                    raise
                except ValueError as exc:
                    if isinstance(exc, activity.AuditError):
                        raise
                    from forensic_assistant.ai.provider_diagnostics import validation
                    validation(client, 'response_parse' if validation_stage == 'proposal_parsing' else
                               'grounding' if validation_stage == 'final_grounding' else 'structured_validation')
                    rejected_diagnostic = rejection_record(decoded, validation_stage, exc)
                    if rejected_diagnostic['category'] == 'GROUNDING_VIOLATION' and validation_stage == 'final_grounding':
                        state.final_grounding_rejections += 1
                        reason = ('unexposed_field' if rejected_diagnostic['reason'] ==
                                  'Observed finding references an unexposed evidence field' else 'grounding_contract')
                        if reason not in state.final_grounding_reasons:
                            state.final_grounding_reasons.append(reason)
                    state.rejected += 1
                    from .feedback import correction
                    feedback = correction(decoded, rejected_diagnostic)
                    rejected = {}
                    try:
                        value = contracts.loads(raw)
                        if isinstance(value, dict):
                            for key in ('action', 'tool', 'arguments', 'reason'):
                                if key in value and len(encoded(value[key]).encode()) <= 2048:
                                    rejected[key] = value[key]
                    except ValueError:
                        pass
                    transcript.append(
                        'rejected',
                        {
                            'step': state.steps,
                            'tool_call_number': call_number if call_metadata is not None else None,
                            'reason': str(exc)[:300],
                            'diagnostic': rejected_diagnostic,
                            'request': rejected,
                            'response_sha256': hashlib.sha256(raw.encode()).hexdigest()
                        }
                    )
                    if call_metadata is not None and call_metadata.get('status') == 'proposed':
                        decision('rejected')
                        audit('TOOL_REJECTED', 'failure', tool_call_number=call_number, tool=call_metadata['tool'])
                    if dry_run:
                        termination = 'USER_SCOPE_REACHED'
                        break
                    if state.rejected >= budget.rejections:
                        termination = 'TOO_MANY_REJECTIONS'
                        break
            else:
                termination = 'BUDGET_EXHAUSTED'
    except activity.AuditError:
        termination = 'AUDIT_FAILURE'
        state.limit('Required investigation audit could not be recorded; execution stopped')
    except WorkerError as exc:
        reason = str(exc)
        if 'EVIDENCE_STATE_CHANGED' in reason:
            integrity['live_case_matches'] = False
        termination = ('EVIDENCE_STATE_CHANGED' if 'EVIDENCE_STATE_CHANGED' in reason else
                       'SEMANTIC_STATE_CHANGED' if 'SEMANTIC_STATE_CHANGED' in reason else
                       'BUDGET_EXHAUSTED' if any(s in reason for s in ('TIMEOUT', 'WAL_PRESSURE', 'byte budget')) else 'TOOL_FAILURE')
        if not startup_complete:
            termination = ('STARTUP_TIMEOUT' if getattr(exc, 'timed_out', False) or remaining() <= 0 else
                           'FINGERPRINT_FAILURE' if getattr(exc, 'stage', None) == 'fingerprint' else
                           'WORKER_START_FAILURE' if worker is None else 'INITIAL_RETRIEVAL_FAILURE')
            profile.send(getattr(exc, 'stage', None) or profile.current,
                         'timeout' if termination == 'STARTUP_TIMEOUT' else 'failure', time.perf_counter()-profile.started)
        state.limit(reason)
    except ValueError as exc:
        termination = 'BUDGET_EXHAUSTED' if 'BUDGET' in str(exc) or 'budget' in str(exc) else 'INSUFFICIENT_EVIDENCE'
        state.limit(str(exc))
    except KeyboardInterrupt:
        termination = 'USER_SCOPE_REACHED'
        state.limit('Investigator interrupted the run')
    finally:
        status('finalizing')
        if worker is not None:
            # Even partial results are checked when time remains. A timeout leaves
            # explicitly historical F0 findings, never an assertion about current state.
            if fingerprint is not None and final is None and remaining() > 0 and termination not in (
                'EVIDENCE_STATE_CHANGED',
                'SEMANTIC_STATE_CHANGED'
            ):
                try:
                    call('check')
                except WorkerError as exc:
                    state.limit('Final state check failed: ' + str(exc))
                    if 'EVIDENCE_STATE_CHANGED' in str(exc):
                        integrity['live_case_matches'] = False
                    if 'STATE_CHANGED' in str(exc):
                        termination = str(exc)
            worker.close()
    if integrity.get('live_case_matches') is False:
        integrity_status, integrity_reason = 'changed', 'Live case fingerprint changed'
    elif integrity_status == 'not_checked' and fingerprint is not None:
        integrity_reason = 'Execution budget exhausted before final verification' if remaining() <= 0 else 'Final verification not attempted under termination policy'
    if integrity.get('strategy') == 'private_sqlite_snapshot' and integrity.get('live_case_matches') is not True:
        state.limit('Live-case equality was not confirmed at completion; findings cover only the original private snapshot.')
    if final is None:
        final = state.partial()
    if remaining() <= 0:
        timeout_cause = timeout_cause or 'execution_budget_exhausted'
        termination = 'MAX_SECONDS' if startup_complete else 'STARTUP_TIMEOUT'
    result = {
        'investigation_id': transcript.id,
        'termination': termination,
        'findings': final,
        'evidence_fingerprint': fingerprint,
        'derived_data': True,
        'state': state.summary(),
        'dry_run_proposal': proposed_action,
        'model_metadata': model_metadata,
        'metrics': {
            **clock.metrics(),
            'timeout_cause': timeout_cause,
            'validation_seconds': profile.totals.get('validation', 0.0),
            'phase_seconds': {k: v for k, v in profile.totals.items() if k not in ('model_request', 'validation')},
            'tool_seconds': tool_time,
            'model_seconds': model_time,
            'prompt_bytes': prompt_sizes,
            'integrity': integrity,
            'integrity_status': integrity_status,
            'integrity_reason': integrity_reason,
            'integrity_elapsed_seconds': integrity_elapsed,
            **failed_lookup
        },
        'limitations': [
            'Bounded investigation; absence of findings does not prove absence of activity.',
            'Findings refer only to the recorded original evidence fingerprint; later case states are not covered.',
            'ANSWER_SUPPORTED means validated disclosed structure, not scientific proof or model accuracy.',
            'Hypotheses and model-proposed unknowns are unverified.'
        ] + state.limits
    }
    LOG.debug('investigate-ai termination investigation=%s termination=%s steps=%d requested_calls=%d accepted_calls=%d rejected_requests=%d',
              transcript.id, termination, state.steps, state.requested, state.accepted, state.rejected)
    with profile.phase('finalization'):
        transcript.finish(result)
        audit('INVESTIGATION_TERMINATION', termination=termination)
    result['metrics'].update(clock.metrics())
    result['metrics']['phase_seconds'] = {k: v for k, v in profile.totals.items() if k not in ('model_request', 'validation')}
    result['transcript_bytes'] = transcript.size
    return result

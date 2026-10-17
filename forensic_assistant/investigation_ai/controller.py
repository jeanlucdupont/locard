"""Model proposals never dispatch directly: validate, authorize, bound, then execute."""
from dataclasses import asdict
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

def run(
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
    deadline = config.get('_deadline', started + budget.seconds)
    status = config.get('_status') or (lambda phase: None)
    status('preparing')
    profile = Profile(deadline)
    startup_complete = False
    state = State(budget)
    rules = [r.rule_id for r in available_rules()]
    config = {**config, 'rule_ids': rules}
    client = client or LocalClient()
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
    final = None
    termination = 'INSUFFICIENT_EVIDENCE'
    feedback = ''
    model_metadata = []
    tool_time = model_time = 0.0
    prompt_sizes = []
    proposed_action = None
    call_number = 0
    call_metadata = None
    def audit(action, outcome='success', **data):
        activity.event(action, outcome, required=True, investigation_id=transcript.id, **data)
    def decision(status):
        if call_metadata is not None:
            call_metadata['status'] = status
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
        return max(0, deadline - time.monotonic())
    def call(name, args=None):
        nonlocal fingerprint, tool_time
        if remaining() <= 0:
            raise WorkerError('INVESTIGATION_TIMEOUT')
        response = worker.call(
            name,
            args,
            fingerprint=fingerprint,
            known_ids=state.exposed,
            seconds=remaining() if name == 'initial' else min(budget.tool_seconds, remaining()),
            question=question
        )
        if response.get('database_changes') != 0 or response.get('schema') not in (3, 4, 5):
            raise WorkerError('Evidence read-only/schema validation failed')
        if fingerprint is not None and response['fingerprint'] != fingerprint:
            raise WorkerError('EVIDENCE_STATE_CHANGED')
        if name != 'check':
            try:
                contracts.validate_output(response['result'])
            except ValueError as exc:
                raise WorkerError(str(exc)) from exc
        fingerprint = response['fingerprint']
        tool_time += response['elapsed_seconds']
        return response
    try:
        with profile.phase('worker_start'):
            worker = worker_factory({k: v for k, v in {**config, '_deadline': deadline}.items() if k != '_startup_complete'})
        with profile.phase('initial_operation'):
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
                    raw = client.complete(messages, grammar)
                except (LLMError, OSError, ValueError):
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
                    decoded = contracts.loads(raw)
                    if isinstance(decoded, dict) and decoded.get('action') == 'tool':
                        state.requested += 1
                        call_number += 1
                        call_metadata = dict(tool_call_number=call_number,
                                             tool=decoded.get('tool') if type(decoded.get('tool')) is str and decoded['tool'] in contracts.TOOLS else 'invalid',
                                             proposed_arguments_sha256=digest(decoded.get('arguments')), status='proposed')
                        transcript.manifest.setdefault('tool_calls', []).append(call_metadata)
                        transcript._manifest()
                        audit('TOOL_PROPOSED', **{k: v for k, v in call_metadata.items() if k != 'status'})
                    validation_stage = 'proposal_validation'
                    proposal = contracts.request(raw, names)
                    if proposal['action'] == 'final':
                        validation_stage = 'final_grounding'
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
                    if approval is not None and not approval(proposal, remaining()):
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
                    try:
                        response = call(name, args)
                    except WorkerError as exc:
                        rejection_record(decoded, 'worker_execution', exc)
                        decision('failed')
                        audit('TOOL_FAILED', 'failure', tool_call_number=call_number, tool=name)
                        raise
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
                        'returned_records': response['result']['returned_count']
                    })
                    feedback = str(new) + ' NEW EVIDENCE' if new else 'NO NEW EVIDENCE'
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
                    rejected_diagnostic = rejection_record(decoded, validation_stage, exc)
                    state.rejected += 1
                    feedback = 'REJECTED: ' + str(exc)[:200]
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
                'SEMANTIC_STATE_CHANGED',
                'TOOL_FAILURE'
            ):
                try:
                    call('check')
                except WorkerError as exc:
                    state.limit('Final state check failed: ' + str(exc))
                    if 'STATE_CHANGED' in str(exc):
                        termination = str(exc)
            worker.close()
    if final is None:
        final = state.partial()
    if remaining() <= 0:
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
            'elapsed_seconds': time.monotonic() - started,
            'tool_seconds': tool_time,
            'model_seconds': model_time,
            'prompt_bytes': prompt_sizes
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
    transcript.finish(result)
    audit('INVESTIGATION_TERMINATION', termination=termination)
    result['transcript_bytes'] = transcript.size
    return result

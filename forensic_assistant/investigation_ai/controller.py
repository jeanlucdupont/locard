"""Model proposals never dispatch directly: validate, authorize, bound, then execute."""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import time
from forensic_assistant.detections.engine import available_rules
from forensic_assistant.llm.client import LocalClient, LLMError
from . import contracts
from .runner import ForensicWorker, WorkerError
from .state import State, Budget, encoded
from .transcript import Transcript, digest

def validate_anchor(state, name, args, rules):
    if name == 'detections' and args['rule_id'] not in rules: raise ValueError('Rule not in frozen registry')
    eid = args.get('evidence_id')
    if eid is None: return
    # Merely retrieving a record does not authorize the model to name it.
    if eid not in state.exposed: raise ValueError('Anchor was not exposed to the model')
    record = state.exposed[eid]
    if name == 'process_tree' and record.get('kind') != 'process': raise ValueError('Process anchor required')
    if name == 'session' and record.get('kind') != 'logon': raise ValueError('Successful logon anchor required')

def run(config, question, transcript_root, *, budget=None, client=None, dry_run=False, approval=None, worker_factory=ForensicWorker):
    if not isinstance(question, str) or not question.strip() or len(question.encode()) > 1000:
        raise ValueError('Question must be 1..1000 UTF-8 bytes')
    budget = budget or Budget(); state = State(budget)
    rules = [r.rule_id for r in available_rules()]
    config = {**config, 'rule_ids': rules}
    client = client or LocalClient()
    started = time.monotonic(); deadline = started + budget.seconds
    transcript = Transcript(transcript_root, {'started_utc': datetime.now(timezone.utc).isoformat(),
        'question': question, 'budgets': asdict(budget), 'tools': list(contracts.TOOLS),
        'rule_ids': rules, 'dry_run': dry_run, 'date_hint': config.get('date_hint')})
    worker = None; fingerprint = None; final = None; termination = 'INSUFFICIENT_EVIDENCE'
    feedback = ''; model_metadata = []; tool_time = model_time = 0.0; prompt_sizes = []
    proposed_action = None
    def remaining(): return max(0, deadline-time.monotonic())
    def call(name, args=None):
        nonlocal fingerprint, tool_time
        if remaining() <= 0: raise WorkerError('INVESTIGATION_TIMEOUT')
        response = worker.call(name, args, fingerprint=fingerprint, known_ids=state.exposed,
                              seconds=min(budget.tool_seconds, remaining()), question=question)
        if response.get('database_changes') != 0 or response.get('schema') != 3:
            raise WorkerError('Evidence read-only/schema validation failed')
        if fingerprint is not None and response['fingerprint'] != fingerprint: raise WorkerError('EVIDENCE_STATE_CHANGED')
        if name!='check':
            try: contracts.validate_output(response['result'])
            except ValueError as exc: raise WorkerError(str(exc)) from exc
        fingerprint = response['fingerprint']; tool_time += response['elapsed_seconds']
        return response
    try:
        worker = worker_factory(config)
        initial = call('initial')
        transcript.manifest.update(evidence_fingerprint=fingerprint, semantic_identity=initial.get('semantic_identity'),
                                   embedding_identity=initial.get('model_identity'))
        transcript.append('initial', initial)
        state.ingest(initial['result']); state.semantic += int(initial['result'].get('semantic_used', False))
        state.path.append({'operation': 'initial', 'new_records': len(state.records)})
        semantic_available = initial.get('semantic_available', False)
        if state.records:
            for step in range(budget.steps):
                state.steps = step + 1
                if remaining() <= 0: termination = 'BUDGET_EXHAUSTED'; break
                names = state.applicable(semantic_available, rules)
                messages, exposed, size = state.prompt(question, names, rules, feedback)
                grammar = contracts.schema(names)
                if len(encoded(grammar).encode()) > 32768: raise ValueError('Grammar byte budget exceeded')
                transcript.append('exposure', {'step': state.steps, 'content': exposed, 'prompt_bytes': size,
                                              'prompt_sha256': digest(messages), 'tools': names})
                state.disclose(exposed); prompt_sizes.append(size)
                # LocalClient applies a wall-clock socket watchdog as well as I/O timeouts.
                client.timeout = min(budget.tool_seconds, remaining())
                model_started = time.monotonic()
                try: raw = client.complete(messages, grammar)
                except (LLMError, OSError, ValueError): termination = 'MODEL_FAILURE'; break
                finally: model_time += time.monotonic()-model_started
                metadata = getattr(client, 'last_metadata', {})
                if metadata: model_metadata.append(metadata)
                if remaining() <= 0: termination = 'BUDGET_EXHAUSTED'; break
                try:
                    decoded = contracts.loads(raw)
                    if isinstance(decoded, dict) and decoded.get('action') == 'tool': state.requested += 1
                    proposal = contracts.request(raw, names)
                    if proposal['action'] == 'final':
                        rendered = state.render(proposal['answer'])
                        if dry_run:
                            proposed_action = proposal
                            transcript.append('dry_run_proposal', proposal); termination = 'USER_SCOPE_REACHED'; break
                        call('check')
                        final = rendered
                        termination = 'ANSWER_SUPPORTED' if any(rendered[k] for k in ('observed','deterministically_correlated','corroborated','detections')) else 'INSUFFICIENT_EVIDENCE'
                        transcript.append('validated_final', proposal); break
                    name, args = proposal['tool'], proposal['arguments']
                    validate_anchor(state, name, args, rules)
                    normalized = contracts.normalized_call(name, args)
                    if normalized in state.calls:
                        transcript.append('loop_rejected', proposal); termination = 'TOOL_LOOP'; break
                    if state.accepted >= budget.calls or (name == 'semantic_search' and state.semantic >= budget.semantic):
                        termination = 'BUDGET_EXHAUSTED'; break
                    if dry_run:
                        proposed_action = proposal
                        transcript.append('dry_run_proposal', proposal); termination = 'USER_SCOPE_REACHED'; break
                    if approval is not None and not approval(proposal, remaining()):
                        termination = 'USER_SCOPE_REACHED'; break
                    if remaining() <= 0: termination = 'BUDGET_EXHAUSTED'; break
                    state.calls.add(normalized); state.accepted += 1
                    if name == 'semantic_search': state.semantic += 1
                    transcript.append('accepted', {'step': state.steps, 'proposal': proposal})
                    response = call(name, args)
                    transcript.append('result', {'step': state.steps, 'operation': name, 'response': response,
                                                 'result_sha256': digest(response['result'])})
                    new = state.ingest(response['result'])
                    state.path.append({'operation': name, 'new_records': new, 'returned_records': response['result']['returned_count']})
                    feedback = str(new) + ' NEW EVIDENCE' if new else 'NO NEW EVIDENCE'
                    if state.no_new >= 3: termination = 'NO_NEW_EVIDENCE'; break
                    if len(state.records) >= budget.records: termination = 'BUDGET_EXHAUSTED'; break
                except WorkerError: raise
                except ValueError as exc:
                    state.rejected += 1; feedback = 'REJECTED: ' + str(exc)[:200]
                    rejected = {}
                    try:
                        value = contracts.loads(raw)
                        if isinstance(value, dict):
                            for key in ('action', 'tool', 'arguments', 'reason'):
                                if key in value and len(encoded(value[key]).encode()) <= 2048: rejected[key] = value[key]
                    except ValueError: pass
                    transcript.append('rejected', {'step': state.steps, 'reason': str(exc)[:300],
                        'request': rejected, 'response_sha256': hashlib.sha256(raw.encode()).hexdigest()})
                    if dry_run: termination = 'USER_SCOPE_REACHED'; break
                    if state.rejected >= budget.rejections: termination = 'TOO_MANY_REJECTIONS'; break
            else: termination = 'BUDGET_EXHAUSTED'
    except WorkerError as exc:
        reason = str(exc)
        termination = ('EVIDENCE_STATE_CHANGED' if 'EVIDENCE_STATE_CHANGED' in reason else
                       'SEMANTIC_STATE_CHANGED' if 'SEMANTIC_STATE_CHANGED' in reason else
                       'BUDGET_EXHAUSTED' if any(s in reason for s in ('TIMEOUT','WAL_PRESSURE','byte budget')) else 'TOOL_FAILURE')
        state.limit(reason)
    except ValueError as exc:
        termination = 'BUDGET_EXHAUSTED' if 'BUDGET' in str(exc) or 'budget' in str(exc) else 'INSUFFICIENT_EVIDENCE'
        state.limit(str(exc))
    except KeyboardInterrupt:
        termination = 'USER_SCOPE_REACHED'; state.limit('Investigator interrupted the run')
    finally:
        if worker is not None:
            # Even partial results are checked when time remains. A timeout leaves
            # explicitly historical F0 findings, never an assertion about current state.
            if fingerprint is not None and final is None and remaining() > 0 and termination not in ('EVIDENCE_STATE_CHANGED', 'SEMANTIC_STATE_CHANGED', 'TOOL_FAILURE'):
                try: call('check')
                except WorkerError as exc:
                    state.limit('Final state check failed: ' + str(exc))
                    if 'STATE_CHANGED' in str(exc): termination = str(exc)
            worker.close()
    if final is None: final = state.partial()
    result = {'investigation_id': transcript.id, 'termination': termination, 'findings': final,
              'evidence_fingerprint': fingerprint, 'derived_data': True, 'state': state.summary(),
              'dry_run_proposal': proposed_action,
              'model_metadata': model_metadata, 'metrics': {'elapsed_seconds': time.monotonic()-started,
                'tool_seconds': tool_time, 'model_seconds': model_time, 'prompt_bytes': prompt_sizes},
              'limitations': ['Bounded investigation; absence of findings does not prove absence of activity.',
                'Findings refer only to the recorded original evidence fingerprint; later case states are not covered.',
                'ANSWER_SUPPORTED means validated disclosed structure, not scientific proof or model accuracy.',
                'Hypotheses and model-proposed unknowns are unverified.'] + state.limits}
    transcript.finish(result)
    result['transcript_bytes'] = transcript.size
    return result

"""Replay validated forensic operations, never a model conversation or arbitrary code."""
from forensic_assistant.detections.engine import available_rules
from .contracts import arguments
from .controller import validate_anchor
from .runner import ForensicWorker
from .state import State, Budget
from .transcript import load, implementation, Transcript, digest
import time

def replay(config, root, investigation_id):
    manifest, events = load(root, investigation_id)
    current = implementation()
    if any(manifest.get(k) != v for k, v in current.items()):
        raise ValueError('Transcript implementation/policy/schema is incompatible; inspect without replay')
    if manifest.get('status') == 'RUNNING': raise ValueError('Incomplete investigation cannot be replayed')
    rules = [r.rule_id for r in available_rules()]
    if manifest.get('rule_ids') != rules: raise ValueError('Detection registry has changed')
    try: budget = Budget(**manifest['budgets'])
    except (KeyError, TypeError) as exc: raise ValueError('Invalid transcript budgets') from exc
    state = State(budget)
    expected = manifest.get('evidence_fingerprint')
    if type(expected) is not str: raise ValueError('Transcript lacks an evidence-state fingerprint')
    question = manifest.get('question')
    if type(question) is not str or not 0 < len(question.encode()) <= 1000: raise ValueError('Invalid replay question')
    started = time.monotonic(); pending = None; initialized = False; comparisons = []
    output = Transcript(root, {'replay_of': investigation_id, 'evidence_fingerprint': expected})
    status = 'REPLAY_MATCH'; reason = None
    def seconds():
        remaining = budget.seconds - (time.monotonic()-started)
        if remaining <= 0: raise ValueError('Replay runtime exhausted')
        return min(budget.tool_seconds, remaining)
    try:
        with ForensicWorker({**config, 'rule_ids': rules, 'date_hint': manifest.get('date_hint')}) as worker:
            for event in events:
                kind, data = event['kind'], event['data']
                if kind == 'initial':
                    if initialized: raise ValueError('Duplicate initial operation')
                    response = worker.call('initial', fingerprint=expected, seconds=seconds(), question=question)
                    if response.get('semantic_identity') != manifest.get('semantic_identity') or response.get('model_identity') != manifest.get('embedding_identity'):
                        raise ValueError('Semantic generation/model differs from original investigation')
                    match = digest(response['result']) == digest(data['result'])
                    comparisons.append({'operation': 'initial', 'match': match})
                    if not match: raise ValueError('Initial retrieval differs')
                    state.ingest(response['result']); state.semantic = int(response['result'].get('semantic_used', False)); initialized = True
                elif kind == 'exposure':
                    if not initialized: raise ValueError('Exposure before initial retrieval')
                    disclosed = data['content']
                    for record in disclosed['records']:
                        if record != state.records.get(record['id']): raise ValueError('Transcript exposure is not a retrieved record')
                    for section, key in (('relationships','relationship_id'), ('detections','detection_id')):
                        for item in disclosed[section]:
                            if item != getattr(state, section).get(item[key]): raise ValueError('Transcript exposes an unknown object')
                    state.disclose(disclosed)
                elif kind == 'accepted':
                    if not initialized or pending is not None: raise ValueError('Invalid replay sequence')
                    proposal = data['proposal']; name = proposal['tool']; args = arguments(name, proposal['arguments'])
                    validate_anchor(state, name, args, rules)
                    if state.accepted >= budget.calls: raise ValueError('Replay call budget exceeded')
                    state.accepted += 1
                    if name == 'semantic_search':
                        state.semantic += 1
                        if state.semantic > budget.semantic: raise ValueError('Replay semantic budget exceeded')
                    response = worker.call(name, args, fingerprint=expected, known_ids=state.exposed, seconds=seconds())
                    pending = (name, response)
                elif kind == 'result':
                    if pending is None or data['operation'] != pending[0]: raise ValueError('Invalid result sequence')
                    response = pending[1]; match = digest(response['result']) == data['result_sha256']
                    comparison = {'operation': pending[0], 'match': match}
                    comparisons.append(comparison); output.append('comparison', comparison)
                    if not match: raise ValueError('Operation result differs')
                    state.ingest(response['result']); pending = None
            if pending is not None: raise ValueError('Original operation has no completed result')
            if not initialized: raise ValueError('Transcript has no initial retrieval')
            worker.call('check', fingerprint=expected, seconds=seconds())
    except (ValueError, OSError, KeyError, TypeError) as exc:
        status = 'REPLAY_REFUSED'; reason = str(exc)[:300]
    result = {'investigation_id': output.id, 'replay_of': investigation_id, 'termination': status,
              'comparisons': comparisons, 'reason': reason, 'model_called': False,
              'caution': 'Reproduces tool outputs, not model hypotheses or forensic truth. Hashes are not authentication.'}
    output.finish(result); return result

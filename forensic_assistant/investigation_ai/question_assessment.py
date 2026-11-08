"""S3 deterministic question assessment over verified historical S1/S2 state.

No natural-language heuristic, provider request, case read, or report permission.
reconstruct() is the grounding entry point. Other helpers consume its trusted
application state; serialized hashes alone cannot confer evidence authority.
"""
from copy import deepcopy
import json
import re

from . import relationships as r, synthesis as s1
from .projection import same
from .state import encoded
from .transcript import digest, load

CONTRACT = 'question-assessment-v1'
MAX_QUESTION_BYTES = 4096
MAX_PROPOSITIONS = 8
MAX_CHECKS = 192
MAX_BYTES = s1.MAX_RESULT_BYTES
QUOTED = r'("(?:[^"\\]|\\.)*")'
CLAUSE = r'([a-f0-9]{64})'
RULES = {
    'browser_download': 'examined-download-path-v1',
    'filesystem_path': 'examined-mft-path-v1',
    'event_identifier': 'examined-event-id-v1',
    'defender_block': 'recognized-asr-interpretation-v1',
    'recorded_order': 'existing-recorded-order-v1',
    'recorded_field_equals': 'exact-clause-field-value-v1',
    'execution_outcome': 'execution-not-supported-v1',
    'causal_sequence': 'causality-not-supported-v1',
    'unmapped': 'no-question-mapping-v1',
}
PATTERNS = (
    ('browser_download', rf'Does the examined Browser evidence record a download to {QUOTED}\?'),
    ('filesystem_path', rf'Does the examined filesystem metadata record path {QUOTED}\?'),
    ('event_identifier', r'Is event ID ([0-9]{1,5}) present in the inspected EVTX records\?'),
    ('defender_block', r'Does the examined evidence include a validated Defender ASR blocking interpretation\?'),
    ('recorded_order', rf'Do recorded UTC values for clause {CLAUSE} precede clause {CLAUSE}\?'),
    ('recorded_field_equals', rf'Does clause {CLAUSE} report ({QUOTED}|true|false|null|-?[0-9]+)\?'),
    ('execution_outcome', rf'Did {QUOTED} execute\?'),
    ('causal_sequence', rf'Did {QUOTED} cause {QUOTED}\?'),
)


def _parts(question):
    """Explicit ';' separator outside JSON quotes, never English conjunctions."""
    parts, start, quoted, escaped = [], 0, False, False
    for i, char in enumerate(question):
        if escaped:
            escaped = False
        elif quoted and char == '\\':
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == ';' and not quoted:
            parts.append(question[start:i].strip())
            start = i + 1
    parts.append(question[start:].strip())
    return parts if not quoted and all(parts) else [question]


def _map(text):
    for kind, pattern in PATTERNS:
        match = re.fullmatch(pattern, text, re.IGNORECASE)
        if not match:
            continue
        try:
            if kind == 'event_identifier':
                return kind, {'event_id': int(match[1])}
            if kind == 'defender_block':
                return kind, {}
            if kind == 'recorded_order':
                return kind, {'left': match[1], 'right': match[2]}
            if kind == 'recorded_field_equals':
                return kind, {'clause_id': match[1], 'value': json.loads(match[2])}
            if kind == 'causal_sequence':
                return kind, {'cause': json.loads(match[1]), 'effect': json.loads(match[2])}
            return kind, {'value': json.loads(match[1])}
        except (ValueError, TypeError):
            break
    return 'unmapped', {}


def _aggregate(rows):
    statuses = {p['status'] for p in rows}
    if statuses == {'SUPPORTED_WITHIN_SCOPE'}:
        return 'SUPPORTED_WITHIN_SCOPE'
    if 'SUPPORTED_WITHIN_SCOPE' in statuses:
        return 'PARTIALLY_SUPPORTED'
    if len(rows) == 1:
        return rows[0]['status']
    # Mixed unsupported/contradicted components do not establish a whole-question
    # negative; expose their individual statuses instead.
    return 'NOT_ASSESSABLE' if statuses == {'NOT_ASSESSABLE'} else 'UNRESOLVED'


def _direct_candidate(kind, args, clause):
    support = clause['supports'][0]
    field = support.get('field', {})
    pointer, value = field.get('pointer'), field.get('value')
    if kind == 'defender_block':
        return clause['predicate'] == 'defender_asr_block'
    if clause['type'] != 'observation' or not r._complete(clause):
        return False
    if kind == 'browser_download':
        return (clause['predicate'] == 'browser_download_field' and pointer in ('/target_path', '/current_path')
                and same(value, args['value']))
    if kind == 'filesystem_path':
        return support['source_type'] == 'mft' and r._path(clause) is not None and same(value, args['value'])
    if kind == 'event_identifier':
        return support['source_type'] == 'evtx' and pointer == '/event_id' and type(value) is int and value == args['event_id']
    return False


def _assess(question, investigation_id, state, *, check_limit=MAX_CHECKS):
    """Internal service over verified reconstruction, not an arbitrary JSON import."""
    if not isinstance(question, str) or not question or len(question.encode('utf-8')) > MAX_QUESTION_BYTES:
        raise ValueError('Invalid or oversized investigation question')
    if type(check_limit) is not int or not 0 <= check_limit <= MAX_CHECKS:
        raise ValueError('Invalid question assessment budget')
    # Reuse S2's exact derivation checks, including S1 shape and epoch bindings.
    r.render(state)
    clauses = {c['id']: c for c in state['factual']['clauses']}
    if len(clauses) > s1.MAX_CLAUSES:
        raise ValueError('S1 clause ceiling exceeded')
    relations = {v['id']: v for v in state['relationships']}
    conflicts = {cid: sorted(v['id'] for v in relations.values()
                            if v['predicate'] == 'incompatible_recorded_field' and cid in v['endpoints'])
                 for cid in clauses}
    qid = digest([CONTRACT, investigation_id, question, state['factual']['evidence_state']])
    parts = _parts(question)
    mapping_limited = len(parts) > MAX_PROPOSITIONS
    if mapping_limited:
        # Never silently assess a prefix of an over-budget compound as the whole.
        parts = [question]
    rows, checks = [], 0
    for index, text in enumerate(parts):
        kind, args = ('unmapped', {}) if mapping_limited else _map(text)
        row = dict(id=digest([qid, index, text, kind, RULES[kind], args]), text=text, type=kind, rule=RULES[kind],
                   arguments=args, status='NOT_ASSESSABLE', direct_clauses=[], direct_relationships=[],
                   contextual_clauses=sorted(clauses), contextual_relationships=sorted(relations),
                   contradictory_clauses=[], contradictory_relationships=[], conflicting_supports=[],
                   gaps=[], unassessed_candidates=0, incomplete_support_candidates=0, support_search='not_searched',
                   validation='deterministic_recorded_view_assessment',
                   new_evidence_search='not_searched')
        if kind == 'unmapped':
            row['gaps'] = ['Question mapping is unsupported or ambiguous; no narrower question is substituted.']
            if mapping_limited:
                row['gaps'].append('Explicit proposition count exceeds the bounded grammar limit.')
        elif kind in ('execution_outcome', 'causal_sequence'):
            row['status'] = 'UNRESOLVED'
            row['support_search'] = 'unsupported'
            row['gaps'] = ['No reviewed ' + ('successful-execution' if kind == 'execution_outcome' else 'causal')
                           + ' proposition rule is enabled. Recorded metadata and ASR blocking do not establish this outcome or its negation.']
        elif kind == 'recorded_order':
            endpoints = [args['left'], args['right']]
            if any(cid not in clauses for cid in endpoints):
                row['gaps'] = ['A specified clause is unavailable in the accepted recorded view.']
            else:
                row['status'] = 'UNRESOLVED'
                row['support_search'] = 'no_match'
                for relation in sorted(relations.values(), key=lambda v: v['id']):
                    if checks >= check_limit:
                        row['unassessed_candidates'] += 1
                        continue
                    checks += 1
                    if relation['predicate'] != 'recorded_time_before':
                        continue
                    if relation['endpoints'] == endpoints:
                        row['direct_relationships'].append(relation['id'])
                    elif relation['endpoints'] == endpoints[::-1]:
                        row['contradictory_relationships'].append(relation['id'])
                if row['direct_relationships']:
                    row['status'] = 'SUPPORTED_WITHIN_SCOPE'
                    row['direct_clauses'] = endpoints
                elif row['contradictory_relationships']:
                    row['status'] = 'CONTRADICTED'
                    row['contradictory_clauses'] = endpoints
                else:
                    row['gaps'] = ['No assessed S2 edge settles this exact comparison; display order is not support.']
                if row['unassessed_candidates'] or state['coverage']['incomplete']:
                    row['gaps'].append('Recorded-time comparisons are sparse/bounded; unassessed pairs are not negative findings.')
        elif kind == 'recorded_field_equals':
            clause = clauses.get(args['clause_id'])
            if clause is None:
                row['gaps'] = ['The specified clause is unavailable in the accepted recorded view.']
            elif checks >= check_limit:
                row['unassessed_candidates'] = 1
                row['gaps'] = ['Assessment budget exhausted before the specified field was checked.']
            else:
                checks += 1
                if clause['type'] != 'observation' or not r._complete(clause):
                    row['gaps'] = ['An eligible complete original-field observation is required.']
                    row['support_search'] = 'incomplete'
                    row['incomplete_support_candidates'] += 1
                elif conflicts[clause['id']]:
                    row['status'] = 'UNRESOLVED'
                    row['conflicting_supports'] = conflicts[clause['id']]
                    row['gaps'] = ['Comparable recorded projections conflict; no value is selected as correct.']
                elif same(clause['arguments']['value'], args['value']):
                    row['status'] = 'SUPPORTED_WITHIN_SCOPE'
                    row['direct_clauses'] = [clause['id']]
                else:
                    row['status'] = 'CONTRADICTED'
                    row['contradictory_clauses'] = [clause['id']]
        else:
            row['status'] = 'UNRESOLVED' if clauses else 'NOT_ASSESSABLE'
            row['support_search'] = 'no_match'
            for clause in sorted(clauses.values(), key=lambda c: c['id']):
                if checks >= check_limit:
                    row['unassessed_candidates'] += 1
                    continue
                checks += 1
                if clause['type'] == 'observation' and not r._complete(clause):
                    row['incomplete_support_candidates'] += 1
                if _direct_candidate(kind, args, clause):
                    if conflicts[clause['id']]:
                        row['conflicting_supports'].extend(conflicts[clause['id']])
                    else:
                        row['direct_clauses'].append(clause['id'])
            if row['direct_clauses']:
                row['status'] = 'SUPPORTED_WITHIN_SCOPE'
            else:
                row['gaps'] = ['No eligible direct support in the assessed accepted clauses. This is not proof of absence from the case or of non-occurrence.']
            if row['unassessed_candidates']:
                row['gaps'].append('Assessment budget exhausted; remaining candidates were not checked.')
        if row['direct_clauses'] or row['direct_relationships'] or row['contradictory_clauses'] or row['contradictory_relationships']:
            row['support_search'] = 'matched'
        if row['unassessed_candidates']:
            row['support_search'] = 'incomplete'
        if row['incomplete_support_candidates']:
            row['gaps'].append('Some candidate field projections are shortened/incomplete and cannot establish exact-value support.')
            if row['support_search'] == 'no_match':
                row['support_search'] = 'incomplete'
        row['contextual_clauses'] = sorted(set(row['contextual_clauses']) - set(row['direct_clauses']) - set(row['contradictory_clauses']))
        row['contextual_relationships'] = sorted(set(row['contextual_relationships']) - set(row['direct_relationships']) - set(row['contradictory_relationships']))
        row['context_relevance'] = 'Available recorded context; relevance to this proposition is not independently established.'
        rows.append(row)
    result = dict(contract=CONTRACT, question=question, question_id=qid, source_investigation=investigation_id,
                  evidence_state=deepcopy(state['factual']['evidence_state']), recorded_not_revalidated=True,
                  status=_aggregate(rows), propositions=rows, evidence=deepcopy(state),
                  mapping='explicit bounded grammar; no general natural-language decomposition',
                  metrics=dict(propositions_recognized=sum(p['type'] != 'unmapped' for p in rows),
                               propositions_assessed=sum(p['support_search'] in ('matched', 'no_match', 'incomplete') for p in rows),
                               support_checks=checks, check_limit=check_limit,
                               direct_supports=sum(len(p['direct_clauses']) + len(p['direct_relationships']) for p in rows),
                               contextual_supports=sum(len(p['contextual_clauses']) + len(p['contextual_relationships']) for p in rows),
                               contradictory_supports=sum(len(p['contradictory_clauses']) + len(p['contradictory_relationships']) for p in rows),
                               unsupported_types=sum(p['type'] in ('unmapped', 'execution_outcome', 'causal_sequence') for p in rows),
                               unassessed_candidates=sum(p['unassessed_candidates'] for p in rows)),
                  limitations=['Recorded-view assessment; no current-case equality or complete examination is claimed.',
                    'Plan completion, question support and forensic completeness are independent.',
                    'No new evidence search was performed. No-match among accepted clauses is not a negative forensic finding.',
                    'Successful execution, complete prevention and causal linkage are not established by this assessment.',
                    'Available recorded context is presented without claiming independent relevance to an unmapped question.'])
    s1._bounded(result, MAX_BYTES)
    return result


def reconstruct(root, identity):
    # Pin the question/provenance to the same on-disk journal used by S1/S2.
    before, _ = load(root, identity)
    state = r.reconstruct(root, identity)
    after, _ = load(root, identity)
    accepted_view = state['factual']['evidence_state']
    if (not same(before, after) or (accepted_view is not None and not same(before.get('evidence_state'), accepted_view))
            or (accepted_view is None and state['factual']['clauses'])):
        raise ValueError('Recorded investigation changed during assessment')
    result = _assess(before.get('question'), identity, state)
    result['source_manifest_sha256'] = digest(before)
    result['recorded_source_view'] = deepcopy(before.get('evidence_state'))
    result['investigation_termination'] = before.get('status', 'unknown')
    s1._bounded(result, MAX_BYTES)
    return result


def render(result):
    if result.get('contract') != CONTRACT:
        raise ValueError('Unsupported question assessment contract')
    s1._bounded(result, MAX_BYTES)
    state = result['evidence']
    expected = _assess(result['question'], result['source_investigation'], state,
                       check_limit=result['metrics']['check_limit'])
    if not same(expected, {k: v for k, v in result.items() if k not in ('source_manifest_sha256', 'investigation_termination', 'recorded_source_view')}):
        raise ValueError('Invalid question assessment derivation')
    clauses = state['factual']['clauses']
    lines = ['Investigation question', json.dumps(result['question'], ensure_ascii=False), '',
             'What the examined evidence establishes',
             'Recorded findings below are not confirmation of an alleged sequence.']
    for clause in clauses:
        args = clause['arguments']
        subject = s1.RULES[clause['predicate']][1]
        text = subject if clause['predicate'] == 'defender_asr_block' else (
            subject + ' reports ' + json.dumps(args['label']) + ' as ' + json.dumps(args['value']) + '.')
        lines.append('  ' + text)
    if not clauses:
        lines.append('  No accepted factual clauses are available.')
    lines += ['', 'What remains unresolved',
              '  Successful execution and causality remain unresolved: no approved outcome rule is enabled.']
    for p in result['propositions']:
        for gap in p['gaps']:
            lines.append('  - ' + gap)
    lines += ['', 'Question assessment', '  ' + result['status']]
    if 'investigation_termination' in result:
        lines.append('  Recorded investigation termination (separate): ' + json.dumps(result['investigation_termination']))
    for p in result['propositions']:
        lines.append('  ' + p['type'] + ': ' + p['status'] + ' (' + p['support_search'] + ')')
        for key in ('direct_clauses', 'direct_relationships', 'contradictory_clauses', 'contradictory_relationships', 'conflicting_supports'):
            if p[key]:
                lines.append('    ' + key + ': ' + encoded(p[key]))
    lines += ['', 'Supporting evidence (recorded context unless classified as direct above)']
    for c in clauses:
        support = c['supports'][0]
        lines.append('  Clause ' + c['id'] + ': ' + json.dumps(support['evidence_id']) + ' '
                     + json.dumps(support.get('field', {}).get('pointer', support.get('interpretation_id'))))
    for edge in state['relationships']:
        lines.append('  Relationship ' + edge['id'] + ': ' + edge['predicate'] + ' ' + encoded(edge['endpoints']))
    lines += ['', 'Unverified hypotheses and alternatives — not factual support']
    lines += ['  ' + encoded(h) for h in state['factual']['hypotheses']] or ['  None recorded.']
    lines += ['  Unverified open question: ' + json.dumps(q) for q in state['factual']['unresolved_questions']]
    notes = set(result['limitations'])
    notes.update('S2 relationship layer: ' + note for note in state['limitations'])
    for c in clauses:
        notes.update(c['qualifications'])
    lines += ['', 'Coverage and limitations'] + ['  - ' + json.dumps(n) for n in sorted(notes)]
    factual_coverage = state['factual']['coverage']
    lines += ['  S1 coverage: ' + encoded({
                  'accepted_clauses': len(clauses),
                  'inspected_records': len(factual_coverage.get('inspected_record_ids', [])),
                  'represented_records': len(factual_coverage.get('represented_record_ids', [])),
                  'inspected_not_represented': len(factual_coverage.get('inspected_not_represented', [])),
                  'basis': factual_coverage.get('basis', 'Recorded accepted clauses only')}),
              '  S2 comparisons: ' + encoded(state['coverage']),
              '  S3 assessment: ' + encoded(result['metrics'])]
    return '\n'.join(lines)

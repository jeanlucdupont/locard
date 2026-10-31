"""Controller-owned derivations and conservative bounded-answer assessment.

Model declarations are not proofs of objective completeness. Only the narrow
literal field-lookup objective below can currently be certified automatically.
"""
import hashlib
import re

COVERAGE = {
    'original_value_shortened': 'Some original EventData names or values were shortened; inspect their truncation flags.',
    'original_fields_omitted': 'Original EventData projection is bounded; not all original fields are available.',
    'search_excerpt_shortened': 'Search excerpts are shortened; separately exposed original field values may be complete.',
    'normalized_value_shortened': 'Some normalized field values were shortened.',
    'context_shortened': 'Some source assertions or warning text were omitted or shortened.',
}


def coverage_text(code):
    return COVERAGE.get(code, str(code))


def interpretations(record):
    from forensic_assistant.retrieval.event_data import interpretation
    expected = interpretation(record)
    if not expected or record.get('defender_asr') != expected:
        return {}
    derivation = 'defender-asr-block-v1'
    identity = 'INT:' + hashlib.sha256((derivation + '\0' + record['id']).encode()).hexdigest()[:24]
    return {identity: {
        'interpretation_id': identity,
        'derivation_id': derivation,
        'classification': 'DETERMINISTIC_INTERPRETATION',
        'evidence_ids': [record['id']],
        'text': expected['limitation'],
    }}


def assess(question, answer, findings, *, limitations=(), omitted=False, candidate_count=None):
    """Separate grounded support, model declaration, and verified completeness.

General investigations stay PARTIAL rather than using lexical similarity or a
model's self-assessment as proof. No additional calls/retries are introduced.
    """
    supported = any(findings.get(k) for k in ('observed', 'deterministically_correlated',
        'corroborated', 'detections', 'interpretations'))
    declared = answer.get('answer_status', 'unresolved')
    status = 'PARTIAL' if supported else 'UNRESOLVED'
    reason = 'Objective completeness is not independently established.'
    # Exact, single-field requests only; never broad execution/absence questions.
    match = re.fullmatch(r'\s*(?:what is|show) (?:the )?(hostname|provider|event id|timestamp)(?:\?)?\s*', question, re.I)
    if (match and candidate_count == 1 and declared == 'answered' and not answer['unknowns']
            and not limitations and not omitted):
        field = {'event id': '/event_id', 'timestamp': '/timestamp_utc'}.get(match[1].lower(), '/' + match[1].lower())
        rows = findings.get('observed', [])
        if len(rows) == 1 and rows[0]['field'] == field and not rows[0].get('truncated_fields'):
            status = 'COMPLETE'
            reason = 'The requested single field was disclosed and grounded; this is not examination completeness.'
    if declared == 'unresolved' and not supported:
        reason = 'No grounded answer was established.'
    return {'grounding': 'SUPPORTED' if supported else 'NO_SUPPORTED_FINDINGS',
            'model_declared_status': declared, 'status': status, 'reason': reason}

"""Human projection of the supplied bounded bundle; model prose stays labeled."""
from forensic_assistant.retrieval.presentation import safe_text as safe
from .grounding import ARTIFACT_GUIDANCE, assess


CONTEXT = {
    'mft': 'MFT: inspect the full normalized record and timestamps for filesystem activity context with show.',
    'evtx': 'EVTX: inspect the normalized event; raw event XML is available with show --raw.',
    'registry': 'Registry: inspect the full normalized key/value context with show.',
    'prefetch': 'Prefetch: inspect the full parsed record/context with show.',
    'browser': 'Browser: inspect the relevant history/download record with show.',
}
NOTES = (
    'Model analysis is not evidence; semantic similarity is retrieval metadata, not evidence or correlation.',
    'Citation validation verifies references, not factual correctness. Validate findings against original records.',
    'Detections are observations for review, not proof of compromise.',
)


def render(result, palette, *, include_question=True):
    bundle = result['evidence_bundle']
    grounding = result.get('grounding') or assess(bundle, result['plan'])
    lines = []

    def section(title):
        if lines:
            lines.append('')
        lines.append(palette('heading', title))

    def value(label, text):
        lines.append('  ' + palette('key', label + ': ') + safe(text))

    if include_question:
        section('Question')
        lines.append('  ' + safe(bundle['QUESTION']))
    section('Plan')
    plan = result['plan']
    value('Retrieval', 'semantic' if plan.get('operation') == 'conceptual' else 'deterministic search')
    for name, item in plan.get('filters', {}).items():
        value(name.replace('_', ' ').capitalize(), item)
    if plan.get('semantic_reason'):
        value('Semantic limitation', plan['semantic_reason'])
    records = bundle['EVIDENCE']
    if grounding['statement']:
        lines += ['', safe(grounding['statement'])]

    def evidence(record, selection):
        kind = record.get('source_type') or record['id'].partition(':')[0].lower()
        objects = record.get('objects') or []
        subject = '; '.join(objects) or record.get('executable') or record.get('key') or record.get('process_name') or record.get('artifact_type', '')
        lines.append('  ' + safe(kind.upper()) + '  ' + safe(subject))
        lines.append('  ' + palette('evidence_id', 'ID: ' + safe(record['id'])))
        value('Selection', selection)

    groups = (
        ('deterministic_selection_ids', 'Evidence selected', 'deterministic match'),
        ('candidate_lead_ids', 'Candidate leads from semantic retrieval', 'semantic similarity'),
        ('context_evidence_ids', 'Additional selected context', 'deterministic expansion; not a direct query match'),
    )
    for key, title, selection in groups:
        ids = set(grounding[key])
        if not ids:
            continue
        section(f'{title}: {len(ids)}')
        for record in records:
            if record['id'] in ids:
                basis = selection
                if key == 'candidate_lead_ids' and 'semantic_similarity' not in record.get('selection_reasons', []):
                    basis = 'deterministic context of a semantic lead'
                evidence(record, basis)
        if key == 'candidate_lead_ids':
            lines.append(palette('forensic_note', '  Candidate leads require field-based review; similarity does not establish the requested activity.'))
    for key, title in (('CORRELATED_EVIDENCE', 'Deterministic relationships'),
                       ('DETECTIONS', 'Detections (review observations)'),
                       ('UNRESOLVED_RELATIONSHIPS', 'Unresolved relationships')):
        if not bundle[key]:
            continue
        section(title)
        for item in bundle[key]:
            value(item.get('relationship') or item.get('rule_name', 'Observation'), item.get('status', item.get('severity', '')))
            value('Reason', item['reason'])
            for eid in item['evidence_ids']:
                lines.append('  ' + palette('evidence_id', 'ID: ' + safe(eid)))
            for limitation in item.get('limitations', []):
                value('Limitation', limitation)
    if result.get('analysis'):
        section('Model analysis — not evidence')
        for finding in result['analysis']['findings']:
            has_candidates = bool(set(finding['evidence_ids']) & set(grounding['candidate_lead_ids']))
            value('Candidate assessment (model; relevance unverified)' if has_candidates
                  else 'Finding (model assessment)', finding['finding'])
            value('Interpretation', finding['interpretation'])
            for eid in finding['evidence_ids']:
                lines.append('  ' + palette('evidence_id', 'Cites: ' + safe(eid)))
            if finding.get('correlation_status'):
                value('Deterministic relationship status', finding['correlation_status'])
            for label, field in (('Alternative explanation', 'alternative_explanations'), ('Next evidence (model suggestion)', 'next_evidence')):
                for text in finding[field]:
                    value(label, text)
        for text in result['analysis']['missing_evidence']:
            value('Missing evidence (model assessment)', text)
    else:
        lines += ['', 'No analysis model was contacted.']
    if result.get('message') and result['message'] != grounding['statement']:
        lines.append(safe(result['message']))
    section('Limitations')
    for limitation in grounding['limitations']:
        lines.append('  ' + safe(limitation))
    metadata = bundle['metadata']
    if metadata['fields_truncated']:
        lines.append(palette('warning', '  Evidence fields were truncated in the model context.'))
    for record in records:
        for field in record.get('truncated_fields', []):
            lines.append(palette('warning', '  ' + safe(field) + ' from model context'))
            lines.append('  ' + palette('evidence_id', 'ID: ' + safe(record['id'])))
    for name in ('omitted_records', 'omitted_relationships', 'omitted_detections', 'omitted_unresolved'):
        if metadata[name]:
            value(name.replace('_', ' ').capitalize(), metadata[name])
    if metadata['candidate_count_is_lower_bound']:
        lines.append('  Candidate count is a lower bound; this is a bounded selection.')
    for text in metadata['retrieval_limits']:
        lines.append('  ' + safe(text))
    lines.append('  ' + safe(metadata['limitations']))
    kinds = {r.get('source_type') or r['id'].partition(':')[0].lower() for r in records}
    for kind in sorted(kinds):
        if kind in CONTEXT:
            lines.append('  ' + CONTEXT[kind])
    notes = list(NOTES)
    notes.extend(ARTIFACT_GUIDANCE[kind] for kind in sorted(kinds) if kind in ARTIFACT_GUIDANCE)
    lines += ['', palette('forensic_note', 'Forensic notes')]
    lines.extend(palette('forensic_note', '  - ' + text) for text in notes)
    return '\n'.join(lines)

"""Human projection of the supplied bounded bundle; model prose stays labeled."""
from forensic_assistant.retrieval.presentation import safe_text as safe


CONTEXT = {
    'mft': 'MFT: inspect the full normalized record and additional timestamps/attributes with show.',
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


def render(result, palette):
    bundle = result['evidence_bundle']
    lines = []

    def section(title):
        if lines:
            lines.append('')
        lines.append(palette('heading', title))

    def value(label, text):
        lines.append('  ' + palette('key', label + ': ') + safe(text))

    section('Question')
    lines.append('  ' + safe(bundle['QUESTION']))
    section('Plan')
    plan = result['plan']
    value('Retrieval', plan.get('operation', 'unknown'))
    for name, item in plan.get('filters', {}).items():
        value(name.replace('_', ' ').capitalize(), item)
    value('Semantic retrieval', 'used' if plan.get('semantic_coverage') == 'searched'
          else plan.get('semantic_coverage', 'not needed'))
    if plan.get('semantic_reason'):
        value('Semantic limitation', plan['semantic_reason'])
    records = bundle['EVIDENCE']
    section(f'Evidence selected: {len(records)}')
    for record in records:
        kind = record.get('source_type') or record['id'].partition(':')[0].lower()
        objects = record.get('objects') or []
        subject = '; '.join(objects) or record.get('executable') or record.get('key') or record.get('process_name') or record.get('artifact_type', '')
        lines.append('  ' + safe(kind.upper()) + '  ' + safe(subject))
        lines.append('  ' + palette('evidence_id', 'ID: ' + safe(record['id'])))
        value('Selection', 'direct evidence' if record['id'] in bundle['DIRECT_EVIDENCE']
              else ', '.join(record.get('selection_reasons', ['deterministic expansion'])))
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
            value('Finding (model assessment)', finding['finding'])
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
    if result.get('message'):
        lines.append(safe(result['message']))
    section('Limitations')
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
    if 'mft' in kinds:
        notes.append('MFT presence and access timestamps do not prove execution.')
    if 'prefetch' in kinds:
        notes.append('Prefetch execution timestamps support execution; counts and retained runs are incomplete.')
    if kinds & {'registry', 'browser'}:
        notes.append('Registry and browser observations do not automatically establish execution.')
    lines += ['', palette('forensic_note', 'Forensic notes')]
    lines.extend(palette('forensic_note', '  - ' + text) for text in notes)
    return '\n'.join(lines)

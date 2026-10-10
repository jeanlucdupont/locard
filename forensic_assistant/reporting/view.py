"""Presentation-only report projection. Never adds claims or changes evidence."""
from collections import Counter
from forensic_assistant.retrieval.presentation import safe_text
from .model import CATEGORIES, CAUTION


CAUTIONS = {
    'mft': 'MFT records contain filesystem metadata. Presence and SI/FN timestamps do not establish execution, meaningful usage, malicious intent, compromise or attribution.',
    'prefetch': 'Prefetch may support execution observations, not malicious intent; retained runs and counts are not a complete execution history.',
    'evtx': 'Event meaning depends on the provider and event type. Recorded fields do not alone establish causality or malicious intent.',
    'registry': 'Registry observations describe key/value context. Key last-write is not individual value creation; interpretation depends on the key/value semantics.',
    'browser': 'Browser observations describe browsing/download context, not proof of execution or intent.',
}
LABELS = {'allocated': 'Allocation state', 'record_number': 'Record number',
          'sequence': 'Sequence', 'objects': 'Object', 'utc': 'UTC',
          'precision_ns': 'Precision (ns)', 'sha256': 'SHA-256', 'id': 'ID'}


def text(value):
    if value is None:
        return 'Not recorded'
    if type(value) is bool:
        return 'Yes' if value else 'No'
    return safe_text(str(value))


def label(key):
    return LABELS.get(key, key.replace('_', ' ').capitalize())


def rows(value, prefix=''):
    """Flatten detail into labeled rows, never serialized dictionaries."""
    if isinstance(value, dict):
        for key, child in sorted(value.items()):
            yield from rows(child, ' / '.join(filter(None, (prefix, label(key)))))
    elif isinstance(value, list):
        for number, child in enumerate(value, 1):
            yield from rows(child, f'{prefix} {number}'.strip())
        if not value:
            yield prefix, 'None recorded'
    else:
        yield prefix, text(value)


def kind(record):
    return record['fields'].get('source_type') or record['id'].partition(':')[0].lower()


def subjects(record):
    fields = record['fields']
    values = fields.get('objects') or [fields.get(key) for key in
        ('executable', 'process_name', 'key', 'url', 'title', 'target_path') if fields.get(key)]
    if not isinstance(values, list):
        values = [values]
    return '; '.join(text(v) for v in values) or kind(record).upper() + ' evidence record'


def allocation(value):
    return 'Allocated' if value is True else 'Unallocated' if value is False else 'Not recorded'


def summary_record(record):
    fields = record['fields']
    subject = subjects(record)
    if kind(record) == 'mft':
        state = allocation(fields.get('allocated')).lower()
        return f'{subject} is represented by an {state} MFT record.' if state != 'not recorded' else f'{subject} is represented in MFT metadata; allocation state is not recorded.'
    return f'{kind(record).upper()} observation: {subject}.'


def build(report):
    """Both human formats consume these same sections and scalar blocks."""
    data = report['data']
    technical = report['profile'] == 'technical'
    sections = []
    def section(title, blocks, anchor=None):
        sections.append({'title': title, 'anchor': anchor, 'blocks': blocks})
    def paragraph(value):
        return ('paragraph', text(value))
    def bullets(values):
        return ('bullets', [text(v) for v in values])
    def table(headers, values):
        return ('table', [headers, [[text(v) for v in row] for row in values]])
    def detail(value):
        return table(['Recorded property', 'Value'], rows(value))
    records = sorted(data['evidence'].values(), key=lambda r: r['id'])
    counts = Counter(kind(r).upper() for r in records)
    selection = data['selection']
    scope_count = (f"{len(selection['evidence_ids'])} explicit evidence records"
                   if data['input_mode'] == 'explicit_evidence_ids' else
                   f"{len(selection['investigation_ids'])} selected same-state investigations")
    overview = [paragraph(scope_count + f"; {len(records)} records included with required support."),
                paragraph('; '.join(f'{count} {name} records' for name, count in sorted(counts.items())) + '.')]
    narrative = report['narrative']
    if narrative['status'] == 'ACCEPTED' and 'summary_paragraphs' in narrative:
        overview.append(paragraph('Constrained narrative assistance — composed from validated claims.'))
        overview.extend(paragraph(item['text']) for item in narrative['summary_paragraphs'])
        summaries = {item['text'] for item in narrative['summary_paragraphs']}
        overview.append(bullets(item['text'] for item in narrative['key_points'] if item['text'] not in summaries))
        cited = {cid for key in ('summary_paragraphs', 'key_points') for item in narrative[key] for cid in item['claim_ids']}
        covered = {eid for c in data['claims'] if c['claim_id'] in cited for eid in c['evidence_ids']}
        remaining = [r for r in records if r['id'] not in covered]
        if remaining:
            overview.append(paragraph('Additional selected observations (deterministic summary):'))
            shown = remaining[:8 if technical else 4]
            overview.append(bullets(summary_record(r) for r in shown))
            if len(shown) < len(remaining):
                overview.append(paragraph(f'{len(remaining)-len(shown)} additional records remain in the evidence references.'))
    else:
        shown = records[:8 if technical else 4]
        overview.append(bullets(summary_record(r) for r in shown))
        if len(shown) < len(records):
            overview.append(paragraph(f'{len(records)-len(shown)} additional records are described in the evidence references.'))
    overview.append(bullets(CAUTIONS[k] for k in sorted({kind(r) for r in records}) if k in CAUTIONS))
    if not any(c['category'] in ('DETERMINISTIC RELATIONSHIP', 'CORROBORATED RELATIONSHIP') for c in data['claims']):
        overview.append(paragraph('No relationship between the selected records is asserted by this report.'))
    if any(r['fields'].get('truncated_fields') for r in records):
        overview.append(paragraph('Compact claim projections have omissions. The timeline separately retains normalized timestamp observations within the report limit.'))
    section('Executive summary', overview, 'summary')
    scope = [paragraph(data['scope']), paragraph('Empty categories are not investigative negative results.'),
             paragraph('Evidence selection: ' + scope_count), detail(data['analyst_metadata']), paragraph(data['analyst_metadata_basis'])]
    if data.get('redaction_notice'):
        scope.append(paragraph(data['redaction_notice']))
    section('Scope and analyst metadata', scope, 'scope')
    inventory = []
    for sha, item in sorted(data['inventory'].items()):
        inventory += [('heading', 'Source ' + sha), table(['Property', 'Value'], [
            ('SHA-256', sha), ('Artifact types', ', '.join(item['source_types'])),
            ('Stored source record count', item['evidence_count'])])]
        inventory += [table(['Parser', 'Version', 'Extractor version'],
            [(p['parser_name'], p['parser_version'], p['extractor_version']) for p in item['parsers']])]
        if technical:
            inventory += [detail({'ingestion_runs': item['ingestion_runs'],
                'source_locations': item.get('source_locations', 'Omitted from this report')})]
    inventory.append(paragraph('Inventory counts describe stored source records, not records individually examined by a model.'))
    section('Evidence inventory', inventory)
    if technical:
        section('Methodology', [detail(data['methodology']), paragraph('Report-time hydration is separate from historical model exposure. Unrecorded operations are not asserted.')], 'method')
    else:
        section('Methodology', [bullets(data['methodology']['report_operations']), paragraph(data['methodology']['scope'])], 'method')
    section('Investigation questions', [bullets(p['question'] for p in data['investigations'])] if data['investigations'] else
            [paragraph('No investigation supplied: this report was generated from explicit evidence IDs.')])
    observed = []
    for record in records:
        fields = record['fields']
        selected = {key: value for key, value in fields.items() if key not in
                    ('id', 'objects', 'timestamps', 'warnings', 'truncated_fields')}
        if 'allocated' in selected:
            selected['allocated'] = allocation(selected['allocated'])
        if not technical:
            selected = {k: v for k, v in selected.items() if k in
                        ('source_type', 'record_number', 'sequence', 'allocated', 'event_id', 'executable', 'run_count', 'key', 'url')}
        observed += [('heading', subjects(record)), paragraph('Evidence ID: ' + record['id']), detail(selected)]
        ids = data['graph']['evidence_to_claims'][record['id']]
        if technical:
            observed += [('details', ['Claim provenance', [text(cid) for cid in ids]])]
    observed.append(paragraph('These are report-time normalized evidence projections. Claim bounds and compact omissions remain recorded separately; display grouping does not merge evidence.'))
    section('Observed evidence', observed, 'findings')
    for category in CATEGORIES[1:-1]:
        group = [c for c in data['claims'] if c['category'] == category]
        blocks = []
        for item in group:
            blocks += [('heading', category.capitalize()), detail(item['assertion']),
                       paragraph('Evidence: ' + '; '.join(item['evidence_ids']))]
            if technical:
                blocks += [paragraph('Claim: ' + item['claim_id']), detail({'origins': item['origins']})]
        section(category.capitalize(), blocks or [paragraph('No ' + category.lower() + ' claims within the selected report scope.')])
    limitations = [bullets(data['limitations']), detail({'report_limits': data['limits'], 'omissions': data['omissions']})]
    if narrative['status'] in ('REJECTED', 'FAILED', 'FALLBACK'):
        limitations.append(paragraph(narrative.get('reason', 'Narrative unavailable; deterministic summary retained.')))
    if narrative['status'] == 'ACCEPTED' and 'limitations' in narrative:
        limitations.append(bullets(item['text'] for item in narrative['limitations']))
    section('Limitations', limitations)
    timeline = data['timeline'] if technical else data['timeline'][:20]
    section('Timestamp observations', [table(
        ['UTC', 'Original value', 'Source', 'Meaning', 'Precision (ns)', 'Normalization', 'Evidence ID', 'Slot'],
        [(t['timestamp_utc'], t['original_value'], t['source'], t['meaning'], t['precision_ns'],
          t['normalization_status'], t['evidence_id'], t['slot']) for t in timeline]),
        paragraph(f"{len(data['timeline'])-len(timeline)} additional included observations are retained in report.json; {data['omissions']['timeline']} omitted by the report timeline bound."),
        paragraph('MFT SI and FN, and Created, Modified, MFTChanged and Accessed observations remain distinct. Timestamps do not imply execution or causality.')], 'timeline')
    section('Conclusions', [paragraph(f"This bounded report contains {len(data['claims'])} structured claims. Report generation establishes no broader compromise, intent, attribution or causal conclusion."), paragraph(CAUTION)])
    references = []
    for record in records:
        references += [('heading', record['id'])]
        if technical:
            references += [detail({'source': record['source'], 'context': record['context'], 'warnings': record['warnings']})]
        else:
            references += [detail({'source_sha256': record['source'].get('sha256'), 'warnings': record['warnings']})]
    references.append(paragraph('Complete evidence fields and forward/reverse claim mappings are retained in report.json.'))
    section('Evidence references', references, 'references')
    section('Investigation provenance', [detail(p) for p in data['investigations']] if technical and data['investigations'] else
            [paragraph('Recorded investigation detail is retained in report.json.' if data['investigations'] else 'No V4 investigation supplied. Only report-time operations were performed.')])
    disclosure = {'narrative_assistance': narrative['status'].replace('_', ' ').capitalize()}
    if narrative['status'] != 'NOT_REQUESTED':
        disclosure.update(model=narrative.get('model_metadata', {}).get('model', 'Not reported'),
            transport='Local loopback', tools='None', thinking='Disabled',
            contract=narrative.get('configuration', {}).get('contract', 'Historical claim ordering'))
    disclosure_blocks = [detail(disclosure), paragraph('The model does not create forensic claims. Accepted narrative is checked against claim-backed wording, not merely citation existence.'), paragraph(CAUTION)]
    if technical:
        disclosure_blocks.append(('details', ['Narrative provenance', [f'{k}: {v}' for k, v in rows(narrative) if k not in ('Summary paragraphs', 'Key points', 'Limitations')]]))
    disclosure_blocks.append(paragraph('Output hashes in manifest.json and checksums.sha256 verify file consistency, not signatures or model attestation.'))
    section('AI disclosure and integrity', disclosure_blocks)
    return {'title': text(data['analyst_metadata'].get('title', 'Forensic evidence report')),
            'identity': f"Report {report['report_id']} · {report['created_utc']} · {report['profile']}",
            'status': text(data['status']), 'sections': sections}

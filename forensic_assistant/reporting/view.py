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
    if report.get('presentation_format') == 2:
        from .view_v2 import build as historical
        return historical(report)
    from .boundaries import approved
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
        overview.append(paragraph('Constrained narrative assistance — composed from validated claims and approved report boundaries.'))
        overview.extend(paragraph(item['text']) for item in narrative['summary_paragraphs'])
        summaries = narrative['summary_paragraphs']
        summary_claims = {cid for item in summaries for cid in item['claim_ids']}
        summary_boundaries = {bid for item in summaries for bid in item.get('boundary_ids', [])}
        key_points = [item for item in narrative['key_points'] if not (
            set(item['claim_ids']) <= summary_claims and
            set(item.get('boundary_ids', [])) <= summary_boundaries)]
        overview.append(bullets(item['text'] for item in key_points))
        cited = {cid for item in [*summaries, *key_points] for cid in item['claim_ids']}
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
    # A referenced boundary is already visible in validated prose. Keep each
    # deterministic caution visible exactly once even when the model omits it.
    cited_boundaries = {bid for key in ('summary_paragraphs', 'key_points')
                        for item in narrative.get(key, []) for bid in item.get('boundary_ids', [])}
    for boundary in approved(data):
        if boundary['boundary_id'] not in cited_boundaries:
            overview.append(paragraph(boundary['text']))
    overview.append(bullets(CAUTIONS[k] for k in sorted({kind(r) for r in records})
                           if k in CAUTIONS and k != 'mft'))
    if any(r['fields'].get('truncated_fields') for r in records):
        overview.append(paragraph('Compact claim projections have omissions. The timeline separately retains normalized timestamp observations within the report limit.'))
    section('Executive summary', overview, 'summary')
    scope = [paragraph(data['scope']), paragraph('Empty categories are not investigative negative results.'),
             paragraph('Evidence selection: ' + scope_count)]
    if data['analyst_metadata']:
        scope += [detail(data['analyst_metadata']), paragraph(data['analyst_metadata_basis'])]
    if data.get('redaction_notice'):
        scope.append(paragraph(data['redaction_notice']))
    section('Scope and analyst metadata', scope, 'scope')
    if technical:
        inventory = []
        for sha, item in sorted(data['inventory'].items()):
            inventory += [('heading', 'Source ' + sha), table(['Property', 'Value'], [
                ('SHA-256', sha), ('Artifact types', ', '.join(item['source_types'])),
                ('Stored source record count', item['evidence_count'])])]
        inventory.append(paragraph('Inventory counts describe stored source records, not records individually examined by a model. Full ingestion and location provenance is retained in report.json.'))
        section('Evidence inventory', inventory)
    if technical:
        section('Methodology', [detail(data['methodology']), paragraph('Report-time hydration is separate from historical model exposure. Unrecorded operations are not asserted.')], 'method')
    else:
        section('Methodology', [bullets(data['methodology']['report_operations']), paragraph(data['methodology']['scope'])], 'method')
    if data['investigations']:
        section('Investigation questions', [bullets(p['question'] for p in data['investigations'])])
    observed = []
    for number, record in enumerate(records, 1):
        fields = record['fields']
        selected = {key: value for key, value in fields.items() if key not in
                    ('id', 'objects', 'timestamps', 'warnings', 'truncated_fields')}
        if 'allocated' in selected:
            selected['allocated'] = allocation(selected['allocated'])
        if not technical:
            selected = {k: v for k, v in selected.items() if k in
                        ('source_type', 'record_number', 'sequence', 'allocated', 'event_id', 'executable', 'run_count', 'key', 'url')}
        observed += [('heading', f'Record {number}: ' + subjects(record))]
        if technical:
            observed.append(paragraph('Evidence ID: ' + record['id']))
        observed.append(detail(selected))
        ids = data['graph']['evidence_to_claims'][record['id']]
        if technical:
            observed += [('details', ['Claim provenance', [text(cid) for cid in ids]])]
    observed.append(paragraph('These are report-time normalized evidence projections. Claim bounds and compact omissions remain recorded separately; display grouping does not merge evidence.'))
    section('Observed evidence' if technical else 'Key evidence', observed, 'findings')
    empty_categories = []
    for category in CATEGORIES[1:-1]:
        group = [c for c in data['claims'] if c['category'] == category]
        blocks = []
        for item in group:
            blocks += [('heading', category.capitalize()), detail(item['assertion']),
                       paragraph('Evidence: ' + '; '.join(item['evidence_ids']))]
            if technical:
                blocks += [paragraph('Claim: ' + item['claim_id']), detail({'origins': item['origins']})]
        if blocks or technical:
            section(category.capitalize(), blocks or [paragraph('No ' + category.lower() + ' claims within the selected report scope.')])
        else:
            empty_categories.append(category.lower())
    if empty_categories:
        section('Findings within scope', [paragraph('No claims in these categories within the selected report scope: ' + '; '.join(empty_categories) + '. This is not an investigative negative result.')])
    # Narrative limitations can only restate approved LIMITATION items. Render
    # that authoritative union once, including historical claim-only limitations;
    # keep all original text and support mappings in JSON/manifest.
    deterministic_limits = list(dict.fromkeys([*data['limitations'],
        *(text(item) for c in data['claims'] if c['category'] == 'LIMITATION'
          for item in c['assertion']['items'])]))
    limitations = [bullets(deterministic_limits)]
    if technical:
        limitations.append(detail({'report_limits': data['limits'], 'omissions': data['omissions']}))
    else:
        limitations.append(paragraph(f"Requested bounds: {data['limits']['claims']} claims and {data['limits']['timeline']} timestamp observations; omitted: {data['omissions']['claims']} claims and {data['omissions']['timeline']} timestamp observations."))
    if narrative['status'] in ('REJECTED', 'FAILED', 'FALLBACK'):
        limitations.append(paragraph(narrative.get('reason', 'Narrative unavailable; deterministic summary retained.')))
    section('Limitations', limitations)
    timeline = data['timeline'] if technical else data['timeline'][:20]
    if technical:
        time_blocks = [table(
            ['UTC', 'Original value', 'Source', 'Meaning', 'Precision (ns)', 'Normalization', 'Evidence ID', 'Slot'],
            [(t['timestamp_utc'], t['original_value'], t['source'], t['meaning'], t['precision_ns'],
              t['normalization_status'], t['evidence_id'], t['slot']) for t in timeline])]
    else:
        time_blocks = []
        for number, record in enumerate(records, 1):
            observations = [t for t in timeline if t['evidence_id'] == record['id']]
            if observations:
                time_blocks += [('heading', f'Record {number}: ' + subjects(record)),
                    table(['Timestamp source', 'Meaning', 'UTC'],
                          list(dict.fromkeys((t['source'], t['meaning'], t['timestamp_utc'] or
                               'Not normalized (' + t['normalization_status'] + ')') for t in observations)))]
    time_blocks += [paragraph(f"{len(data['timeline'])-len(timeline)} additional included observations are retained in report.json; {data['omissions']['timeline']} omitted by the report timeline bound."),
        paragraph('MFT SI and FN, and Created, Modified, MFTChanged and Accessed observations remain distinct. Timestamps do not imply execution or causality.')]
    section('Timestamp observations' if technical else 'Time observations', time_blocks, 'timeline')
    section('Conclusions', [paragraph(f"This bounded report contains {len(data['claims'])} structured claims. Report generation establishes no broader compromise, intent, attribution or causal conclusion."), paragraph(CAUTION)])
    references = []
    for number, record in enumerate(records, 1):
        references += [('heading', f'Record {number}: ' + record['id'])]
        primary = {'artifact': kind(record).upper(), 'source_sha256': record['source'].get('sha256'),
                   'warnings': record['warnings']}
        if technical:
            source, context = record['source'], record['context']
            primary.update({key: source.get(key) for key in ('parser', 'parser_version', 'extractor_version', 'locator')})
            names = list(dict.fromkeys(a['display_name'] for a in context.get('source_assertions', []) if a.get('display_name')))
            if names:
                primary['source_display_names'] = names
            for key in ('hostname', 'username', 'volume_root'):
                if context.get(key) is not None:
                    primary[key] = context[key]
            # Conflicting assertions must not disappear or become a single host.
            if context.get('conflicts'):
                primary['context_conflicts'] = context['conflicts']
            assertions = [{k: a[k] for k in ('hostname', 'username', 'volume_root') if a.get(k) is not None}
                          for a in [*context.get('assertions', []), *context.get('source_assertions', [])]]
            assertions = [a for i, a in enumerate(assertions) if a and a not in assertions[:i]]
            if assertions:
                primary['analyst_context_assertions'] = assertions
        references.append(detail(primary))
    references.append(paragraph('Complete evidence fields and forward/reverse claim mappings are retained in report.json.'))
    section('Evidence references', references, 'references')
    if technical and data['investigations']:
        section('Investigation provenance', [detail(p) for p in data['investigations']])
    disclosure = {'narrative_assistance': narrative['status'].replace('_', ' ').capitalize()}
    if narrative['status'] != 'NOT_REQUESTED':
        disclosure.update(model=narrative.get('model_metadata', {}).get('model', 'Not reported'),
                          validation=narrative.get('validation', 'Not recorded').replace('_', ' ').capitalize())
        if technical:
            disclosure.update(transport='Local loopback', tools='None', thinking='Disabled',
                              contract='Grounded narrative of validated claims only')
    disclosure_blocks = [detail(disclosure)]
    if narrative['status'] != 'NOT_REQUESTED':
        disclosure_blocks.append(paragraph('Local model; no tools. Narrative is checked against approved claim wording and report boundaries. Model identity is server-reported, not attested.'))
    disclosure_blocks.append(paragraph('Full prompt, model and narrative support provenance is retained in report.json and manifest.json. Output hashes verify file consistency, not signatures or model attestation.'))
    section('AI disclosure and integrity', disclosure_blocks)
    return {'title': text(data['analyst_metadata'].get('title', 'Forensic evidence report')),
            'identity': f"Report {report['report_id']} · {report['created_utc']} · {report['profile']}",
            'status': text(data['status']), 'sections': sections}

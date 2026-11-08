"""Reusable, deterministic narrative from accepted findings, never model prose.

Each sentence retains indices into the validated findings. No additional case
reads, identity inference, temporal correlation, or claim repair occurs here.
"""
import json
import re


def build(findings, state):
    groups = {}
    for index, row in enumerate(findings.get('observed', [])):
        ids = row.get('evidence_ids', [])
        if not ids:
            continue
        group = groups.setdefault(ids[0], {'evidence_id': ids[0], 'sentences': [], 'seen': {}})
        field = row['field']
        value = row.get('reported_value')
        key = ('download_path' if field in ('/target_path', '/current_path') else field,
               json.dumps(value, ensure_ascii=True, sort_keys=True))
        if key in group['seen']:
            group['sentences'][group['seen'][key]]['observations'].append(index)
            continue
        entry = row.get('recorded_field')
        label = (entry.get('name', 'unnamed EventData field') + ' (original ordinal ' + str(entry.get('ordinal')) + ')'
                 if entry else field.strip('/').replace('/', ' / ').replace('_', ' '))
        match = re.fullmatch(r'/timestamps/(\d+)/utc', field)
        stamps = row.get('timestamp_semantics')
        if match and isinstance(stamps, list) and int(match[1]) < len(stamps):
            stamp = stamps[int(match[1])]
            if stamp.get('utc') == value:
                label = str(stamp.get('type') or label)
        if field in ('/target_path', '/current_path'):
            label = 'download path'
        if field.startswith('/url_chain/'):
            label = 'download URL-chain ' + label
        if field == '/referrer':
            label = 'recorded referrer (not necessarily the download source)'
        truncated = bool(row.get('truncated_fields') or (entry or {}).get('truncated'))
        subject = {'BROWSER': 'The browser record', 'MFT': 'The filesystem metadata',
                   'PREFETCH': 'The Prefetch record', 'EVTX': 'The event', 'REGISTRY': 'The Registry record'}.get(ids[0].split(':', 1)[0], 'The record')
        sentence = subject + ' reports ' + label + ' as ' + json.dumps(value, ensure_ascii=False) + (' [bounded/truncated record].' if truncated else '.')
        group['seen'][key] = len(group['sentences'])
        group['sentences'].append({'text': sentence, 'observations': [index]})
    sections = []
    for eid, group in groups.items():
        family = eid.split(':', 1)[0]
        title, caution = {
            'BROWSER': ('Browser record', 'A download record does not establish opening or execution.' if ':download:' in eid else 'A browser visit does not establish user interaction.'),
            'MFT': ('Filesystem metadata', 'MFT timestamps describe filesystem metadata, not process execution.'),
            'PREFETCH': ('Prefetch record', 'Referenced files are not proof that those files executed.'),
            'EVTX': ('Windows event record', 'Recorded event fields must be interpreted in their provider and event context.'),
            'REGISTRY': ('Registry record', 'Registry presence does not establish execution.'),
        }.get(family, ('Evidence record', 'Recorded values do not establish execution or causation.'))
        sections.append({'title': title, 'evidence_id': eid, 'sentences': group['sentences'], 'caution': caution})
    derived = [{'text': item['text'], 'interpretation': i, 'evidence_ids': item['evidence_ids']}
               for i, item in enumerate(findings.get('interpretations', []))]
    remaining = set(state.get('retrieved_ids', [])) - set(state.get('inspected_ids', []))
    families = sorted({eid.split(':', 1)[0].lower() for eid in remaining})
    return {'contract': 'grounded-narrative-v1', 'records': sections, 'interpretations': derived,
            'relationship_caution': 'Field observations alone do not establish that one event caused another, or that matching paths identify the same file.',
            'coverage': {'inspected_records': len(state.get('inspected_ids', [])),
                         'inspected_families': state.get('inspected_artifact_families', []),
                         'known_records_without_detail_lookup': len(remaining)},
            'next_steps': [('Consider remaining known records in ' + ', '.join(families) + ' if relevant to the question; each lookup requires approval.' if families else 'Review whether further authorized evidence retrieval is needed; no completeness claim is made.'),
                           'Use independent execution evidence to test execution hypotheses; treat incomplete searches as unresolved.']}

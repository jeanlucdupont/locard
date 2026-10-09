"""Human views of bounded deterministic results; never modify evidence projections."""
import json
import ntpath
from collections import Counter

from forensic_assistant.terminal import Palette
from .around_display import display_time
from .layout import pagination, table
from .presentation import safe_text as safe


EVENT_LABELS = {
    'logon': ('Logon', 'success'),
    'failed_logon': ('Failed logon', 'error'),
    'privileged_logon': ('Privileged logon', 'warning'),
    'explicit_credentials': ('Explicit credentials', 'warning'),
    'logoff_request': ('Logoff request', 'key'),
    'logoff': ('Logoff', 'key'),
}
SHARED_DETECTION_CAUTION = 'This observation alone does not establish malicious activity'


def timestamp(value):
    return display_time(value).replace('T', ' ').removesuffix('Z') if value else '-'


def notes(lines, messages, palette):
    messages = list(dict.fromkeys(messages))
    if messages:
        lines.extend(['', palette('heading', 'Forensic notes')])
        lines.extend(palette('warning', '- ' + safe(message)) for message in messages)


def evtx_context(db, records):
    """Text-only context, outside JSON. One bounded hash lookup, no per-row queries.

    File-hash history establishes an ingestion attempt for those bytes, not which
    run created a particular event. Do not label every partial attempt as recovery.
    """
    paths = {}
    for record in records:
        if record.get('file_sha256'):
            paths.setdefault(record['file_sha256'], record.get('source_file') or 'Unknown EVTX file')
    partial = []
    if paths:
        partial = [row[0] for row in db.execute(
            "SELECT DISTINCT file_sha256 FROM ingestion_runs WHERE status='partial' "
            "AND file_sha256 IN (SELECT value FROM json_each(?)) ORDER BY file_sha256",
            (json.dumps(list(paths)),))]
    names = Counter(ntpath.basename(paths[sha]).casefold() for sha in partial)
    labels = [paths[sha] + ' [' + sha + ']' if names[ntpath.basename(paths[sha]).casefold()] > 1
              else ntpath.basename(paths[sha]) for sha in partial]
    return dict(has_evtx=bool(records) or bool(db.execute('SELECT EXISTS(SELECT 1 FROM events)').fetchone()[0]),
                partial_files=labels)


def evtx_notes(context):
    messages = []
    if context.get('has_evtx') is False:
        messages.extend(['Logon analysis depends on available Windows Event Log evidence.',
                         'This case contains no EVTX evidence.',
                         'Missing or incomplete Security logs do not prove that no logons occurred.'])
    for label in context.get('partial_files', []):
        messages.append(label + ': a partial EVTX ingestion attempt is recorded; usable records were retained.')
    if context.get('partial_files'):
        messages.append('Missing records do not prove absence of activity.')
    return messages


def render_logons(result, palette=None, *, context=None, width=None):
    palette = palette or Palette()
    records = result['records']
    lines = []
    if not records:
        lines.append('No logon events found.' if not result['total'] else 'No logon events on this page.')
    else:
        rows = [(timestamp(r.get('timestamp_utc')), EVENT_LABELS.get(r.get('kind'), (r.get('kind'),))[0],
                 r.get('username') or r.get('target_account') or r.get('subject_account')) for r in records]
        roles = {label: role for label, role in EVENT_LABELS.values()}
        def style(role, text):
            return palette(roles.get(text.strip(), 'secondary_text') if role == 'event_category' else role, text)
        def detail(index):
            record = records[index]
            extra = ['    Event ID: ' + safe(record.get('event_id')) +
                     ' | Logon type: ' + safe(record.get('logon_type')) +
                     ' | Source IP: ' + safe(record.get('source_ip')) +
                     ' | Host: ' + safe(record.get('hostname')),
                     '    Process: ' + safe(record.get('process_name')),
                     '    ID: ' + palette('evidence_id', safe(record['id']))]
            warnings = json.loads(record.get('warnings_json') or '[]') + json.loads(record.get('normalization_warnings_json') or '[]')
            extra.extend('    ' + palette('warning', safe(w)) for w in dict.fromkeys(warnings))
            if index + 1 < len(records):
                extra.append('')
            return extra
        lines += table(['TIME (UTC)', 'TYPE', 'USER'], rows, style,
                       minimums=[23, 20, 12], maximums=[23, 20, 50],
                       roles=['key', 'event_category', 'secondary_text'], width=width, text=safe,
                       format_cell=lambda row, col, value, room: value if col < 2 else None, after_row=detail)
    if result['total']:
        unit = ' logon event' + ('s' if result['total'] != 1 else '')
        lines += ['', (pagination(len(records), result['total'], result.get('offset', 0)) or str(len(records))) + unit]
    messages = evtx_notes(context or {})
    if result.get('truncated'):
        messages.append('This is a bounded result page; additional matching events lie outside the displayed page.')
    if records:
        messages.append('Event colors identify categories, not maliciousness. Missing logs or auditing may hide activity.')
    elif (context or {}).get('has_evtx') is not False:
        messages.append('Missing matches do not prove that no logons occurred; available logs and filters bound this result.')
    notes(lines, messages, palette)
    return '\n'.join(lines)


def render_detections(result, palette=None, *, width=None):
    palette = palette or Palette()
    findings = result['detections']
    lines = []
    if not findings:
        lines.append('No detections matched.')
    else:
        rows = [(timestamp(d.get('timestamp')), d['severity'], d['rule_id'], d['rule_name']) for d in findings]
        def style(role, text):
            return palette({'high': 'error', 'medium': 'warning', 'low': 'key'}.get(text.strip(), 'secondary_text')
                           if role == 'severity' else role, text)
        def detail(index):
            finding = findings[index]
            extra = ['    ID: ' + palette('evidence_id', safe(finding['detection_id']))]
            extra.extend('    Evidence: ' + palette('evidence_id', safe(eid)) for eid in finding['evidence_ids'])
            extra.append('    Reason: ' + safe(finding['reason']))
            extra.extend('    ' + palette('warning', safe(message)) for message in dict.fromkeys(finding.get('limitations', []))
                         if message != SHARED_DETECTION_CAUTION)
            if index + 1 < len(findings):
                extra.append('')
            return extra
        lines += table(['TIME (UTC)', 'SEVERITY', 'RULE', 'DESCRIPTION'], rows, style,
                       minimums=[23, 8, 18, 15], maximums=[23, 8, 40, 60],
                       roles=['key', 'severity', 'secondary_text', 'secondary_text'], width=width, text=safe,
                       format_cell=lambda row, col, value, room: value if col < 3 else None, after_row=detail)
    total = result['total_evaluated_detections']
    unit = ' detection' + ('s' if total != 1 else '')
    lines += ['', (f'Showing {len(findings)} of {total}' if len(findings) != total else str(total)) + unit]
    coverage = result['rule_coverage']
    candidate_truncated = any(c['truncated'] for c in coverage)
    lines += ['', palette('heading', 'Rule coverage'),
              f'  Rules evaluated: {len(coverage)}',
              f'  Rules with displayed matches: {len({d["rule_id"] for d in findings})}',
              f'  Candidate evaluations (across rules): {sum(c["evaluated_count"] for c in coverage)}',
              '  Candidate evaluation truncated: ' + ('yes' if candidate_truncated else 'no')]
    messages = ['Severity is static review priority, not confidence or probability of compromise.',
                'A detection does not establish malicious activity by itself.',
                result['caution']]
    if result.get('truncated'):
        messages.append('Detection results are incomplete: display or candidate evaluation bounds were reached.')
    if candidate_truncated:
        messages.append('Counts describe evaluated candidates only; additional matches may exist.')
    notes(lines, messages, palette)
    return '\n'.join(lines)


def render_process_tree(result, palette=None):
    palette = palette or Palette()
    if 'nodes' not in result:
        lines = [palette('key', 'Status: ') + safe(result['status']), palette('warning', safe(result['reason']))]
        lines.extend('    Candidate ID: ' + palette('evidence_id', safe(eid)) for eid in result.get('candidate_evidence_ids', []))
        if 'total' in result:
            lines.append(f"Showing {len(result.get('candidate_evidence_ids', []))} of {result['total']} candidate anchors")
        return '\n'.join(lines)
    records = {r['id']: r for r in result['nodes']}
    supported = [edge for edge in result['relationships'] if edge['status'] in ('CONFIRMED', 'LIKELY')
                 and edge['source_id'] in records and edge['target_id'] in records]
    incoming = Counter(edge['target_id'] for edge in supported)
    # A hierarchy cannot faithfully choose between competing parents.
    edges = [edge for edge in supported if incoming[edge['target_id']] == 1]
    children = {}
    for edge in edges:
        children.setdefault(edge['source_id'], []).append(edge)
    targets = {edge['target_id'] for edge in edges}
    roots = [eid for eid in records if eid not in targets]
    lines = [palette('heading', 'Process evidence')]
    visited, rendered_edges = set(), set()
    for root in [*roots, *records]:
        pending = [(root, 0, None)]
        while pending:
            eid, depth, relation = pending.pop()
            if eid in visited:
                continue
            visited.add(eid)
            record = records[eid]
            indent = '  ' * depth
            label = safe(record.get('process_name') or 'Unknown process') + '  PID ' + safe(record.get('pid'))
            lines.append(indent + palette('key', label) + (' [anchor]' if eid == result['anchor_id'] else ''))
            lines.append(indent + '  ID: ' + palette('evidence_id', safe(eid)))
            lines.append(indent + '  Time (UTC): ' + safe(timestamp(record.get('timestamp_utc'))) + ' | Host: ' + safe(record.get('hostname')))
            if relation:
                rendered_edges.add(id(relation))
                lines.append(indent + '  Parent relationship: ' + palette('warning' if relation['status'] == 'LIKELY' else 'key',
                                                                       safe(relation['status'])) + ': ' + safe(relation['reason']))
            pending.extend((edge['target_id'], depth + 1, edge) for edge in reversed(children.get(eid, [])))
    remaining = [edge for edge in result['relationships'] if id(edge) not in rendered_edges]
    if remaining:
        lines += ['', palette('heading', 'Unresolved or undisplayed relationships')]
        for edge in remaining:
            lines.append(palette('warning', safe(edge['status']) + ': ' + safe(edge['reason'])))
            for label, key in (('Parent ID', 'source_id'), ('Child ID', 'target_id')):
                if edge.get(key):
                    lines.append('  ' + label + ': ' + palette('evidence_id', safe(edge[key])))
            lines.extend('  Supporting ID: ' + palette('evidence_id', safe(eid)) for eid in edge.get('evidence_ids', [])
                         if eid not in (edge.get('source_id'), edge.get('target_id')))
            lines.extend('  Outside returned nodes: ' + palette('evidence_id', safe(eid)) for eid in edge.get('omitted_evidence_ids', []))
    parameters = result['parameters']
    lines += ['', palette('heading', 'Bounds'),
              f"  PID lookback: {parameters['pid_lookback_seconds']} seconds; child window: {parameters['child_window_seconds']} seconds",
              f"  Maximum nodes: {parameters['max_nodes']}; maximum graph depth: {parameters['max_depth']}",
              f'  Returned process records: {len(records)}']
    messages = [*result['limits'], result['caution'],
                'Missing parents or children remain unobserved; this does not establish that they do not exist.']
    messages.extend(message for edge in result['relationships'] for message in edge.get('limitations', []))
    for record in records.values():
        messages.extend(json.loads(record.get('warnings_json') or '[]'))
        messages.extend(json.loads(record.get('normalization_warnings_json') or '[]'))
    notes(lines, messages, palette)
    return '\n'.join(lines)

"""Human views of existing deterministic results; no queries or new relationships."""
import json
import ntpath

from forensic_assistant.correlation.models import time_ns
from forensic_assistant.ingest.validation import is_identifier_note
from forensic_assistant.terminal import Palette
from .around_display import delta, display_time, observation
from .presentation import detail, logon_id, safe


def utc(value):
    return display_time(value).replace('T', ' ').removesuffix('Z') + ' UTC' if value else '-'


def label(record):
    if record is None:
        return 'Evidence outside returned set'
    if record.get('kind') == 'process':
        name = ntpath.basename(record.get('process_name') or 'Unknown process')
        return name + f" [PID {record.get('pid') if record.get('pid') is not None else '-'}]"
    if record.get('source_type', 'evtx') == 'evtx':
        return detail(record)
    return observation(record) or record.get('artifact_type') or 'Unknown artifact'


class View:
    def __init__(self, palette):
        self.palette = palette or Palette()
        self.lines = []

    def line(self, text='', role='secondary_text'):
        # Escape evidence before adding Locard-controlled terminal styling.
        self.lines.append(self.palette(role, safe(text)))

    def section(self, title):
        if self.lines:
            self.lines.append('')
        self.line(title, 'heading')

    def field(self, name, value):
        self.lines.append(self.palette('key', name + ': ') + self.palette('string_value', safe(value)))

    def result(self):
        return '\n'.join(self.lines)


def relationships(view, relations, records):
    """Retain engine statuses and reasons; an association arrow is not causation."""
    headings = {'CONFIRMED': 'Confirmed relationships', 'UNRESOLVED': 'Unresolved'}
    for status in dict.fromkeys(r['status'] for r in relations):
        view.section(headings.get(status, status + ' relationships'))
        cautions = []
        for relation in (r for r in relations if r['status'] == status):
            kind = relation['relationship'].replace('_', ' ').capitalize()
            source = records.get(relation.get('source_id'))
            target = records.get(relation.get('target_id'))
            if relation.get('source_id') and relation.get('target_id'):
                view.line(f'{kind}: {label(source)} -> {label(target)}')
            elif relation.get('target_id'):
                view.line(f'{kind}: {label(target)}')
            else:
                view.line(kind)
            view.line('  ' + relation['reason'])
            cautions.extend(relation.get('limitations', []))
            if relation.get('omitted_evidence_ids'):
                cautions.append('Supporting evidence omitted by the result limit; inspect JSON/raw references.')
        for caution in dict.fromkeys(cautions):
            view.line(caution, 'warning')


def warnings(view, records):
    messages = []
    for record in records:
        messages.extend(record.get('warnings', []))
        messages.extend(json.loads(record.get('warnings_json') or '[]'))
        messages.extend(json.loads(record.get('normalization_warnings_json') or '[]'))
        conflicts = record.get('context', {}).get('conflicts', [])
        if conflicts:
            messages.append('Conflicting context: ' + ', '.join(conflicts))
        if record.get('objects_truncated'):
            messages.append('Object projection is bounded; inspect show/JSON for details.')
        if record.get('observation'):
            messages.append(record['observation'])
    messages = [m for m in dict.fromkeys(messages) if not is_identifier_note(m)]
    if messages:
        view.section('Evidence limitations')
        for message in messages:
            view.line(message, 'warning')


def render_session(result, palette=None):
    view = View(palette)
    #view.section('SESSION')
    view.field('Status', result['status'])
    records = {r['id']: r for r in result.get('records', [])}
    anchor = records.get(result.get('anchor_id'))
    if anchor:
        for name, value in (
            ('User', anchor.get('username') or anchor.get('target_account')),
            ('Host', result.get('hostname')),
            ('Logon ID', logon_id(anchor)),
            ('Logon type', anchor.get('logon_type')),
            ('Reported process', ntpath.basename(anchor.get('process_name') or '') or None),
            ('PID', anchor.get('pid')),
            ('Start', utc(result.get('start'))),
        ):
            view.field(name, value)
        # Only a returned, confirmed logoff relationship establishes an observed end.
        logoff_ids = {r['id'] for r in records.values()
                      if r.get('kind') == 'logoff' and r.get('timestamp_utc') == result.get('end')}
        observed = result.get('end_reason') == 'logoff' and any(
            r['status'] == 'CONFIRMED' and r.get('target_id') in logoff_ids
            and r.get('source_id') == anchor['id'] for r in result['relationships']
        )
        view.field('End', utc(result['end']) if observed else 'Not observed')
        if not observed:
            view.line('No confirmed session-ending logoff in the returned evidence.')
        view.field('Correlation boundary', utc(result.get('end')) + ' (' + result.get('end_reason', 'unknown') + ')')
        view.field('Maximum correlation window', str(result['parameters']['max_hours']) + ' hours')
    if result.get('reason'):
        view.line(result['reason'], 'warning')
    if result.get('candidate_anchor_ids'):
        view.field('Candidate anchors', len(result['candidate_anchor_ids']))
        view.line('Use JSON/raw for full candidate evidence IDs and --evidence to disambiguate.')
    if records:
        view.section('Activity in returned evidence')
        for record in records.values():
            view.line(f"{utc(record.get('timestamp_utc'))} | {record.get('event_id', '-')} | {label(record)}")
    relationships(view, result.get('relationships', []), records)
    if result.get('truncated'):
        view.line('Session candidate limit reached; results are incomplete.', 'warning')
    warnings(view, records.values())
    return view.result()


def render_investigation(result, palette=None):
    from forensic_assistant.v2_cli import anchor_time
    from . import mixed_display
    from types import SimpleNamespace

    view = View(palette)
    #view.section('INVESTIGATION')
    records = {r['id']: r for r in result['evidence_records']}
    anchor = result['direct_evidence'][0]
    parameters = result['parameters']
    def project(record):
        # Parent/child arrows belong in investigate's relationship section.
        # Keep its established process/PID label in temporal context.
        return safe(label(record)) if record.get('kind') == 'process' else mixed_display.object_text(record)
    try:
        stamp = anchor_time(anchor, parameters.get('timestamp_slot'), require_slot=True)
    except ValueError:
        stamp = None
    view.section('Anchor')
    view.field('Time', utc(stamp) if stamp else 'No unambiguous selected timestamp')
    if stamp:
        slots = [t['slot'] for t in anchor['timestamps'] if t['timestamp_utc'] == stamp
                 and (not parameters.get('timestamp_slot') or t['slot'] == parameters['timestamp_slot'])]
        view.field('Timestamp slot', ', '.join(slots))
    view.field('Type', mixed_display.artifact(anchor))
    obj = project(anchor)
    # The shared object projection is already escaped, with literal path separators.
    view.lines.append(view.palette('key', 'Object: ') + view.palette('string_value', obj))
    view.field('Host', 'CONFLICT' if anchor.get('context', {}).get('conflicts') else anchor.get('hostname'))
    if anchor.get('username'):
        view.field('User', anchor['username'])
    view.field('Source', '; '.join(s['display_name'] for s in anchor.get('context', {}).get('source_assertions', [])) or 'unassigned')
    if not stamp:
        slots = [t['slot'] for t in anchor['timestamps'] if t['timestamp_utc']]
        view.line('Temporal investigation requires a timestamp slot.' if slots else 'No usable timestamp slots; temporal investigation not performed.', 'warning')
        if slots:
            view.line('Available slots:')
            for slot in slots:
                view.line('  ' + slot)
            view.line('Re-run with --timestamp-slot "<one of the slots above>".')
    if anchor.get('command_line'):
        view.field('Command', anchor['command_line'])
    relationships(view, result['correlated_evidence'], records)
    view.section('Nearby evidence')
    temporal_searched = any(c.get('query') == 'temporal' for c in result['source_query_counts'])
    if result['temporal_neighbor_ids'] and stamp:
        view.line('Temporal proximity only; not a causal relationship.')
        rows = []
        for eid in result['temporal_neighbor_ids']:
            record = records.get(eid)
            if record is None:
                continue
            for t in record['timestamps']:
                value = t['timestamp_utc']
                if value and abs(time_ns(value) - time_ns(stamp)) <= parameters['seconds'] * 1_000_000_000:
                    rows.append(dict(record, timestamp=t, timestamp_utc=value))
        # Preserve investigate's nearest-first policy, with stable observation ties.
        rows.sort(key=lambda r: (abs(time_ns(r['timestamp_utc']) - time_ns(stamp)),
                                 r['timestamp_utc'], r['id'], r['timestamp']['slot']))
        view.lines.append(mixed_display.render(
            dict(records=rows, total=len(rows), offset=0, truncated=False), palette=view.palette,
            anchor=anchor, stamp=stamp, args=SimpleNamespace(timestamp_slot=parameters.get('timestamp_slot'), ids=False),
            anchor_header=False, warning_summary=False, retain_userassist=True, wrap_objects=True,
            omission_help='use investigate --json or --raw to inspect all retrieved evidence and timestamp slots.',
            object_projection=project))
    elif not temporal_searched:
        view.line('Temporal search not performed; resolve the anchor timestamp and host context.')
    else:
        view.line('None in the returned result.')
    relationships(view, result['unresolved_relationships'], records)
    view.section('Detections')
    if not result['detections']:
        view.line('None in the returned result.' if stamp else 'Not evaluated; temporal anchor unresolved.')
    for finding in result['detections']:
        view.line(f"{finding['severity']} | {finding['rule_id']} | {finding['rule_name']}")
        view.line(finding['reason'])
        for limitation in finding.get('limitations', []):
            view.line(limitation, 'warning')
        if finding.get('omitted_evidence_ids'):
            view.line('Supporting evidence omitted by the result limit; inspect JSON/raw references.', 'warning')
    view.section('Coverage')
    # artifact_distribution includes known-but-omitted records; count only the
    # returned evidence for this summary instead of mislabeling that distribution.
    kinds = sorted({r['source_type'].upper() for r in records.values()})
    view.line(f"{len(records)} evidence records retrieved | " + ', '.join(kinds) if temporal_searched else
              f"{len(records)} evidence records retained for anchor/snapshot review; temporal search not performed.")
    if temporal_searched:
        view.field('Temporal search window', '+/- ' + str(parameters['seconds']) + ' seconds')
    for limitation in result['limits']:
        view.line(limitation, 'warning')
    coverage = result['coverage']
    if coverage['events_without_utc']:
        view.line(f"Case contains {coverage['events_without_utc']} events without UTC timestamps.", 'warning')
    if coverage['incomplete_ingestion_runs']:
        view.line(f"Case contains {coverage['incomplete_ingestion_runs']} incomplete ingestion runs.", 'warning')
    investigation_notes(view, records.values())
    return view.result()


def investigation_notes(view, records):
    """Group interpretation notes once; retain actual unknown warnings/truncation."""
    from .artifact_notes import PREFETCH, PREFETCH_PARSER, USERASSIST, USERASSIST_PARSER
    from .presentation import PREFETCH_CAUTIONS
    from .registry_display import KEY_CORRUPTION
    records = list(records)
    prefetch = [r for r in records if r['source_type'] == 'prefetch']
    userassist = [r for r in records if (r.get('detail') or {}).get('userassist')]
    for title, selected, notes, parser in (
        ('Prefetch', prefetch, PREFETCH, PREFETCH_PARSER),
        ('UserAssist', userassist, USERASSIST, USERASSIST_PARSER)
    ):
        if not selected:
            continue
        view.section(title + ' forensic notes')
        for note in notes:
            view.line('- ' + note, 'warning')
        if title == 'UserAssist' or any('Referenced files are not all executed images; directory tables are not exposed by this binding'
                                      in r.get('warnings', []) for r in selected):
            view.section(title + ' parser note')
            view.line('- ' + parser)
    registry = [r for r in records if r['source_type'] == 'registry']
    if registry:
        view.section('Registry forensic note')
        view.line('Registry key LastWrite does not establish individual value creation time.')
    corrupt = {r['id'] for r in registry if KEY_CORRUPTION in r.get('warnings', [])}
    if corrupt:
        view.line(f'Warning: parser reported key corruption for {len(corrupt)} retrieved Registry records; '
                  'the flag alone does not establish unreadable data.', 'warning')
    projected = []
    standard = {
        'Prefetch records execution timestamps; retained runs are incomplete',
        'Registry key last-write; not individual value creation',
        'Registry value in snapshot; associated timestamp belongs to containing key'
    }
    for record in records:
        r = dict(record)
        r['warnings'] = [w for w in r.get('warnings', []) if w != KEY_CORRUPTION and
                         not (r['source_type'] == 'prefetch' and w in PREFETCH_CAUTIONS)]
        if r.get('observation') in standard or (r.get('detail') or {}).get('userassist'):
            r.pop('observation', None)
        projected.append(r)
    warnings(view, projected)

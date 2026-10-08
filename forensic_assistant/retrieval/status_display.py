"""Concise read-only status projection; stored run statuses are never rewritten."""
import json
from collections import Counter

from forensic_assistant.artifacts.registry_logs import is_log
from forensic_assistant.terminal import Palette
from .presentation import safe, safe_path
from .layout import fit


def error_details(db):
    """Existing error rows with optional structured locators; no schema changes."""
    result = []
    for row in db.execute('SELECT e.*,a.locator_json FROM ingestion_errors e '
                          'LEFT JOIN artifact_errors a ON a.error_id=e.id ORDER BY e.id'):
        item = dict(row)
        locator = item.pop('locator_json')
        if locator:
            item['diagnostics'] = json.loads(locator)
        result.append(item)
    return result


def context(db):
    # Extra text-only metadata stays outside the established status JSON contract.
    runs = {}
    for row in db.execute('SELECT run_id,source_type,parameters_json FROM artifact_runs'):
        parameters = json.loads(row['parameters_json'])
        runs[row['run_id']] = dict(source_type=row['source_type'], parameters=parameters)
    return dict(runs=runs,
                dirty_hives=db.execute('SELECT count(*) FROM registry_hives WHERE dirty<>0').fetchone()[0],
                hive_warnings=[r[0] for r in db.execute('SELECT DISTINCT warnings_json FROM registry_hives ORDER BY warnings_json LIMIT 6')],
                error_summaries=[dict(r) for r in db.execute('''SELECT message,count(*) AS count FROM ingestion_errors
                    WHERE run_id NOT IN (SELECT r.id FROM ingestion_runs r JOIN artifact_runs a ON a.run_id=r.id
                    WHERE a.source_type='registry' AND (lower(r.source_file) LIKE '%.log1' OR lower(r.source_file) LIKE '%.log2'))
                    GROUP BY message ORDER BY count(*) DESC,message LIMIT 6''')])


def render(result, case, details, palette=None):
    palette = palette or Palette()
    lines = [palette('heading', 'CASE STATUS'), 'Case: ' + safe_path(case), '', palette('heading', 'Evidence')]
    counts = result.get('artifact_counts', {})
    lines.append('  Total evidence records: ' + f'{sum(counts.values()):,}')
    for kind, count in sorted(counts.items()):
        lines.append('  ' + safe(kind.capitalize()) + ': ' + f'{count:,}')
        if kind == 'browser':
            for label, key in [('Visits', 'browser_visit'), ('Downloads', 'browser_download')]:
                lines.append('    ' + label + ': ' + str(result.get('browser_counts', {}).get(key, 0)))
    lines.append('  Timeline observations: ' + f"{result.get('timeline_observations', 0):,}")
    outcomes, companions, historical = Counter(), Counter(), Counter()
    log_files = set()
    for run in result.get('ingestion_runs', []):
        meta = details['runs'].get(run['id'], {})
        classified = meta.get('parameters', {}).get('classification') == 'registry_transaction_log'
        if classified or (meta.get('source_type') == 'registry' and is_log(run['source_file'])):
            (companions if classified else historical)[run['status']] += 1
            log_files.add(run['source_file'])
        else:
            outcomes[run['status']] += 1
    lines += ['', palette('heading', 'Ingestion (file attempts)')]
    for status in ('complete', 'partial', 'failed'):
        lines.append('  ' + status.capitalize() + ': ' + f'{outcomes.pop(status, 0):,}')
    for status, count in sorted(outcomes.items()):
        lines.append('  ' + safe(status) + ': ' + f'{count:,}')
    def summary(counter):
        return ', '.join(safe(status) + ': ' + str(count) for status, count in sorted(counter.items()))
    if companions:
        lines.append('  Companion log attempts: ' + summary(companions))
    if historical:
        lines.append('  Historical companion log attempts: ' + summary(historical))
    lines.append('  Recorded ingestion errors: ' + f"{sum(r['error_count'] for r in result.get('ingestion_runs', [])):,}")
    coverage = result.get('source_coverage', {})
    lines += ['', palette('heading', 'Sources'), '  Total: ' + str(coverage.get('total', 'unknown (legacy schema)'))]
    for source in coverage.get('sources', [])[:5]:
        lines += ['  ' + fit(safe(source['display_name']), 100),
                  '    Analyst host: ' + safe(source.get('hostname') or 'unknown') +
                  '; files: ' + str(source['files']) + '; evidence records: ' + f"{source['evidence_count']:,}"]
        if source.get('artifact_hostnames'):
            lines.append('    Artifact hosts: ' + fit(safe(', '.join(source['artifact_hostnames'])), 120))
    if coverage.get('total', 0) > 5:
        lines.append(f"  Showing {min(5, len(coverage.get('sources', [])))} of {coverage['total']} sources; use status --json")
    lines.append('  Unfinished batches: ' + str(coverage.get('unfinished_batches', 'unknown')))
    limitations = list(coverage.get('limitations', []))
    if coverage.get('unknown_hostname_sources'):
        limitations.append(f"Analyst hostname unknown for {coverage['unknown_hostname_sources']} sources; source membership alone does not establish a host")
    if coverage.get('unassigned_files'):
        limitations.append(f"Unassigned evidence files: {coverage['unassigned_files']}")
    if any(s.get('host_conflict') for s in coverage.get('sources', [])):
        limitations.append('Source-level conflicting hostname assertions; record hosts are resolved individually; review source details')
    if log_files:
        limitations.append(f'Registry transaction-log replay is not supported: {len(log_files)} companion file paths in ingestion history')
    if historical:
        limitations.append('Historical companion attempts predate classification; their recorded statuses/errors remain unchanged, not successful hive parsing')
    if details['dirty_hives']:
        limitations.append(f"Dirty Registry hives: {details['dirty_hives']}; transaction logs were not replayed; snapshots may be inconsistent (dirty does not mean corrupted)")
    from .registry_display import DIRTY_WARNING
    for raw in details['hive_warnings']:
        limitations.extend(w for w in json.loads(raw) if w != DIRTY_WARNING)
    for error in details['error_summaries'][:5]:
        limitations.append(f"Recorded error ({error['count']}): " + error['message'])
    if len(details['error_summaries']) > 5 or len(details['hive_warnings']) > 5:
        limitations.append('Additional error/warning groups omitted; inspect detailed evidence and ingestion metadata')
    for error in result.get('ingestion_errors', []):
        diagnostic = error.get('diagnostics', {})
        if diagnostic.get('format') == 'evtx' and diagnostic.get('resume_offset') is not None:
            limitations.append(
                f"EVTX recovery resumed at file offset {diagnostic['resume_offset']}; "
                f"{diagnostic['parsed_records_after_error']} later records parsed successfully "
                '(parser anomaly remains recorded; see status --json)')
    if result.get('caution'):
        limitations.append(result['caution'])
    limitations = list(dict.fromkeys(limitations))
    if limitations:
        lines += ['', palette('heading', 'Limitations')]
        lines += [palette('warning', '  ' + fit(safe(value), 180)) for value in limitations[:12]]
        if len(limitations) > 12:
            lines.append(f'  Showing 12 of {len(limitations)} limitation summaries')
    return '\n'.join(lines)

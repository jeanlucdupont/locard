"""Concise read-only status projection; stored run statuses are never rewritten."""
from forensic_assistant.terminal import aligned_lines
import json
from pathlib import Path
from collections import Counter

from forensic_assistant.artifacts.registry_logs import is_log
from forensic_assistant.terminal import Palette, field
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


def context(db, *, verbose=True):
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
                    GROUP BY message ORDER BY count(*) DESC,message LIMIT 6''')] if verbose else [])


def render(result, case, details, palette=None, *, verbose=False):
    palette = palette or Palette()
    lines = [palette('heading', 'CASE STATUS'), field('Case', safe_path(case) if verbose else (Path(case).parent.name or Path(case).stem), palette), '', palette('heading', 'Evidence')]
    counts = result.get('artifact_counts', {})
    lines.append(field('  Total evidence records', f'{sum(counts.values()):,}', palette))
    for kind, count in sorted(counts.items()):
        lines.append(field('  '+safe(kind.capitalize()), f'{count:,}', palette))
        if kind == 'browser':
            for label, key in [('Visits', 'browser_visit'), ('Downloads', 'browser_download')]:
                lines.append(field('    '+label, result.get('browser_counts', {}).get(key, 0), palette))
    lines.append(field('  Timeline observations', f"{result.get('timeline_observations', 0):,}", palette))
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
        lines.append(field('  '+status.capitalize(), f'{outcomes.pop(status, 0):,}', palette))
    for status, count in sorted(outcomes.items()):
        lines.append(field('  '+safe(status), f'{count:,}', palette))
    def summary(counter):
        return ', '.join(field(safe(status), count, palette) for status, count in sorted(counter.items()))
    if companions:
        lines.append('  Companion log attempts: ' + summary(companions))
    if historical:
        lines.append('  Historical companion log attempts: ' + summary(historical))
    lines.append(field('  Recorded ingestion errors', f"{sum(r['error_count'] for r in result.get('ingestion_runs', [])):,}", palette))
    coverage = result.get('source_coverage', {})
    lines += ['', palette('heading', 'Sources'), field('  Total', coverage.get('total', 'unknown (legacy schema)'), palette)]
    for source in (coverage.get('sources', [])[:5] if verbose else []):
        lines += ['  ' + palette('value', fit(safe(source['display_name']), 100)),
                  field('    Source ID', source['source_id'], palette),
                  field('    Analyst host', safe(source.get('hostname') or 'unknown'), palette),
                  field('    Files', source['files'], palette), field('    Evidence records', f"{source['evidence_count']:,}", palette)]
        if source.get('artifact_hostnames'):
            lines.append(field('    Artifact hosts', fit(safe(', '.join(source['artifact_hostnames'])), 120), palette))
    if verbose and coverage.get('total', 0) > 5:
        lines.append(f"  Showing {min(5, len(coverage.get('sources', [])))} of {coverage['total']} sources; use status --json")
    lines.append(field('  Unfinished batches', coverage.get('unfinished_batches', 'unknown'), palette))
    limitations = list(coverage.get('limitations', []))
    if not verbose:
        from forensic_assistant.source_cli import identity_note
        sources = coverage.get('sources', [])
        for n, source in enumerate(sources, coverage.get('offset', 0) + 1):
            note = identity_note(source)
            if note:
                # Keep different sources distinct, including identical names.
                prefix = f'Source {n}: ' if coverage.get('total', len(sources)) > 1 else ''
                limitations.append(prefix + note)
        unlisted = coverage.get('unknown_hostname_sources', 0) - sum(not s.get('hostname') for s in sources)
        if unlisted > 0:
            limitations.append(f'Source computer identity has not been confirmed for {unlisted} additional sources outside this source page.')
        if log_files or details['dirty_hives']:
            limitations.append('Registry recovery incomplete: transaction logs were not replayed' +
                (f"; {details['dirty_hives']} hives are marked dirty." if details['dirty_hives'] else '.'))
    if verbose and coverage.get('unknown_hostname_sources'):
        limitations.append(f"Analyst hostname unknown for {coverage['unknown_hostname_sources']} sources; source membership alone does not establish a host")
    if coverage.get('unassigned_files'):
        limitations.append(f"Unassigned evidence files: {coverage['unassigned_files']}")
    if verbose and any(s.get('host_conflict') for s in coverage.get('sources', [])):
        limitations.append('Source-level conflicting hostname assertions; record hosts are resolved individually; review source details')
    if verbose and log_files:
        limitations.append(f'Registry transaction-log replay is not supported: {len(log_files)} companion file paths in ingestion history')
    if verbose and historical:
        limitations.append('Historical companion attempts predate classification; their recorded statuses/errors remain unchanged, not successful hive parsing')
    if verbose and details['dirty_hives']:
        limitations.append(f"Dirty Registry hives: {details['dirty_hives']}; transaction logs were not replayed; snapshots may be inconsistent (dirty does not mean corrupted)")
    from .registry_display import DIRTY_WARNING
    for raw in details['hive_warnings']:
        limitations.extend(w for w in json.loads(raw) if w != DIRTY_WARNING)
    if len(details['hive_warnings']) > 5:
        limitations.append('Additional hive warning groups omitted; inspect detailed evidence metadata')
    for meta in details['runs'].values():
        acquisition = meta.get('parameters', {}).get('acquisition') or {}
        if acquisition.get('source_state') == 'live mounted volume; not frozen':
            from forensic_assistant.artifacts.ntfs_acquisition import LIVE_LIMITATION
            limitations.append(LIVE_LIMITATION)
    for error in result.get('ingestion_errors', []):
        diagnostic = error.get('diagnostics', {})
        if diagnostic.get('format') == 'evtx' and diagnostic.get('resume_offset') is not None:
            limitations.append(
                f"EVTX recovery resumed at file offset {diagnostic['resume_offset']}; "
                f"{diagnostic['parsed_records_after_error']} later records parsed successfully "
                '(parser anomaly remains recorded; see status --json)')
    generic = 'Missing events do not establish absence of activity. Auditing and supplied logs may be incomplete.'
    if result.get('caution') and result['caution'] != generic:
        limitations.append(result['caution'])
    limitations.insert(0, 'No evidence has been ingested. Activity cannot be assessed.' if not sum(counts.values()) else
        'The absence of matching evidence records does not establish that no activity occurred. Available forensic data may be incomplete.')
    limitations = list(dict.fromkeys(limitations))
    if limitations:
        lines += ['', palette('heading', 'Limitations')]
        lines += [palette('forensic_note', '  ' + fit(safe(value), 180)) for value in limitations[:12]]
        if len(limitations) > 12:
            lines.append(f'  Showing 12 of {len(limitations)} limitation summaries')
    if verbose:
        lines += diagnostic_lines(result, details, palette)
    return aligned_lines(lines)


def diagnostic_lines(result, details, palette):
    """Recorded history is neutral regardless of the original exception wording."""
    runs = {row['id']: row for row in result.get('ingestion_runs', [])}
    grouped = Counter()
    for error in result.get('ingestion_errors', []):
        run_id = error.get('run_id')
        artifact = details['runs'].get(run_id, {}).get('source_type', 'unclassified artifact')
        status = runs.get(run_id, {}).get('status', 'unknown')
        grouped[(artifact, status, error['stage'], error['message'])] += 1
    lines = ['', palette('heading', 'Ingestion diagnostics'),
             field('  Per-attempt elapsed time', 'unavailable (not recorded)', palette, role='unknown')]
    if not grouped:
        lines.append(palette('label', '  No recorded ingestion errors.'))
    for (artifact, status, stage, message), count in sorted(grouped.items())[:100]:
        lines += [palette('label', f'  {safe(artifact)} / {safe(status)} attempt / {safe(stage)}'),
                  field('    Occurrences', f'{count:,}', palette),
                  palette('label', '    Original diagnostic: ' + safe(message))]
    if len(grouped) > 100:
        lines.append(palette('label', 'Showing 100 groups; use case status --json for all recorded errors.'))
    lines.append(palette('label', 'Attempt outcomes and recorded parser errors are separate counts; error counts do not measure lost records.'))
    return lines

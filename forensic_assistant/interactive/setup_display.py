"""Human setup projections; stored ingestion counters and statuses stay intact."""
import json
import sys
import time

from forensic_assistant.retrieval.presentation import safe_text as safe
from forensic_assistant.terminal import Palette, capable, replace_progress_line


def role(status):
    return ('success' if status == 'complete' else 'error' if status in ('failed', 'changed')
            else 'secondary_text' if status == 'not selected' else 'warning')


def category_line(kind, progress, palette):
    status = progress.outcome
    return (palette('key', kind) + ': ' + palette(role(status), status) + ' | ' +
            palette('success' if progress.records else 'error' if status == 'failed' else 'secondary_text',
                    f'{progress.records:,} records') + ' | ' +
            palette('warning' if progress.duplicates else 'success', f'{progress.duplicates:,} duplicates') + ' | ' +
            palette('error' if progress.errors else 'success', f'{progress.errors:,} errors'))


def file_outcomes(statuses, palette):
    return 'File outcomes: ' + ', '.join(palette(role(status), f'{count:,} {status}')
                                        for status, count in statuses.items() if count)


class FileProgress:
    """No background worker/reader and no mid-file estimates; use completed files."""
    def __init__(self, kind, total, palette, *, stream=None, clock=time.monotonic):
        self.kind, self.total, self.palette = kind, total, palette
        self.stream = sys.stdout if stream is None else stream
        self.clock = clock
        self.started = clock()
        self.last = None
        self.inplace = capable(self.stream)

    def update(self, processed, records):
        current = self.clock()
        interval = .1 if self.inplace else 5
        if self.last is not None and processed < self.total and current - self.last < interval:
            return
        self.last = current
        elapsed = max(0, int(current - self.started))
        percent = (100 * processed // self.total) if self.total else 0
        text = (f'{self.kind}  {processed} / {self.total} files  {percent}%  '
                f'{elapsed // 60:02d}:{elapsed % 60:02d} elapsed  {records:,} records stored')
        if not self.inplace or not replace_progress_line(self.palette('key', text), self.stream):
            print(self.palette('key', text), file=self.stream, flush=True)

    def close(self):
        if self.inplace:
            replace_progress_line('', self.stream)


def diagnostic_groups(db, run_ids=None):
    """Only two known verification notes qualify, with retained records + diagnostics."""
    groups = {}
    for row in db.execute('''SELECT e.*,a.locator_json,r.status,r.inserted_count,r.duplicate_count,
                                   r.file_sha256 FROM ingestion_errors e JOIN ingestion_runs r ON r.id=e.run_id
                            LEFT JOIN artifact_errors a ON a.error_id=e.id ORDER BY e.id'''):
        if run_ids is not None and row['run_id'] not in run_ids:
            continue
        try:
            details = json.loads(row['locator_json'] or '{}')
        except (ValueError, TypeError):
            details = {}
        if not isinstance(details, dict):
            details = {}
        after = details.get('parsed_records_after_error', 0)
        retained = (row['status'] == 'partial' and row['file_sha256'] is not None
                    and row['inserted_count'] + row['duplicate_count'] > 0
                    and type(after) is int and after > 0 and details.get('format') == 'evtx')
        limitation = retained and row['stage'] == 'parse' and (
            row['message'] == 'File header verification failed' or (
                row['message'] == 'Validated EVTX chunks extend beyond the declared chunk count'
                and details.get('recovery') == 'validated_contiguous_dirty_tail'))
        key = (row['stage'], row['message'], bool(limitation))
        group = groups.setdefault(key, dict(stage=row['stage'], message=row['message'],
                                          limitation=bool(limitation), count=0, runs=set()))
        group['count'] += 1
        group['runs'].add(row['run_id'])
    return list(groups.values())


def print_diagnostics(db, palette):
    groups = diagnostic_groups(db)
    for limitation, heading in ((True, 'Parser verification limitations (records retained)'),
                                (False, 'Other recorded ingestion errors')):
        selected = [g for g in groups if g['limitation'] == limitation]
        if selected:
            print(palette('key', heading))
        for group in selected:
            print(palette('forensic_note' if limitation else 'error',
                          '- ' + safe(group['message']) + f" — {group['count']:,} occurrences across "
                          f"{len(group['runs']):,} ingestion attempts"))


def completion(plan, outcomes, stored):
    if not plan.items:
        return 'Case created. No evidence ingested.'
    if not stored:
        if outcomes and all(value == 'failed' for value in outcomes.values()):
            return 'Case created, but selected evidence ingestion failed.'
        return 'Case created. No evidence records stored; review the ingestion outcomes.'
    if plan.deferred or plan.limited or any(value != 'complete' for value in outcomes.values()):
        return 'Case created. Ingestion completed with limitations.'
    return 'Case ready.'

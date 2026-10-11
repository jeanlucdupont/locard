"""Human setup projections; stored ingestion counters and statuses stay intact."""
import json
import sys
import time

from forensic_assistant.retrieval.presentation import safe_text as safe
from forensic_assistant.terminal import Palette, capable, replace_progress_line


def role(status):
    return ('success' if status == 'complete' else 'error' if status in ('failed', 'changed', 'requires extraction')
            else 'secondary_text' if status in ('not selected', 'no supported history found') else 'warning')


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
                                   r.file_sha256,r.source_file FROM ingestion_errors e JOIN ingestion_runs r ON r.id=e.run_id
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
        no_records = row['inserted_count'] + row['duplicate_count'] == 0 and row['status'] in ('partial', 'failed', 'changed')
        key = (row['stage'], row['message'], bool(limitation), no_records)
        group = groups.setdefault(key, dict(stage=row['stage'], message=row['message'],
                                          limitation=bool(limitation), no_records=no_records, count=0, runs=set(), files=set()))
        group['count'] += 1
        group['runs'].add(row['run_id'])
        group['files'].add(row['source_file'])
    return list(groups.values())


def human_limitation(message, kind=None, count=1):
    from forensic_assistant.artifacts.registry_logs import LIMITATION
    if message == LIMITATION:
        return ('Registry transaction logs detected but not replayed. '
                'Recent uncommitted Registry changes may be missing.')
    if message == 'Source signature does not match requested artifact type':
        formats = {'registry': 'Registry hives', 'prefetch': 'Prefetch files', 'mft': 'MFT files',
                   'evtx': 'Windows event logs', 'browser': 'supported browser History files'}
        if kind in formats:
            if count == 1:
                return f'1 file was skipped because it was not a valid {formats[kind][:-1]}.'
            return f'{count} files were skipped because they were not valid {formats[kind]}.'
        return 'Some discovered files did not match the expected artifact format and were skipped.'
    return safe(message) + f' ({count} occurrences)'


def evtx_diagnostic(group):
    count = len(group['files'])
    message = group['message']
    files = f'{count} file' + ('s' if count != 1 else '')
    if message == 'File header verification failed':
        if group['limitation']:
            return f'{files} had header verification issues, but records were recovered and retained.'
        if group['no_records']:
            return f'{files} could not be successfully ingested because header verification failed; no records were retained.'
        return f'{files} had header verification issues; inspect detailed ingestion diagnostics for the evidence outcome.'
    if message == 'Validated EVTX chunks extend beyond the declared chunk count' and group['limitation']:
        return f'{files} contained additional validated EVTX chunks beyond the declared count; those records were retained.'
    return None


def print_diagnostics(db, palette, *, run_ids=None):
    groups = diagnostic_groups(db, run_ids)
    evtx = [(g, evtx_diagnostic(g)) for g in groups]
    selected = [(g, text) for g, text in evtx if text]
    if selected:
        print(palette('key', 'EVTX ingestion limitations'))
        for group, text in selected:
            print('- ' + palette('forensic_note' if group['limitation'] else 'error', text))
    other = [g for g, text in evtx if not text]
    if other:
        print(palette('key', 'Other ingestion limitations and errors'))
    from forensic_assistant.artifacts.registry_logs import LIMITATION
    for group in other:
        print('- ' + palette('forensic_note' if group['message'] == LIMITATION else 'error',
                             human_limitation(group['message'], count=group['count'])))


def completion_line(message, palette):
    if message.startswith('Case created.'):
        return palette('success', 'Case created.') + palette('warning', message[len('Case created.'):])
    if message.startswith('Case created,'):
        return palette('success', 'Case created') + palette('error', message[len('Case created'):])
    return palette('success', message)


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


def addition_line(plan, outcomes, totals, palette):
    if totals.records:
        text = palette('success', 'Evidence added to case.')
        if plan.deferred or plan.limited or any(value != 'complete' for value in outcomes.values()):
            text += ' ' + palette('warning', 'Ingestion completed with limitations.')
        return text
    if totals.duplicates:
        text = palette('warning', 'No new evidence records were added. Existing evidence was recognized as duplicate.')
        if any(value != 'complete' for value in outcomes.values()):
            text += ' ' + palette('warning', 'Ingestion completed with limitations.')
        return text
    if outcomes and all(value == 'failed' for value in outcomes.values()):
        return palette('error', 'No evidence was added. Selected evidence ingestion failed.')
    return palette('warning', 'No evidence records were added. Review the ingestion outcomes.')


def duration(seconds):
    """Whole monotonic seconds; never imply sub-second measurement precision."""
    seconds = max(0, int(seconds))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f'{hours} hr {minutes} min'
    if minutes:
        return f'{minutes} min {seconds} sec'
    return f'{seconds} sec'

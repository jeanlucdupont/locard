"""Human setup projections; stored ingestion counters and statuses stay intact."""
import json
import sys
import time
import threading

from forensic_assistant.retrieval.presentation import safe_text as safe
from forensic_assistant.ingest.presentation import elapsed_line
from forensic_assistant.terminal import Palette, capable, replace_progress_line, supports_unicode


def role(status):
    return ('success' if status == 'complete' else 'error' if status in ('failed', 'changed', 'requires extraction')
            else 'unknown' if status == 'unsupported' else 'label' if status in ('not selected', 'no supported history found') else 'warning')


def category_line(kind, progress, palette):
    status = progress.outcome
    return (palette('value', kind) + ': ' + palette(role(status), status) + ' | ' +
            palette('value',
                    f'{progress.records:,} records retained') + ' | ' +
            palette('value', f'{progress.duplicates:,} duplicates') + ' | ' +
            palette('value', f'{progress.errors:,} error' + ('' if progress.errors == 1 else 's')))


def file_outcomes(statuses, palette, kind=None):
    return 'File outcomes: ' + ', '.join(palette(role(status), f'{count:,} {status}' + (' companions' if kind == 'registry' and status == 'unsupported' else ''))
                                        for status, count in statuses.items() if count)


class FileProgress:
    """Completed-file counters with a display-only spinner during active ingestion."""
    def __init__(self, kind, total, palette, *, stream=None, clock=time.monotonic):
        self.kind, self.total, self.palette = kind, total, palette
        self.stream = sys.stdout if stream is None else stream
        self.clock = clock
        self.started = clock()
        self.last = None
        self.inplace = capable(self.stream)
        self.animated = self.inplace and self.stream.isatty() and sys.stdin.isatty()
        frames = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        self.frames = frames if supports_unicode(frames, self.stream) else '|/-' + chr(92)
        self.index = 0
        self.processed = self.records = 0
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None
        self.closed = False
        self.phase_text = ""

    def _text(self):
        elapsed = max(0, int(self.clock() - self.started))
        percent = (100 * self.processed // self.total) if self.total else 0
        text = (f'{self.kind}  {self.processed} / {self.total} files  {percent}%  '
                f'{elapsed // 60:02d}:{elapsed % 60:02d} elapsed  {self.records:,} records stored')
        if self.phase_text:
            text += ' | ' + self.phase_text
        return (self.frames[self.index % len(self.frames)] + ' ' if self.animated else '') + text

    def observe(self, fields):
        if self.kind != 'mft':
            return
        from forensic_assistant.artifacts.progress import description
        with self.lock:
            self.phase_text = description(fields)

    def _frame(self):
        # Caller holds the display lock. Never print fallback lines from animation.
        from forensic_assistant.session_recording import suspended
        with suspended():
            if not replace_progress_line(self.palette('progress', self._text()), self.stream):
                self.stop.set()
        self.index += 1

    def _animate(self):
        while not self.stop.wait(.1):
            with self.lock:
                try:
                    self._frame()
                except (OSError, ValueError):
                    self.stop.set()

    def update(self, processed, records):
        with self.lock:
            if self.closed:
                return
            self.processed, self.records = processed, records
            current = self.clock()
            if self.animated:
                if self.thread is None:
                    self._frame()
                    self.thread = threading.Thread(target=self._animate, daemon=True, name='Locard ingestion spinner')
                    self.thread.start()
                return
            interval = .1 if self.inplace else 5
            if self.last is not None and processed < self.total and current - self.last < interval:
                return
            self.last = current
            text = self.palette('progress', self._text())
            from forensic_assistant.session_recording import suspended
            with suspended():
                replaced = self.inplace and replace_progress_line(text, self.stream)
            if not replaced:
                print(text, file=self.stream, flush=True)

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join()
        with self.lock:
            if self.closed:
                return
            self.closed = True
            if self.inplace:
                from forensic_assistant.session_recording import suspended
                with suspended():
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
        print(palette('heading', 'EVTX ingestion limitations'))
        for group, text in selected:
            print('- ' + palette('forensic_note' if group['limitation'] else 'label' if run_ids is None else 'error', text))
    other = [g for g, text in evtx if not text]
    if other:
        print(palette('heading', 'Other ingestion limitations and errors'))
    from forensic_assistant.artifacts.registry_logs import LIMITATION
    for group in other:
        count = group['count']
        if group['message'] == LIMITATION:
            text = human_limitation(LIMITATION, count=count)
        else:
            category = {'parse': 'Parsing', 'normalize': 'Normalization',
                        'integrity': 'Source integrity', 'file': 'File ingestion'}.get(group['stage'], 'Ingestion')
            text = f'{category}: {count:,} recorded error' + ('' if count == 1 else 's') + '; detailed diagnostics retained.'
        print('- ' + (palette('forensic_note', text) if group['message'] == LIMITATION else
                      palette('label', category + ': ') + palette('value', f'{count:,}') +
                      palette('label', ' recorded errors; detailed diagnostics retained.')))


def completion_line(message, palette, *, plan=None, outcomes=None, stored=None):
    # Presentation follows the same structured outcome used to construct the message.
    if plan is None:
        return palette('label', message)
    failed = bool(plan.items and not stored and outcomes and all(v == 'failed' for v in outcomes.values()))
    limited = bool(plan.items and (not stored or plan.deferred or plan.limited or any(v != 'complete' for v in (outcomes or {}).values())))
    return palette('error' if failed else 'warning' if limited else 'success', message)


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
    from forensic_assistant.ingest.presentation import duration as format_duration
    return format_duration(seconds)


def simple_success(progress):
    """Only suppress detail when a single complete result has no exceptions."""
    return (progress.statuses == {'complete': 1} and progress.records > 0
            and not progress.duplicates and not progress.errors and not progress.limitations)


def failure_description(kind, status):
    """Application-owned descriptions; original diagnostics remain untouched."""
    if status in ('Source signature does not match requested artifact type',
                  'Unsupported or invalid artifact signature'):
        return {'registry': 'invalid Registry hive', 'prefetch': 'invalid Prefetch file',
                'evtx': 'invalid EVTX file', 'browser': 'invalid browser database',
                'mft': 'invalid MFT file'}.get(kind, 'invalid artifact')
    if status == 'changed':
        return 'source changed during ingestion; staged records rejected'
    if status == 'unsupported':
        return 'unsupported artifact'
    if status == 'partial':
        return 'incomplete ingestion; inspect recorded limitations'
    if status in ('cancelled', 'interrupted'):
        return 'ingestion interrupted'
    return 'ingestion failed; inspect recorded diagnostics'


def print_file_exceptions(kind, rows, palette):
    """Presentation aggregation only; run records and parser counts are untouched."""
    from forensic_assistant.artifacts.registry_logs import is_log
    companions = [r for r in rows if kind == 'registry' and r['status'] == 'unsupported' and is_log(r['path'])]
    if companions:
        noun = 'companion was' if len(companions) == 1 else 'companions were'
        print(palette('forensic_note', f'  {len(companions)} Registry transaction-log {noun} not replayed.'))
        print(palette('forensic_note', '  Recent uncommitted Registry changes may be missing.'))
    for row in rows:
        if row in companions:
            continue
        retained = row.get('inserted', 0) + row.get('duplicates', 0)
        status = str(row['status'])
        label = 'Partial' if status == 'partial' else 'Unsupported' if status == 'unsupported' else 'Failed'
        description = 'file could not be read' if row.get('unreadable') else failure_description(kind, status)
        if status == 'partial' or not retained:
            description += (f'; {retained:,} records retained/previously present' if retained else '; no records retained')
        print(palette('error' if label == 'Failed' else 'warning', '  ' + label + ': ') + palette('value', safe(row['path'])) + ' — ' + description)
    return len(companions)

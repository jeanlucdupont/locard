"""Human ingestion results. Never changes stored outcomes or evidence counts."""
import sys
import time

from forensic_assistant.terminal import Palette, aligned_lines, enabled, field
from forensic_assistant.retrieval.presentation import safe_text


def duration(seconds):
    if seconds is None:
        return 'unavailable'
    seconds = max(0, int(seconds))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f'{hours}h {minutes:02d}m {seconds:02d}s'
    if minutes:
        return f'{minutes}m {seconds:02d}s'
    return f'{seconds}s'


class Timer:
    def __init__(self):
        self.started = time.monotonic()
        self.reported = False
        self.failure_reported = False

    def elapsed(self):
        return max(0, time.monotonic() - self.started)


def role(status):
    return ('success' if status == 'complete' else 'warning' if status in
            ('partial', 'unsupported', 'cancelled', 'interrupted', 'skipped') else
            'unknown' if status in ('unknown', 'uncertain') else 'error')


def outcome(status, retained=0):
    if status == 'complete':
        return 'Completed'
    if status == 'partial':
        return 'Partial — incomplete evidence coverage'
    if status in ('cancelled', 'interrupted'):
        return 'Cancelled — earlier committed evidence remains retained'
    if status in ('failed', 'changed'):
        return ('Failed after retaining evidence' if retained else 'Failed — no new records retained')
    return safe_text(status.capitalize())


def limitations(row):
    if row.get('acquisition'):
        # Native acquisition supplies structured provenance; its legacy combined
        # limitation string also contains an operational message, not a cause.
        from forensic_assistant.artifacts.ntfs_acquisition import LIVE_LIMITATION
        notes = [LIVE_LIMITATION]
        if row['status'] == 'partial':
            notes.insert(0, 'MFT parsing coverage is incomplete; inspect recorded diagnostics.')
        return notes
    if row['status'] in ('failed', 'changed') or row.get('acquisition_error'):
        return []
    return [row['limitation']] if row.get('limitation') else []


def elapsed_line(seconds, palette):
    return str(field('Elapsed time', duration(seconds), palette,
                     role='unknown' if seconds is None else 'value'))


def render(result, palette=None):
    palette = palette or Palette()
    lines = []
    for row in result['results']:
        if lines:
            lines.append('')
        lines.extend([palette('heading', safe_text(row.get('source_type', 'evtx').upper()) + ' INGESTION'), '',
                      field('Outcome', outcome(row['status'], row['inserted']), palette, role=role(row['status'])),
                      field('Records retained (new)', f"{row['inserted']:,}", palette),
                      field('Duplicates', f"{row['duplicates']:,}", palette),
                      field('Recorded errors', f"{row['errors']:,}", palette)])
        if row.get('limitation') and not row.get('acquisition') and (row['status'] in ('failed', 'changed') or row.get('acquisition_error')):
            lines.append(field('Failure detail', safe_text(row['limitation']), palette, role='error'))
        acquisition_time = (row.get('acquisition') or {}).get('elapsed_seconds')
        if isinstance(acquisition_time, (int, float)) and acquisition_time >= 0:
            lines.append(field('Acquisition time', duration(acquisition_time), palette))
        notes = limitations(row)
        if notes:
            lines += ['', palette('heading', 'Limitations')]
            lines += [palette('forensic_note', '  ' + safe_text(note)) for note in notes]
    if not result['results']:
        lines += [palette('warning', 'No ingestion attempts completed.')]
    lines += ['', field('Elapsed time', duration(result.get('elapsed_seconds')), palette,
                        role='value' if result.get('elapsed_seconds') is not None else 'unknown')]
    return aligned_lines(lines)


def exception_outcome(exc):
    from forensic_assistant import activity
    if isinstance(exc, activity.AuditError):
        return 'Uncertain — audit persistence failed; committed evidence may remain', 'error'
    if isinstance(exc, (KeyboardInterrupt, EOFError, activity.Cancelled)):
        return 'Cancelled — earlier committed evidence remains retained', 'warning'
    return 'Failed — inspect persisted outcomes; earlier committed evidence may remain', 'error'


def interrupted(exc, seconds, *, args=None, palette=None, stream=None):
    """Supplement the existing exception path without changing or swallowing it."""
    stream = sys.stderr if stream is None else stream
    palette = palette or Palette(enabled(args, stream))
    text, semantic_role = exception_outcome(exc)
    print(aligned_lines([field('Ingestion outcome', text, palette, role=semantic_role),
                         field('Elapsed time', duration(seconds), palette)]), file=stream)


def report_failure(timer, exc, *, args=None, palette=None):
    if timer.failure_reported:
        return
    timer.failure_reported = timer.reported = True
    interrupted(exc, timer.elapsed(), args=args, palette=palette)

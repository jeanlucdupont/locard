"""Browser text projections use existing terminal escaping and palette roles."""
from forensic_assistant.terminal import Palette, value_role
from .presentation import safe_text as safe, safe_path


def label(record):
    return 'BrowserVisit' if record['artifact_type'] == 'browser_visit' else 'BrowserDownload'


def object_value(record):
    detail = record.get('detail') or {}
    return (detail.get('url') if record['artifact_type'] == 'browser_visit' else
            detail.get('target_path') or detail.get('current_path') or detail.get('full_path')) or '[not recorded]'


def secondary(record):
    d = record.get('detail') or {}
    result = [('Browser', {'chrome': 'Chrome', 'edge': 'Edge'}.get(d.get('browser_product'), 'Unknown')),
              ('Profile', d.get('profile'))]
    if record['artifact_type'] == 'browser_visit':
        result.append(('Title', d.get('title')))
    else:
        result.append(('State', d.get('state_name', 'unknown')))
    return result


def render(record, palette=None):
    palette = palette or Palette()
    lines = [palette('heading', label(record))]
    def field(name, value, path=False):
        if value is not None:
            lines.append(palette('key', name + ': ') + palette(value_role(value), (safe_path if path else safe)(value)))
    d, ctx = record['detail'], record['context']
    field('Evidence ID', record['id'])
    for name, value in secondary(record):
        field(name, value)
    field('Host', ctx.get('hostname') or 'unknown')
    field('Host basis', ctx.get('basis'))
    field('Windows user', ctx.get('username') or 'unknown')
    for source in ctx.get('source_assertions', []):
        field('Source', source['display_name'])
        field('Source ID', source['source_id'])
    if not ctx.get('source_assertions'):
        field('Source', 'unassigned')
    fields = [('URL', 'url'), ('Transition (raw)', 'transition'), ('URL-row visit count', 'url_visit_count'),
              ('URL-row typed count', 'url_typed_count')] if record['artifact_type'] == 'browser_visit' else [
                  ('Target path', 'target_path'), ('Current path', 'current_path'), ('Full path', 'full_path'),
                  ('Stored URL', 'url'), ('Referrer', 'referrer'), ('MIME type', 'mime_type'),
                  ('Received bytes', 'received_bytes'), ('Total bytes', 'total_bytes'),
                  ('State (raw)', 'state'), ('Danger type (raw)', 'danger_type')]
    for name, key in fields:
        field(name, d.get(key), key.endswith('path'))
    for item in d.get('url_chain', []):
        field('URL chain [' + str(item['chain_index']) + ']', item['url'])
    if d.get('url_chain'):
        lines.append('URL chain ordering is recorded by Chromium; it does not establish a malicious origin.')
    lines += ['', palette('heading', 'Timestamps (UTC)')]
    for stamp in record['timestamps']:
        field(stamp['slot'], stamp['timestamp_utc'] or stamp['normalization_status'])
    lines += ['', palette('heading', 'Provenance')]
    field('History SHA-256', record['file_sha256'])
    field('Source path (first ingestion)', record['source_file'], True)
    field('Browser context', d['context_id'])
    occurrences = ctx.get('browser_occurrences', [])
    field('Ingestion occurrences', len(occurrences))
    for item in occurrences[:5]:
        field('Run', item['run_id'])
        field('Batch', item['batch_id'])
        field('Ingested path', item['source_file'], True)
        field('Snapshot SHA-256', item['snapshot_sha256'])
    if len(occurrences) > 5:
        lines.append('Additional run occurrences available in show --json.')
    lines += ['', palette('heading', 'Forensic notes')]
    for warning in record['warnings']:
        lines.append(palette('warning', '- ' + safe(warning)))
    return '\n'.join(lines)


# Exact parser notes only; unknown anomalies/conflicts stay with each record.
SHARED_NOTES = (
    'Browser history may be deleted, expired, synchronized, or absent from the supplied profile; missing history is not proof of no activity.',
    'No WAL supplied; uncheckpointed browser activity may be absent.',
    'Committed WAL content read by SQLite from a private copy; no WAL carving performed.',
    'Browser-recorded navigation does not prove that a user read or interacted with the page.',
    'A download record does not prove execution or that the file still exists.',
)


def search_group(group, palette, ids, width):
    from .layout import table
    from .search_display import timestamp
    rows = []
    for index, record in group:
        d, ctx = record.get('detail') or {}, record.get('context') or {}
        rows.append([index, timestamp(record.get('timestamp_utc')), label(record),
                     d.get('browser_product', '').capitalize(),
                     'CONFLICT' if ctx.get('conflicts') else ctx.get('hostname') or 'unknown', object_value(record)])
    def details(index):
        record = group[index][1]
        lines = ['    ' + palette('key', name + ': ') + safe(value)
                 for name, value in secondary(record) if name != 'Browser' and value is not None]
        if ids:
            lines.append('    ID: ' + palette('evidence_id', safe(record['id'])))
        for warning in record.get('warnings', []):
            if warning not in SHARED_NOTES:
                lines.append('    ' + palette('warning', safe(warning)))
        ctx = record.get('context') or {}
        if ctx.get('conflicts'):
            lines.append('    ' + palette('warning', 'Conflicting context: ' + safe(', '.join(ctx['conflicts']))))
        if record.get('objects_truncated'):
            lines.append('    ' + palette('warning', 'Object projection is bounded; inspect show/JSON for details.'))
        return lines
    return table(['#', 'TIME (UTC)', 'TYPE', 'BROWSER', 'HOST', 'OBJECT'], rows, palette,
                 minimums=[1, 23, 15, 6, 7, 14], maximums=[5, 23, 15, 6, 24, 65],
                 roles=['number_value', 'number_value', 'string_value', 'string_value', 'secondary_text', 'string_value'],
                 width=width, tail=(5,), paths=(5,), text=safe, after_row=details)


def shared_notes(records, palette):
    applicable = {warning for record in records if record['source_type'] == 'browser'
                  for warning in record.get('warnings', []) if warning in SHARED_NOTES}
    if not applicable:
        return []
    lines = ['', palette('heading', 'Forensic notes')]
    for note in SHARED_NOTES:
        if note in applicable:
            lines.append(palette('warning', '- ' + note))
    return lines

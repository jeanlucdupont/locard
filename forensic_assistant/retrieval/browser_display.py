"""Browser text projections use existing terminal escaping and palette roles."""
from forensic_assistant.terminal import Palette, value_role
from .presentation import safe, safe_path


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

"""Bounded Registry text; values retain independent identities and key timestamps."""
import json

from forensic_assistant.terminal import Palette
from .presentation import safe, safe_path
from .layout import table, fit, pagination
from .search_display import timestamp

DIRTY_WARNING = 'Dirty hive: transaction logs were not replayed; snapshot may be inconsistent'
TYPE_NAMES = ('REG_NONE', 'REG_SZ', 'REG_EXPAND_SZ', 'REG_BINARY', 'REG_DWORD',
              'REG_DWORD_BIG_ENDIAN', 'REG_LINK', 'REG_MULTI_SZ', 'REG_RESOURCE_LIST',
              'REG_FULL_RESOURCE_DESCRIPTOR', 'REG_RESOURCE_REQUIREMENTS_LIST', 'REG_QWORD')
VALUE_LIMIT = 20
DATA_LIMIT = 240


def type_name(value):
    return TYPE_NAMES[value] if type(value) is int and 0 <= value < len(TYPE_NAMES) else f'Unknown ({safe(value)})'


def data_text(value_type, value, *, raw_size=None, omitted=False):
    if omitted and raw_size is not None and value_type in (0, 3, 8, 9, 10):
        return f'<binary, {raw_size} bytes>'
    if omitted:
        return '<data omitted: exceeds text projection bound; use value show --json/--raw>'
    if isinstance(value, dict) and value.get('encoding') == 'base64':
        encoded = value.get('data', '')
        size = raw_size if raw_size is not None else max(0, len(encoded) // 4 * 3 - len(encoded) + len(encoded.rstrip('=')))
        return f'<binary, {size} bytes>'
    if value_type in (1, 2, 6) and isinstance(value, str):
        text = safe_path(value[:DATA_LIMIT])
        shortened = len(value) > DATA_LIMIT
    elif value_type == 7 and isinstance(value, list):
        parts = [safe_path(v[:DATA_LIMIT]) if isinstance(v, str) else safe(v) for v in value[:10]]
        text = '[' + '; '.join(parts) + ']'
        shortened = len(value) > 10 or any(isinstance(v, str) and len(v) > DATA_LIMIT for v in value[:10])
    elif value_type in (4, 5, 11) and type(value) is int:
        text, shortened = str(value), False
    else:
        # Unknown/binary types are never guessed to be strings or executed.
        return '<data available in --json/--raw>'
    return text[:DATA_LIMIT] + '... [truncated; use --json/--raw]' if shortened or len(text) > DATA_LIMIT else text


def projected_values(db, key_id):
    total = db.execute('SELECT count(*) FROM registry_values WHERE key_id=?', (key_id,)).fetchone()[0]
    rows = []
    for row in db.execute('''SELECT evidence_id,value_name,value_type,length(raw_data) AS raw_size,
        length(decoded_json) AS json_size,
        CASE WHEN length(decoded_json)<=4096 THEN decoded_json END AS decoded
        FROM registry_values WHERE key_id=? ORDER BY value_name COLLATE NOCASE,evidence_id LIMIT ?''', (key_id, VALUE_LIMIT)):
        item = dict(row)
        item['value_data'] = json.loads(item.pop('decoded') or 'null')
        rows.append(item)
    return dict(values=rows, total=total)


def render(record, palette=None, *, values=None):
    palette = palette or Palette()
    d = record.get('detail') or {}
    value = 'value_name' in d
    ctx = record.get('context') or {}
    lines = [palette('heading', 'Registry value' if value else 'Registry key')]
    def field(label, text):
        lines.append(palette('key', label + ': ') + text)
    field('Evidence ID', palette('evidence_id', safe(record['id'])))
    hive = d.get('hive', {})
    field('Hive', safe(hive.get('hive_type', 'UNKNOWN')))
    filename = record.get('source', {}).get('source_file', record.get('source_file'))
    if filename:
        field('File', safe_path(filename))
    names = [s['display_name'] for s in ctx.get('source_assertions', [])]
    field('Source', safe('; '.join(names) or 'unassigned'))
    field('Host', safe(ctx.get('hostname') or 'unknown'))
    field('Key', safe_path(d.get('key_path')))
    if value:
        field('Name', safe(d['value_name'] or '(Default)'))
        field('Type', type_name(d.get('value_type')))
        field('Data', data_text(d.get('value_type'), d.get('value_data')))
    times = [t for t in record.get('timestamps', []) if t.get('timestamp_utc')]
    for t in times:
        field('Last write', timestamp(t['timestamp_utc']) + ' UTC')
    if not times:
        field('Last write', 'unavailable')
    lines.append('Note: Timestamp belongs to the containing key; not individual value creation.' if value else
                 'Note: Registry key last-write time; not individual value creation.')
    if not value:
        lines += ['', palette('heading', 'Values')]
        if values is None:
            lines.append('Value details not loaded; use CLI show for the bounded values table (--json exposes value IDs).')
        else:
            rows = [[v['value_name'] or '(Default)', type_name(v['value_type']),
                     data_text(v['value_type'], v['value_data'], raw_size=v['raw_size'], omitted=(v['json_size'] or 0) > 4096)]
                    for v in values['values']]
            lines += table(['NAME', 'TYPE', 'DATA'], rows, palette,
                           minimums=[12, 13, 16], maximums=[35, 32, DATA_LIMIT],
                           roles=['secondary_text'] * 3,
                           format_cell=lambda row, col, text, room: fit(rows[row][col], room) if col in (1, 2) else None)
            if not rows:
                lines.append('No values.')
            if note := pagination(len(rows), values['total']):
                lines.append(note + ' values')
    warnings = list(dict.fromkeys(record.get('warnings', [])))
    if ctx.get('conflicts'):
        warnings.append('Conflicting context: ' + ', '.join(ctx['conflicts']))
    if warnings:
        lines += ['', palette('heading', 'Limitations / data quality')]
        lines.extend(palette('warning', safe(w)) for w in warnings)
    return '\n'.join(lines)


def warning_context(record):
    """Scope hive warnings to content plus source assertions, not row numbers."""
    return (record.get('file_sha256') or record.get('source', {}).get('sha256') or record['id'],
            tuple(sorted(s['source_id'] for s in record.get('context', {}).get('source_assertions', []))))


def warning_label(record):
    path = record.get('source', {}).get('source_file', record.get('source_file'))
    sha, _ = warning_context(record)
    return safe_path(path or 'Unknown hive') + ' [' + safe(sha) + ']'

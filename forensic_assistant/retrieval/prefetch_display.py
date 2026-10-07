"""Human Prefetch observations; no grouping, path mapping or evidence mutation."""
from forensic_assistant.terminal import Palette
from .layout import pagination, table
from .search_display import timestamp


def executable(record):
    """Use the recorded executable only, never a supporting file reference."""
    return (record.get('detail') or {}).get('executable') or record.get('process_name') or next(
        (o['original'] for o in record.get('objects', [])
         if o['role'] in ('executable_name', 'executable')), None)


def render_timeline(result, *, palette=None, width=None):
    palette = palette or Palette()
    records = result['records']
    rows = [[timestamp(r.get('timestamp_utc')), executable(r),
             '[' + r['timestamp']['slot'] + ']'] for r in records]
    lines = table(
        ['TIME (UTC)', 'EXECUTABLE', 'RUN SLOT'], rows, palette,
        minimums=[23, 10, 8], maximums=[23, 60, 16],
        roles=['number_value', 'string_value', 'secondary_text'], width=width
    ) if rows else ['No matching evidence.']
    if note := pagination(len(records), result['total'], result.get('offset', 0)):
        lines.append(note)
    return '\n'.join(lines)

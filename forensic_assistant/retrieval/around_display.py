"""Compact temporal presentation; never changes query results or stored evidence."""
import shutil
import textwrap
from forensic_assistant.correlation.models import time_ns
from forensic_assistant.terminal import Palette
from .presentation import safe, detail


def delta(stamp, anchor):
    ns = time_ns(stamp) - time_ns(anchor)
    seconds, fraction = divmod(abs(ns), 1_000_000_000)
    digits = f'{fraction:09d}'.rstrip('0').ljust(3, '0')
    return ('+' if ns > 0 else '-' if ns < 0 else '') + f'{seconds}.{digits}s'


def observation(record):
    if record['source_type'] == 'evtx': return detail(record)
    return next((o['original'] for o in record.get('objects', [])
                 if o['role'] != 'parent_image'), None) or record.get('observation')


def artifact(record):
    return {'prefetch_file': 'Prefetch', 'mft_record': 'MFT record',
            'registry_key': 'Registry key', 'registry_value': 'Registry value'}.get(
                record.get('artifact_type'), f"{record['source_type']} / {record.get('artifact_type', '-')}")


def source(record):
    assertions = record.get('context', {}).get('source_assertions', [])
    return '; '.join(sorted(f"{s['display_name']} [{s['source_id']}]" for s in assertions)) or 'unassigned'


def semantics(record):
    stamp = record.get('timestamp', {})
    return f"{stamp.get('source', '-')} / {stamp.get('meaning', '-')}"


def render(result, anchor, stamp, args, palette=None, *, width=None):
    palette = palette or Palette()
    width = max(20, width or shutil.get_terminal_size(fallback=(80, 24)).columns)
    rows = result['records']
    slots = [t['slot'] for t in anchor['timestamps'] if t['timestamp_utc'] == stamp
             and (args.timestamp_slot is None or t['slot'] == args.timestamp_slot)]
    selected = slots[0] if len(slots) == 1 else None
    lines = []
    def line(text, role='secondary_text'):
        lines.extend(palette(role, part) for part in
                     (textwrap.wrap(text, width, break_on_hyphens=False, replace_whitespace=False) or ['']))
    window = f'+/-{args.seconds}s around' if args.direction == 'around' else f'{args.seconds}s {args.direction}'
    line(f'Temporal context: {window} {safe(observation(anchor))}', 'heading')
    line(f'Anchor: {stamp} (UTC)', 'key')
    line('Anchor slot: ' + safe(selected if selected is not None else 'ambiguous; select --timestamp-slot'))
    getters = [('Source', source), ('Artifact', artifact), ('Timestamp meaning', semantics)]
    shared = {}
    for name, getter in getters:
        values = {getter(r) for r in rows}
        if len(values) == 1:
            shared[name] = next(iter(values))
            line(f'{name} (displayed rows): {safe(shared[name])}')
    if shared.get('Source') != source(anchor): line('Anchor source: ' + safe(source(anchor)))
    line('')
    dates = {r['timestamp_utc'][:10] for r in rows}
    one_date = len(dates) == 1
    if one_date: line('Date (UTC): ' + next(iter(dates)))
    time_width = 18 if one_date else 30
    delta_width = max([5] + [len(delta(r['timestamp_utc'], stamp)) for r in rows])
    room = width - time_width - delta_width - 6
    table = room >= 25
    line((f"{'TIME (UTC)':<{time_width}} | {'DELTA':>{delta_width}} | OBJECT / OBSERVATION"
          if table else 'TIME (UTC) | DELTA; object below'), 'heading')
    for r in rows:
        marker = r['id'] == anchor['id'] and r['timestamp']['slot'] == selected
        time = r['timestamp_utc']
        # Keep dates and all normalized precision visible, including midnight crossings.
        obj = safe(observation(r))
        suffix = ' <- anchor' if marker else ''
        obj_room = (room if table else width - 2) - len(suffix)
        if len(obj) > obj_room: obj = obj[:obj_room-3] + '...'
        if table:
            shown_time = time[11:-1] if one_date else time
            line(f'{shown_time:<{time_width}} | {delta(time, stamp):>{delta_width}} | {obj}{suffix}',
                 'heading' if marker else 'secondary_text')
        else:
            line(f"{time} | {delta(time, stamp)}", 'number_value')
            line('  ' + obj + suffix, 'heading' if marker else 'string_value')
        for name, getter in getters:
            if name not in shared: line(f'  {name}: {safe(getter(r))}', 'key')
        if args.ids:
            # IDs are deliberately never shortened; the shared pager can wrap them.
            lines.append(palette('evidence_id', '  ID: ' + safe(r['id'])))
    line(f"Displayed {len(rows)} / {result['total']} timestamp observations; offset={result['offset']}; truncated={result['truncated']}.")
    line('Display objects may be shortened (...). Use --text --ids for IDs; show <id>, --json or --raw for complete data.')
    line('Correlation != causation. Timestamp semantics differ by artifact.', 'warning')
    return '\n'.join(lines)

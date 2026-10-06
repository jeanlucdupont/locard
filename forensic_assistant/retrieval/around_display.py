"""Compact temporal presentation; never changes query results or stored evidence."""
import textwrap
from datetime import datetime, timedelta
from forensic_assistant.correlation.models import time_ns
from forensic_assistant.terminal import Palette
from .presentation import safe, detail
from .layout import terminal_width, fit


def delta(stamp, anchor):
    ns = time_ns(stamp) - time_ns(anchor)
    milliseconds = (abs(ns) + 500_000) // 1_000_000
    seconds, fraction = divmod(milliseconds, 1000)
    return ('+' if ns > 0 and milliseconds else '-' if ns < 0 and milliseconds else '') + f'{seconds}.{fraction:03d}s'


def display_time(stamp):
    """Nearest millisecond, half up; integer arithmetic retains carry across dates."""
    rounded = (int(stamp[20:29]) + 500_000) // 1_000_000
    try:
        value = datetime.fromisoformat(stamp[:19]) + timedelta(milliseconds=rounded)
    except OverflowError:
        # Rounding the last representable second carries into year 10000.
        return '10000-01-01T00:00:00.000Z'
    return value.isoformat(timespec='milliseconds') + 'Z'


def observation(record):
    if record['source_type'] == 'evtx':
        return detail(record)
    return next(
        (o['original'] for o in record.get('objects', [])
         if o['role'] != 'parent_image'),
        None
    ) or record.get('observation')


def artifact(record):
    return {
        'prefetch_file': 'Prefetch',
        'mft_record': 'MFT record',
        'registry_key': 'Registry key',
        'registry_value': 'Registry value'
    }.get(
        record.get('artifact_type'), f"{record['source_type']} / {record.get('artifact_type', '-')}")


def source(record):
    assertions = record.get('context', {}).get('source_assertions', [])
    return '; '.join(sorted(f"{s['display_name']} [{s['source_id']}]" for s in assertions)) or 'unassigned'


def semantics(record):
    stamp = record.get('timestamp', {})
    return f"{stamp.get('source', '-')} / {stamp.get('meaning', '-')}"


def render(result, anchor, stamp, args, palette=None, *, width=None):
    palette = palette or Palette()
    width = terminal_width(width)
    rows = result['records']
    from . import mft_display
    grouped = mft_display.groups(rows)
    collisions = mft_display.precision_collisions(grouped)
    has_mft = any(r['source_type'] == 'mft' for r in rows)
    slots = [t['slot'] for t in anchor['timestamps'] if t['timestamp_utc'] == stamp
             and (args.timestamp_slot is None or t['slot'] == args.timestamp_slot)]
    selected = slots[0] if len(slots) == 1 else None
    lines = []
    def line(text, role='secondary_text'):
        lines.extend(palette(role, part) for part in
                     (textwrap.wrap(text, width, break_on_hyphens=False, replace_whitespace=False) or ['']))
    names = {}
    for record in [anchor, *rows]:
        for s in record.get('context', {}).get('source_assertions', []):
            names.setdefault(s['display_name'], set()).add(s['source_id'])
    def source_label(record):
        assertions = record.get('context', {}).get('source_assertions', [])
        return '; '.join(sorted(s['display_name'] + (f" [{s['source_id']}]" if args.ids or len(names[s['display_name']]) > 1 else '')
                                for s in assertions)) or 'unassigned'
    getters = [('Source', source), ('Artifact', artifact), ('Timestamp meaning', semantics)]
    shared = {}
    for name, getter in getters:
        values = {getter(r) for r in rows}
        if len(values) == 1:
            shared[name] = next(iter(values))
    context = [display_time(stamp).replace('T', ' ').removesuffix('Z') + ' UTC', safe(source_label(anchor))]
    if 'Artifact' in shared:
        context.append(('Rows: ' if shared['Artifact'] != artifact(anchor) else '') + safe(shared['Artifact']))
    line(' | '.join(context), 'key')
    if 'Source' in shared and shared['Source'] != source(anchor):
        line('Rows source: ' + safe(source_label(rows[0])))
    if selected is None:
        line('Anchor slot ambiguous; select --timestamp-slot to identify one observation.', 'warning')
    elif anchor['source_type'] == 'mft':
        selected_stamp = next(t for t in anchor['timestamps'] if t['slot'] == selected)
        attribute, label = mft_display.timestamp_label(selected_stamp)
        # Never hide the exact anchor slot, even when outside the retrieved page.
        lines.append('Anchor: ' + safe(attribute + ' ' + label + ' [' + selected + ']'))
    if args.ids:
        line(f'Anchor: {stamp}; slot: {safe(selected)}')
        if 'Timestamp meaning' in shared:
            line('Timestamp meaning: ' + safe(shared['Timestamp meaning']))
    line('')
    if anchor['source_type'] == 'mft':
        collisions |= {tuple(k) for k in result.get('_mft_page', {}).get('precision_collisions', [])}
        lines += mft_display.render_blocks(grouped, width=width, palette=palette, anchor=anchor,
                                           stamp=stamp, selected=selected, ids=args.ids, collisions=collisions)
        if note := mft_display.footer(result, len(grouped)):
            line(note)
        return '\n'.join(lines)
    dates = {display_time(r['timestamp_utc']).split('T')[0] for r in rows}
    one_date = len(dates) == 1
    if one_date and next(iter(dates)) != display_time(stamp).split('T')[0]:
        line('Rows dated (UTC): ' + next(iter(dates)))
    time_width = 12 if one_date else 24
    delta_width = max([5] + [len(delta(r['timestamp_utc'], stamp)) for r in rows])
    room = width - time_width - delta_width - 6
    table = room >= 25
    shortened = False
    line(
        (f"{'TIME (UTC)':<{time_width}} | {'DELTA':>{delta_width}} | OBJECT / OBSERVATION"
         if table else 'TIME (UTC) | DELTA; object below'),
        'heading'
    )
    for group in grouped:
        r = group[0]
        marker = r['id'] == anchor['id'] and any(item['timestamp']['slot'] == selected for item in group)
        time = display_time(r['timestamp_utc'])
        relative = delta(r['timestamp_utc'], stamp)
        obj = mft_display.object_text(r) if r['source_type'] == 'mft' else safe(observation(r))
        suffix = ' <- anchor' if marker else ''
        obj_room = (room if table else width - 2) - len(suffix)
        shortened = shortened or len(obj) > obj_room
        obj = fit(obj, obj_room)
        if table:
            shown_time = time.split('T')[1][:-1] if one_date else time
            line(
                f'{shown_time:<{time_width}} | {relative:>{delta_width}} | {obj}{suffix}',
                'heading' if marker else 'secondary_text'
            )
        else:
            line(f"{time} | {relative}", 'number_value')
            line('  ' + obj + suffix, 'heading' if marker else 'string_value')
        for name, getter in getters:
            if r['source_type'] == 'mft' and name == 'Timestamp meaning':
                continue
            if name not in shared:
                line(f'  {name}: {safe(source_label(r) if name=="Source" else getter(r))}', 'key')
        if r['source_type'] == 'mft':
            line('  State: ' + mft_display.state(r.get('detail', {}).get('allocated')))
            for label in mft_display.semantics(group, selected if marker else None):
                # Exact anchor is above; avoid a second anchor marker in the group.
                line('  ' + label.replace(' <- anchor ', ' [selected] '))
            if (r['id'], time) in collisions:
                line('  Exact UTC: ' + safe(r['timestamp_utc']))
        if args.ids:
            # IDs are deliberately never shortened; the shared pager can wrap them.
            lines.append(palette('evidence_id', '  ID: ' + safe(r['id'])))
            for item in group:
                line('  Timestamp: ' + item['timestamp_utc'] + '; slot: ' + safe(item['timestamp']['slot']))
    from .layout import pagination
    footer = mft_display.footer(result, len(grouped)) if has_mft else pagination(len(rows), result['total'], result['offset'])
    if footer:
        line(footer)
    return '\n'.join(lines)

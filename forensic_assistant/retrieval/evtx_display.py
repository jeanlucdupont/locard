"""EVTX text projections. Display groups never replace evidence observations."""
import ntpath
import textwrap
from itertools import groupby

from forensic_assistant.terminal import Palette
from . import mft_display
from .around_display import display_time, delta, source
from .layout import terminal_width
from .presentation import safe, safe_path, human_detail, file_create_target


def groups(records):
    return mft_display.groups(records, source_types=('mft', 'evtx'))


def page(result, limit, offset, *, anchor=None, stamp=None, selected_slot=None):
    projected = mft_display.page(result, limit, offset, anchor=anchor, stamp=stamp,
                                 source_types=('mft', 'evtx'), selected_slot=selected_slot)
    projected['_evtx_page'] = projected.pop('_mft_page')
    return projected


def footer(result, count):
    if '_evtx_page' not in result:
        if result.get('truncated') or result.get('offset', 0) or len(result['records']) != result['total']:
            return 'Observation page only; complete-group pagination requires EVTX text retrieval.'
        return ''
    return mft_display.footer({**result, '_mft_page': result['_evtx_page']}, count)


def timestamp_label(stamp):
    slot = stamp['slot']
    if slot.startswith('Sysmon.'):
        return 'Sysmon', slot.removeprefix('Sysmon.')
    return 'EVTX', slot


def semantics(group, selected=None):
    buckets = {}
    for record in group:
        stamp = record['timestamp']
        kind, label = timestamp_label(stamp)
        buckets.setdefault(kind, []).append((label, stamp['slot']))
    return [safe(kind + '  ' + ', '.join(
        label + (f' [selected: {slot}]' if slot == selected else '')
        for label, slot in sorted(items))) for kind, items in sorted(buckets.items())]


def collisions(result, grouped):
    return mft_display.precision_collisions(grouped, source_types=('mft', 'evtx')) | {
        tuple(key) for key in result.get('_evtx_page', {}).get('precision_collisions', [])}


def render_blocks(grouped, *, width=None, palette=None, anchor=None, stamp=None,
                  selected=None, ids=False, precision=()):
    """Style compact structural fields; leave paths neutral and wrap intact text."""
    palette = palette or Palette()
    width = terminal_width(width)
    around = anchor is not None
    one_date = around and all(display_time(g[0]['timestamp_utc'])[:10] == display_time(stamp)[:10] for g in grouped)
    time_width = 12 if one_date else 23
    delta_width = max([5] + [len(delta(g[0]['timestamp_utc'], stamp)) for g in grouped]) if around else 0
    sizes = [time_width] + ([delta_width] if around else []) + [max([11] + [len(safe(g[0].get('artifact_type'))) for g in grouped])]
    headings = ['TIME (UTC)'] + (['DELTA'] if around else []) + ['TYPE']
    object_start = sum(sizes) + 2 * len(sizes)
    aligned = width - object_start >= 16
    lines = []

    def pieces(value, room):
        return textwrap.wrap(value, max(1, room), break_on_hyphens=False,
                             replace_whitespace=False, expand_tabs=False) or ['']

    def wrapped(value, indent='    ', role=None):
        for part in pieces(value, width - len(indent)):
            lines.append(indent + (palette(role, part) if role else part))

    def columns(values):
        return '  '.join(value.rjust(size) if around and i == 1 else value.ljust(size)
                         for i, (value, size) in enumerate(zip(values, sizes)))

    if aligned:
        lines += [palette('heading', columns(headings) + '  OBJECT'),
                  columns(['-' * size for size in sizes]) + '  ' + '-' * (width - object_start)]
    else:
        wrapped('  '.join(headings + ['OBJECT']), indent='', role='heading')
    for index, group in enumerate(grouped):
        if index:
            lines.append('')
        r = group[0]
        kind = r.get('artifact_type')
        marker = around and (r['id'], r['timestamp_utc']) == (anchor['id'], stamp) and any(
            item['timestamp']['slot'] == selected for item in group)
        time = display_time(r['timestamp_utc']).replace('T', ' ').removesuffix('Z')
        values = [time[11:] if one_date else time] + ([delta(r['timestamp_utc'], stamp)] if around else [])
        activity = safe(kind)
        role = 'key' if kind == 'process' else 'string_value' if kind == 'file_create' else 'secondary_text'
        if kind == 'process':
            obj = safe_path(r.get('parent_process_name') or '?')
            detail = '-> ' + safe_path(r.get('process_name') or '?')
        elif kind == 'file_create':
            obj = safe(ntpath.basename(r.get('process_name') or '?'))
            detail = 'Target  ' + safe_path(file_create_target(r) or '?')
        else:
            obj, detail = human_detail(r), None
        suffix = ' <- anchor' if marker else ''
        if aligned:
            prefix = columns(values + [''])
            # Padding precedes styling so ANSI escapes never affect widths.
            prefix = prefix[:-sizes[-1]] + palette(role, activity.ljust(sizes[-1])) + '  '
            marker_below = marker and len(obj + suffix) > width - object_start
            parts = pieces(obj + (suffix if not marker_below else ''), width - object_start)
            for i, part in enumerate(parts):
                # Only the literal marker is emphasized, never the object text.
                if marker and part.endswith('<- anchor'):
                    part = part[:-9] + palette('heading', '<- anchor')
                lines.append((prefix if i == 0 else ' ' * object_start) + part)
            if marker_below:
                wrapped('<- anchor', role='heading')
        else:
            wrapped('  '.join(values), indent='')
            wrapped(activity, indent='', role=role)
            wrapped(obj)
            if marker:
                wrapped('<- anchor', role='heading')
        if detail:
            wrapped(detail)
        for label in semantics(group, selected if marker else None):
            wrapped(label)
        if around and source(r) != source(anchor):
            wrapped('Source: ' + safe(source(r)))
        if (r['id'], display_time(r['timestamp_utc'])) in precision:
            wrapped('Exact UTC: ' + safe(r['timestamp_utc']))
        if ids:
            lines.append(palette('evidence_id', '    ID: ' + safe(r['id'])))
            for item in group:
                wrapped('Timestamp: ' + safe(item['timestamp_utc']) + '; slot: ' + safe(item['timestamp']['slot']))
    return lines


def render_segments(grouped, *, width=None, palette=None, anchor=None, stamp=None,
                    selected=None, ids=False, precision=()):
    """Keep existing non-EVTX layouts in mixed windows."""
    lines = []
    for kind, segment in groupby(grouped, key=lambda g: g[0]['source_type']):
        segment = list(segment)
        if lines:
            lines.append('')
        options = dict(width=width, palette=palette, anchor=anchor, stamp=stamp, selected=selected, ids=ids)
        if kind == 'evtx':
            lines += render_blocks(segment, **options, precision=precision)
        elif kind == 'mft':
            lines += mft_display.render_blocks(segment, **options, collisions=precision)
        else:
            # Prefetch/Registry retain individual observations and their detailed
            # timestamp semantics. Reuse the established non-EVTX timeline text.
            rows = [r for group in segment for r in group]
            lines.append(mft_display.render_timeline(dict(records=rows, total=len(rows), offset=0, truncated=False), width=width))
    return lines


def render_timeline(result, *, palette=None, width=None):
    grouped = groups(result['records'])
    lines = render_segments(grouped, width=width, palette=palette, precision=collisions(result, grouped))
    if not grouped:
        lines.append('No matching evidence.')
    if note := footer(result, len(grouped)):
        lines.append(note)
    return '\n'.join(lines)


def render_around(result, anchor, stamp, args, palette=None, *, width=None):
    palette = palette or Palette()
    width = terminal_width(width)
    grouped = groups(result['records'])
    slots = [t for t in anchor['timestamps'] if t['timestamp_utc'] == stamp
             and (args.timestamp_slot is None or t['slot'] == args.timestamp_slot)]
    selected = slots[0]['slot'] if len(slots) == 1 else None
    names = {}
    for r in [anchor, *result['records']]:
        for assertion in r.get('context', {}).get('source_assertions', []):
            names.setdefault(assertion['display_name'], set()).add(assertion['source_id'])
    labels = sorted(s['display_name'] + (f" [{s['source_id']}]" if args.ids or len(names[s['display_name']]) > 1 else '')
                    for s in anchor.get('context', {}).get('source_assertions', []))
    context = display_time(stamp).replace('T', ' ').removesuffix('Z') + ' UTC | ' + safe('; '.join(labels) or 'unassigned')
    lines = [palette('key', part) for part in textwrap.wrap(context, width, break_on_hyphens=False)]
    if selected:
        kind, label = timestamp_label(slots[0])
        heading = 'Anchor: ' + safe(kind + ' ' + label + ' [' + selected + ']')
        lines.extend(textwrap.wrap(heading, width, break_on_hyphens=False))
    else:
        lines.append(palette('warning', 'Anchor slot ambiguous; select --timestamp-slot to identify one observation.'))
    if args.ids:
        lines.append('Anchor: ' + safe(stamp) + '; slot: ' + safe(selected))
    lines.append('')
    lines += render_segments(grouped, width=width, palette=palette, anchor=anchor, stamp=stamp,
                             selected=selected, ids=args.ids, precision=collisions(result, grouped))
    if note := footer(result, len(grouped)):
        lines.append(note)
    return '\n'.join(lines)

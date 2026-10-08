"""Mixed temporal text projections; never merge evidence or infer relationships."""
import textwrap

from forensic_assistant.terminal import Palette
from . import mft_display
from .around_display import display_time, delta
from .layout import terminal_width, fit_path, pagination
from .presentation import safe, safe_path, human_detail


def is_mixed(result, anchor=None):
    kinds = {r['source_type'] for r in result['records']}
    if anchor:
        kinds.add(anchor['source_type'])
    return bool(result.get('_mixed_text')) or len(kinds) > 1 or 'browser' in kinds


def artifact(record):
    kind = record['source_type']
    if kind == 'browser':
        from .browser_display import label
        return label(record)
    if kind == 'registry':
        d = record.get('detail') or {}
        return 'UserAssist' if d.get('userassist') else 'RegistryValue' if 'value_name' in d else 'RegistryKey'
    if kind == 'evtx':
        return 'EVTX ' + safe(record.get('artifact_type') or 'event')
    return {'prefetch': 'Prefetch', 'mft': 'MFT'}.get(kind, safe(kind))


def object_text(record):
    kind = record['source_type']
    d = record.get('detail') or {}
    if kind == 'browser':
        from .browser_display import object_value
        return safe_path(object_value(record))
    if kind == 'registry':
        from .registry_display import value_name_text
        if ua := d.get('userassist'):
            return safe_path(ua['decoded_name'] or '(Default)')
        if 'value_name' in d:
            return safe_path(d.get('key_path') or '?') + ' :: ' + value_name_text(d['value_name'])
        return safe_path(d.get('key_path') or next(
            (o['original'] for o in record.get('objects', []) if o.get('role') == 'key'), '[unknown key]'))
    if kind == 'prefetch':
        from .prefetch_display import executable
        return safe_path(executable(record))
    if kind == 'mft':
        return mft_display.object_text(record)
    return human_detail(record)


def render(result, *, palette=None, width=None, anchor=None, stamp=None, args=None,
           anchor_header=True, warning_summary=True, retain_userassist=False,
           wrap_objects=False, omission_help=None, object_projection=None):
    palette = palette or Palette()
    width = terminal_width(width)
    rows = result['records']
    grouped = mft_display.groups(rows, source_types=('mft', 'evtx'))
    around = anchor is not None
    ids = bool(args and args.ids)
    slots = [t['slot'] for t in anchor['timestamps'] if t['timestamp_utc'] == stamp
             and (args.timestamp_slot is None or t['slot'] == args.timestamp_slot)] if around else []
    selected = slots[0] if len(slots) == 1 else None
    lines = []

    def line(value='', role='secondary_text', indent=''):
        for part in textwrap.wrap(value, max(1, width - len(indent)), break_on_hyphens=False,
                                  replace_whitespace=False, expand_tabs=False) or ['']:
            lines.append(indent + palette(role, part))

    names = {}
    for r in [*rows, *([anchor] if around else [])]:
        for s in r.get('context', {}).get('source_assertions', []):
            names.setdefault(s['display_name'], set()).add(s['source_id'])

    def source_label(r):
        return '; '.join(sorted(s['display_name'] + (f" [{s['source_id']}]" if ids or len(names[s['display_name']]) > 1 else '')
                                for s in r.get('context', {}).get('source_assertions', []))) or 'unassigned'

    if around and anchor_header:
        line(display_time(stamp).replace('T', ' ').removesuffix('Z') + ' UTC | ' +
             safe(anchor.get('host_key') or anchor.get('context', {}).get('hostname') or 'unknown'), 'key')
        label = 'Prefetch run' if anchor['source_type'] == 'prefetch' else artifact(anchor)
        if selected:
            line('Anchor: ' + label + ' [' + safe(selected) + ']', 'heading')
        else:
            line('Anchor slot ambiguous; select --timestamp-slot to identify one observation.', 'warning')
        line()

    one_date = around and all(display_time(r['timestamp_utc'])[:10] == display_time(stamp)[:10] for r in rows)
    time_width = 12 if one_date else 23
    delta_width = max([5] + [len(delta(r['timestamp_utc'], stamp)) for r in rows]) if around else 0
    type_width = max([4] + [len(artifact(r)) for r in rows])
    sizes = [time_width] + ([delta_width] if around else []) + [type_width]
    headings = ['TIME (UTC)'] + (['DELTA'] if around else []) + ['TYPE']
    room = width - sum(sizes) - 2 * len(sizes)
    aligned = room >= 18
    header = '  '.join(h.ljust(n) for h, n in zip(headings, sizes)) + '  OBJECT'
    line(header if aligned else ' | '.join(headings + ['OBJECT']), 'heading')
    if aligned:
        line('  '.join('-' * n for n in sizes) + '  ' + '-' * room)
    precision = mft_display.precision_collisions(grouped, source_types=('mft', 'evtx', 'prefetch', 'registry', 'browser'))
    for key in ('_evtx_page', '_mft_page'):
        precision.update(tuple(v) for v in result.get(key, {}).get('precision_collisions', []))
    generic_count = omitted = 0
    for group in grouped:
        r = group[0]
        marker = around and (r['id'], r['timestamp_utc']) == (anchor['id'], stamp) and any(
            t['timestamp']['slot'] == selected for t in group)
        generic = r['source_type'] == 'registry' and all(t['timestamp']['slot'] == 'LastWrite' for t in group)
        if retain_userassist and (r.get('detail') or {}).get('userassist'):
            generic = False
        if generic:
            generic_count += 1
            if generic_count > 3 and not marker and not ids:
                omitted += len(group)
                continue
        time = display_time(r['timestamp_utc']).replace('T', ' ').removesuffix('Z')
        values = [time[11:] if one_date else time] + ([delta(r['timestamp_utc'], stamp)] if around else [])
        kind = artifact(r)
        role = {'prefetch': 'string_value', 'registry': 'key', 'mft': 'number_value', 'evtx': 'boolean_value', 'browser': 'heading'}[r['source_type']]
        obj = (object_projection or object_text)(r)
        if aligned:
            prefix = '  '.join(v.rjust(n) if around and i == 1 else v.ljust(n)
                               for i, (v, n) in enumerate(zip(values, sizes)))
            lead = palette('secondary_text', prefix) + '  ' + palette(role, kind.ljust(type_width))
            if wrap_objects and len(obj) > room:
                lines.append(lead)
                line(obj, indent='    ')
            else:
                lines.append(lead + '  ' + fit_path(obj, room, literal=True))
        else:
            line(' | '.join(values))
            line(kind, role)
            line(obj if wrap_objects else fit_path(obj, width - 4, literal=True), indent='    ')
        if marker:
            line('<- anchor', 'heading', '    ')
        if r['source_type'] == 'browser':
            from .browser_display import secondary
            for name, value in secondary(r):
                line(name + ': ' + safe(value), indent='    ')
        ctx = r.get('context') or {}
        if ctx.get('username'):
            line('User: ' + safe(ctx['username']), indent='    ')
        if not around:
            line('Host: ' + safe(r.get('host_key') or ctx.get('hostname') or 'unknown'), indent='    ')
        line('Source: ' + safe(source_label(r)), indent='    ')
        for item in group:
            t = item['timestamp']
            line('Timestamp: ' + safe(t.get('source') or t['slot']) + ' [' + safe(t['slot']) + ']', indent='    ')
        if r['source_type'] == 'mft':
            line('State: ' + mft_display.state((r.get('detail') or {}).get('allocated')), indent='    ')
        if (r['id'], display_time(r['timestamp_utc'])) in precision:
            line('Exact UTC: ' + safe(r['timestamp_utc']), indent='    ')
        if ids:
            # Keep explicit IDs copyable; the shared pager handles wrapping.
            lines.append(palette('evidence_id', '    ID: ' + safe(r['id'])))
            for item in group:
                line('Timestamp: ' + safe(item['timestamp_utc']) + '; slot: ' + safe(item['timestamp']['slot']), indent='    ')
        line()
    if omitted:
        line(f'{omitted} additional Registry LastWrite observations omitted from this compact page; '
             + (omission_help or 'use --json/--raw (with observation pagination), around --text --ids, or timeline --artifact registry --text.'), 'warning')
    # Count distinct evidence records, not co-valued timestamp slots.
    from .registry_display import KEY_CORRUPTION
    corrupted = {r['id'] for r in rows if r['source_type'] == 'registry' and KEY_CORRUPTION in r.get('warnings', [])}
    if corrupted and warning_summary:
        line(f'Warning: parser reported key corruption for {len(corrupted)} records in this page '
             '(including compactly summarized observations); the flag alone does not establish unreadable data.', 'warning')
    if '_evtx_page' in result:
        from .evtx_display import footer
        note = footer(result, len(grouped))
    elif '_mft_page' in result:
        note = mft_display.footer(result, len(grouped))
    else:
        note = pagination(len(rows), result['total'], result.get('offset', 0))
    if note:
        line(note)
    if not rows:
        line('No matching evidence.')
    return '\n'.join(lines).rstrip()

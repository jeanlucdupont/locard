"""MFT presentation only: groups never replace stored timestamp observations."""
from collections import Counter
from .presentation import safe, safe_path


LABELS = {'Created': 'Created', 'Modified': 'Modified',
          'MFTChanged': 'MFT changed', 'Accessed': 'Accessed'}
ATTRIBUTES = {'SI': 'STANDARD_INFORMATION (SI)', 'FN': 'FILE_NAME (FN)'}


def state(value):
    return {0: 'Unallocated', 1: 'Allocated'}.get(value, 'Unknown')


def timestamp_label(stamp):
    # Attribute offsets are instance locators, NOT NTFS attribute type codes.
    parts = (stamp.get('source') or '').split()
    if len(parts) == 3 and parts[0] == 'MFT' and parts[1] in ATTRIBUTES and parts[2] in LABELS:
        return parts[1], LABELS[parts[2]]
    return 'Other timestamps', stamp.get('source') or stamp['slot']


def object_text(record):
    for obj in record.get('objects', []):
        if obj.get('role') in ('file_path', 'filename') and obj.get('original'):
            return safe_path(obj['original'])
    detail = record.get('detail') or {}
    for name in detail.get('names', []):
        if value := name.get('reconstructed_path') or name.get('filename'):
            return safe_path(value)
    if detail.get('record_number') is not None and detail.get('sequence_number') is not None:
        return f"MFT record {safe(detail['record_number'])}/{safe(detail['sequence_number'])}"
    return '[unnamed MFT record]'


def groups(records, *, source_types=('mft',)):
    """Group opted-in artifacts (MFT by default) by ID and unrounded timestamp.

    Retain first-occurrence order and every observation, including duplicate labels
    from distinct FILE_NAME attributes. Pagination is applied after grouping.
    """
    result, positions = [], {}
    for record in records:
        if record['source_type'] in source_types:
            key = record['id'], record['timestamp_utc']
            if key in positions:
                result[positions[key]].append(record)
                continue
            positions[key] = len(result)
        result.append([record])
    return result


def semantics(group, selected=None):
    buckets = {}
    for record in group:
        stamp = record['timestamp']
        kind, label = timestamp_label(stamp)
        buckets.setdefault(kind, []).append((label, stamp['slot']))
    lines = []
    for kind in sorted(buckets, key=lambda k: {'SI': 0, 'FN': 1}.get(k, 2)):
        items = sorted(buckets[kind], key=lambda item: (list(LABELS.values()).index(item[0])
                       if item[0] in LABELS.values() else 4, item[1]))
        repeated = {label for label, count in Counter(label for label, _ in items).items() if count > 1}
        labels = [label + (f' [{slot}]' if label in repeated else '') +
                  (f' [selected: {slot}]' if slot == selected else '') for label, slot in items]
        lines.append(safe(kind + '  ' + ', '.join(labels)))
    return lines


def footer(result, count):
    from .layout import pagination
    info = result.get('_mft_page')
    if info is None:
        if result.get('truncated') or result.get('offset', 0) or len(result['records']) != result['total']:
            return 'Observation page only; complete-group pagination requires MFT text retrieval.'
        return ''
    if info['around']:
        if count == info['total']:
            return ''
        return f"Showing {count} of {info['total']} groups (anchor included" + (
            f"; neighbor offset {info['offset']}" if info['offset'] else '') + ')'
    note = pagination(count, info['total'], info['offset'])
    return note + ' groups' if note else ''


def page(result, limit, offset, *, anchor=None, stamp=None, source_types=('mft',), selected_slot=None):
    """Pure display projection. Never page incomplete observation windows."""
    from forensic_assistant.correlation.models import time_ns
    if not 1 <= limit <= 10000 or offset < 0:
        raise ValueError('Invalid pagination bounds')
    if result.get('truncated') or result.get('offset', 0) or len(result['records']) != result['total']:
        raise ValueError('Complete timestamp window required for grouped text')
    records = list(result['records'])
    if anchor is not None:
        # before/after excludes the anchor time from neighbors. Add only the
        # known anchor's co-valued observations, never other same-time records.
        records = [r for r in records if (r['id'], r['timestamp_utc']) != (anchor['id'], stamp)]
        records += [dict(anchor, timestamp=t, timestamp_utc=stamp,
                         timeline_id=anchor['id'] + ':Timestamp:' + t['slot'])
                    for t in anchor['timestamps'] if t['timestamp_utc'] == stamp]
    if len(records) > 10000:
        raise ValueError('Grouped text exceeds the 10,000 timestamp-observation safety bound; narrow the window')
    order = lambda g: (g[0]['timestamp_utc'], g[0]['id'], g[0]['timestamp']['slot'])
    grouped = sorted(groups(sorted(records, key=lambda r: (r['timestamp_utc'], r['id'], r['timestamp']['slot'])),
                            source_types=source_types), key=order)
    if anchor is None:
        chosen = grouped[offset:offset + limit]
    else:
        selected = next((g for g in grouped if (g[0]['id'], g[0]['timestamp_utc']) == (anchor['id'], stamp)
                         and (selected_slot is None or any(r['timestamp']['slot'] == selected_slot for r in g))), None)
        if selected is None:
            raise ValueError('Selected anchor timestamp is unavailable')
        neighbors = sorted((g for g in grouped if g is not selected), key=lambda g: (
            abs(time_ns(g[0]['timestamp_utc']) - time_ns(stamp)), *order(g)))
        chosen = sorted([selected, *neighbors[offset:offset + limit - 1]], key=order)
    return {**result, 'records': [r for g in chosen for r in g],
            '_mft_page': dict(total=len(grouped), offset=offset, around=anchor is not None,
                              precision_collisions=sorted(precision_collisions(grouped, source_types=source_types)))}


def precision_collisions(grouped, *, source_types=('mft',)):
    """Identify rounded labels needing exact precision, in linear time."""
    from .around_display import display_time
    values = {}
    for group in grouped:
        r = group[0]
        if r['source_type'] in source_types:
            key = r['id'], display_time(r['timestamp_utc'])
            values.setdefault(key, set()).add(r['timestamp_utc'])
    return {key for key, times in values.items() if len(times) > 1}


def render_blocks(grouped, *, width=None, palette=None, anchor=None, stamp=None, selected=None,
                  ids=False, collisions=()):
    """Small width-aware MFT layout, using existing time, delta and palette rules."""
    import textwrap
    from forensic_assistant.terminal import Palette
    from .around_display import display_time, delta, observation, semantics as other_semantics, source
    from .presentation import human_detail
    from .layout import terminal_width
    palette = palette or Palette()
    width = terminal_width(width)
    around = anchor is not None
    one_date = around and all(display_time(g[0]['timestamp_utc'])[:10] == display_time(stamp)[:10] for g in grouped)
    time_width = 12 if one_date else 23
    delta_width = max([5] + [len(delta(g[0]['timestamp_utc'], stamp)) for g in grouped]) if around else 0
    headings = ['TIME (UTC)'] + (['DELTA'] if around else []) + ['STATE']
    sizes = [time_width] + ([delta_width] if around else []) + [11]
    object_start = sum(sizes) + 2 * len(sizes)
    aligned = width - object_start >= 16
    lines = []
    def wrapped(value, *, indent='', role='secondary_text'):
        for part in textwrap.wrap(value, max(1, width - len(indent)), break_on_hyphens=False,
                                  replace_whitespace=False, expand_tabs=False) or ['']:
            lines.append(palette(role, indent + part))
    def columns(values):
        return '  '.join(value.rjust(n) if around and i == 1 else value.ljust(n)
                         for i, (value, n) in enumerate(zip(values, sizes)))
    if aligned:
        lines += [palette('heading', columns(headings) + '  OBJECT'),
                  columns(['-' * n for n in sizes]) + '  ' + '-' * (width - object_start)]
    else:
        wrapped('  '.join(headings + ['OBJECT']), role='heading')
    for index, group in enumerate(grouped):
        if index:
            lines.append('')
        r = group[0]
        mft = r['source_type'] == 'mft'
        marker = around and r['id'] == anchor['id'] and any(t['timestamp']['slot'] == selected for t in group)
        time = display_time(r['timestamp_utc']).replace('T', ' ').removesuffix('Z')
        if one_date:
            time = time[11:]
        values = [time] + ([delta(r['timestamp_utc'], stamp)] if around else []) + [
            state(r.get('detail', {}).get('allocated')) if mft else '-']
        obj = (object_text(r) if mft else human_detail(r) if r['source_type'] == 'evtx' else safe(observation(r))) + (' <- anchor' if marker else '')
        role = 'heading' if marker else 'secondary_text'
        if aligned:
            pieces = textwrap.wrap(obj, width - object_start, break_on_hyphens=False,
                                   replace_whitespace=False, expand_tabs=False) or ['']
            lines.append(palette(role, columns(values) + '  ' + pieces[0]))
            lines.extend(palette(role, ' ' * object_start + part) for part in pieces[1:])
        else:
            wrapped('  '.join(values), role=role)
            wrapped(obj, indent='    ', role=role)
        labels = semantics(group, selected if marker else None) if mft else [safe(other_semantics(r))]
        for label in labels:
            wrapped(label, indent='    ')
        if around and (not mft or source(r) != source(anchor)):
            wrapped('Source: ' + safe(source(r)), indent='    ', role='key')
        if (r['id'], display_time(r['timestamp_utc'])) in collisions:
            wrapped('Exact UTC: ' + safe(r['timestamp_utc']), indent='    ')
        if ids:
            lines.append(palette('evidence_id', '    ID: ' + safe(r['id'])))
            for item in group:
                wrapped('Timestamp: ' + item['timestamp_utc'] + '; slot: ' + safe(item['timestamp']['slot']), indent='    ')
    return lines


def render_timeline(result, *, width=None):
    from itertools import groupby
    from .presentation import detail
    grouped = groups(result['records'])
    collisions = precision_collisions(grouped) | {tuple(k) for k in result.get('_mft_page', {}).get('precision_collisions', [])}
    lines = []
    for mft, segment in groupby(grouped, key=lambda g: g[0]['source_type'] == 'mft'):
        if lines:
            lines.append('')
        if mft:
            lines += render_blocks(list(segment), width=width, collisions=collisions)
            continue
        # Non-MFT rows retain their existing exact timestamp, ID and semantics.
        lines.append('UTC | EVIDENCE ID | SOURCE | ARTIFACT TYPE | TIMESTAMP MEANING | OBJECT / OBSERVATION')
        for group in segment:
            r = group[0]
            lines.append(' | '.join(safe(v) for v in (
                r.get('timestamp_utc'), r['id'], r['source_type'], r.get('artifact_type'),
                r.get('timestamp', {}).get('source'),
                detail(r) if r['source_type'] == 'evtx' else next(
                    (o['original'] for o in r.get('objects', []) if o['role'] != 'parent_image'),
                    None) or r.get('observation'))))
    if not grouped:
        lines.append('No matching evidence.')
    if note := footer(result, len(grouped)):
        lines.append(note)
    return '\n'.join(lines)

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


def groups(records):
    """Group only MFT observations, by evidence ID and full unrounded timestamp.

    Retain first-occurrence order and every observation, including duplicate labels
    from distinct FILE_NAME attributes. Work only with the retrieved page.
    """
    result, positions = [], {}
    for record in records:
        if record['source_type'] == 'mft':
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
                  (f' <- anchor [{slot}]' if slot == selected else '') for label, slot in items]
        lines.append(safe(kind + ': ' + ', '.join(labels)))
    return lines


def footer(result, count):
    shown, total, offset = len(result['records']), result['total'], result.get('offset', 0)
    if shown == total and not offset:
        return ''
    span = f'{offset + 1}-{offset + shown}' if shown else '0'
    return f'Displayed {count} groups from timestamp observations {span} of {total}; page may split groups.'


def precision_collisions(grouped):
    """Identify rounded labels needing exact precision, in linear time."""
    from .around_display import display_time
    values = {}
    for group in grouped:
        r = group[0]
        if r['source_type'] == 'mft':
            key = r['id'], display_time(r['timestamp_utc'])
            values.setdefault(key, set()).add(r['timestamp_utc'])
    return {key for key, times in values.items() if len(times) > 1}


def render_timeline(result, *, width=None):
    import textwrap
    from .around_display import display_time
    from .layout import terminal_width, fit_path
    from .presentation import detail
    width = terminal_width(width)
    grouped = groups(result['records'])
    collisions = precision_collisions(grouped)
    lines = []
    previous_kind = None
    for group in grouped:
        r = group[0]
        kind = 'mft' if r['source_type'] == 'mft' else 'other'
        if kind != previous_kind:
            if lines:
                lines.append('')
            lines.append('TIME (UTC) | STATE | OBJECT / OBSERVATION' if kind == 'mft' else
                         'UTC | EVIDENCE ID | SOURCE | ARTIFACT TYPE | TIMESTAMP MEANING | OBJECT / OBSERVATION')
            previous_kind = kind
        if r['source_type'] != 'mft':
            # Non-MFT rows keep their existing exact timestamp, ID and semantics.
            lines.append(' | '.join(safe(v) for v in (
                r.get('timestamp_utc'), r['id'], r['source_type'], r.get('artifact_type'),
                r.get('timestamp', {}).get('source'),
                detail(r) if r['source_type'] == 'evtx' else next(
                    (o['original'] for o in r.get('objects', []) if o['role'] != 'parent_image'),
                    None) or r.get('observation'))))
            continue
        time = display_time(r['timestamp_utc']).replace('T', ' ').removesuffix('Z')
        prefix = time + ' | ' + state(r.get('detail', {}).get('allocated')) + ' | '
        if width - len(prefix) >= 20:
            lines.append(prefix + fit_path(object_text(r), width - len(prefix), literal=True))
        else:
            lines.append(time + ' UTC | ' + state(r.get('detail', {}).get('allocated')))
            lines.append('  ' + fit_path(object_text(r), width - 2, literal=True))
        for label in semantics(group):
            lines.extend(textwrap.wrap('  ' + label, width, subsequent_indent='    ', break_on_hyphens=False))
        # Rounded display must not conceal distinct submillisecond values.
        if (r['id'], display_time(r['timestamp_utc'])) in collisions:
            lines.append('  Exact UTC: ' + safe(r['timestamp_utc']))
    if note := footer(result, len(grouped)):
        lines.append(note)
    return '\n'.join(lines)

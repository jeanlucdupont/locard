"""Compact search projections; selection and hydration remain unchanged."""
from .presentation import safe, safe_path, detail, human_detail, file_create_target, logon_id, PREFETCH_CAUTIONS
from .layout import table, pagination, fit, fit_path
import ntpath
from forensic_assistant.ingest.validation import is_identifier_note
from .around_display import display_time


def timestamp(value):
    return display_time(value).replace('T', ' ').removesuffix('Z') if value else '-'


def render(result, palette=None, *, ids=False, width=None):
    from forensic_assistant.terminal import Palette
    palette = palette or Palette()
    lines = []
    records = result['records']
    # Group only adjacent kinds, preserving the exact query ordering.
    groups = []
    for index, r in enumerate(records, 1):
        kind = r['source_type']
        auth = kind == 'evtx' and (r.get('kind') or r.get('artifact_type')) in ('logon', 'failed_logon')
        if not groups or groups[-1][:2] != (kind, auth):
            groups.append((kind, auth, []))
        groups[-1][2].append((index, r))
    for kind, auth, group in groups:
        if lines:
            lines.append('')
        if len({r['source_type'] for r in records}) > 1:
            lines.append(palette('heading', kind.upper()))
        rows = []
        for index, r in group:
            d = r.get('detail') or {}
            ctx = r.get('context', {})
            host = 'CONFLICT' if ctx.get('conflicts') else ctx.get('hostname') or 'unknown'
            if kind == 'prefetch':
                times = [t['timestamp_utc'] for t in r.get('timestamps', []) if t.get('timestamp_utc')]
                paths = sorted({o['original'] for o in r.get('objects', []) if o['role'] == 'executable_path_candidate'})
                row = [
                    timestamp(max(times) if times else None),
                    d.get('run_count'),
                    d.get('executable'),
                    host,
                    paths[0] if paths else '-'
                ]
            elif kind == 'mft':
                from .mft_display import state
                names = d.get('names', [])
                row = [
                    f"{d.get('record_number')}/{d.get('sequence_number')}",
                    state(d.get('allocated')),
                    d.get('file_size'),
                    host,
                    (names[0].get('reconstructed_path') or names[0].get('filename')) if names else '-'
                ]
            elif kind == 'registry':
                from .registry_display import type_name
                row = [
                    timestamp(r.get('timestamp_utc')),
                    host,
                    'Value' if 'value_name' in d else 'Key',
                    d.get('key_path'),
                    (d['value_name'] or '(Default)') if 'value_name' in d else '-',
                    type_name(d['value_type']) if 'value_type' in d else '-'
                ]
            elif auth:
                row = [timestamp(r.get('timestamp_utc')), r.get('event_id'), host,
                       r.get('username'), r.get('logon_type'), logon_id(r)]
            else:
                row = [timestamp(r.get('timestamp_utc')), r.get('event_id'), host, r.get('username'), detail(r)]
            rows.append(([index] if ids else []) + row)
        headers = {
            'prefetch': ['LAST RUN (UTC)', 'RUNS', 'EXECUTABLE', 'HOST', 'CANDIDATE PATH'],
            'mft': ['RECORD/SEQ', 'STATE', 'SIZE', 'HOST', 'NAME/PATH'],
            'registry': ['KEY TIME (UTC)', 'HOST', 'KIND', 'KEY', 'VALUE', 'TYPE'],
            'evtx': ['TIME (UTC)', 'EVENT', 'HOST', 'USER', 'OBSERVATION']
        }[kind]
        minimums = {
            'prefetch': [23, 4, 10, 7, 14],
            'mft': [10, 11, 5, 7, 12],
            'registry': [23, 7, 5, 8, 8, 5],
            'evtx': [23, 5, 7, 7, 12]
        }[kind]
        roles = ['number_value', 'number_value', 'string_value', 'secondary_text', 'string_value']
        maximums = [23, 20, 32, 24, 65]
        if kind == 'registry':
            maximums = [23, 24, 5, 65, 32, 32]
            roles = ['number_value', 'string_value', 'secondary_text', 'secondary_text', 'secondary_text', 'secondary_text']
        if auth:
            headers = ['TIME (UTC)', 'EVENT', 'HOST', 'USER', 'TYPE', 'LOGON ID']
            # Keep the copyable identifier intact, shrinking descriptive cells first.
            id_width = max(8, *(len(row[-1] or '-') for row in rows))
            minimums = [23, 5, 7, 7, 4, id_width]
            maximums = [23, 5, 24, 32, 4, id_width]
            roles = ['number_value', 'number_value', 'string_value', 'string_value',
                     'number_value', 'number_value']
        if ids:
            headers = ['#'] + headers
            minimums = [1] + minimums
            maximums = [5] + maximums
            roles = ['number_value'] + roles
        def format_cell(row_index, column, value, available):
            record = group[row_index][1]
            if kind == 'evtx' and not auth and column == len(headers) - 1 and record.get('artifact_type') == 'process':
                return fit(human_detail(record), available)
            if kind != 'evtx' or column != len(headers) - 1 or record.get('artifact_type') != 'file_create':
                return None
            actor = safe(ntpath.basename(record.get('process_name') or '?'))
            prefix = actor + ' - file creation/overwrite: '
            target = safe_path(file_create_target(record) or '?')
            if available <= len(prefix) + 8:
                return fit(prefix + target, available)
            return prefix + fit_path(target, available - len(prefix), literal=True)
        lines += table(
            headers,
            rows,
            palette,
            minimums=minimums,
            maximums=maximums,
            roles=roles,
            width=width,
            tail=(len(headers) - 1,) if kind in ('prefetch', 'mft') else (),
            format_cell=format_cell,
            paths=(len(headers) - 1,) if kind in ('prefetch', 'mft') else
                  (3 + int(ids),) if kind == 'registry' else ()
        )
    if not records:
        lines.append('No matching evidence.')
    if ids:
        for index, r in enumerate(records, 1):
            lines.append(f"{index}: " + palette('evidence_id', safe(r['id'])))
    dirty_hives = set()
    for index, r in enumerate(records, 1):
        ctx = r.get('context', {})
        for warning in r.get('warnings', []):
            if r['source_type'] == 'registry':
                from .registry_display import DIRTY_WARNING, warning_context, warning_label
                if warning == DIRTY_WARNING:
                    context = warning_context(r)
                    if context not in dirty_hives:
                        lines.append(palette('warning', 'Warning: ' + warning_label(r) + ': ' + safe(warning)))
                        dirty_hives.add(context)
                    continue
            if is_identifier_note(warning):
                continue
            if r['source_type'] != 'prefetch' or warning not in PREFETCH_CAUTIONS:
                lines.append(palette('warning', f'Row {index}: ' + safe(warning)))
        if ctx.get('conflicts'):
            lines.append(palette('warning', f"Row {index}: conflicting context: " + safe(', '.join(ctx['conflicts']))))
        if r['source_type'] == 'prefetch':
            paths = {o['original'] for o in r.get('objects', []) if o['role'] == 'executable_path_candidate'}
            if len(paths) > 1:
                lines.append(palette('warning', f'Row {index}: multiple executable path candidates.'))
            if r.get('objects_truncated') and not paths:
                lines.append(palette(
                    'warning',
                    f'Row {index}: executable path candidate unavailable in the bounded projection.'
                ))
    footer = pagination(len(records), result['total'], result.get('offset', 0))
    if footer:
        lines += ['', footer]
    return '\n'.join(lines)

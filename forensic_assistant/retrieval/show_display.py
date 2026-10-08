"""Analyst summaries of existing evidence projections, never new conclusions."""
from .presentation import safe, safe_path, human_detail, file_create_target, PREFETCH_CAUTIONS
from .layout import pagination
from forensic_assistant.ingest.validation import is_identifier_note
from .search_display import timestamp


def render(record, palette=None, *, registry_values=None):
    if record['source_type'] == 'registry':
        from .registry_display import render as render_registry
        return render_registry(record, palette, values=registry_values)
    from forensic_assistant.terminal import Palette, value_role
    palette = palette or Palette()
    lines = []
    def field(name, value, *, path=False):
        lines.append(palette('key', name + ': ') + palette(value_role(value), (safe_path if path else safe)(value)))
    kind = record['source_type']
    d = record.get('detail') or {}
    ctx = record.get('context', {})
    src = record.get('source', {})
    lines.append(palette(
        'heading',
        {'prefetch': 'Prefetch', 'evtx': 'EVTX', 'mft': 'MFT', 'registry': 'Registry'}[kind]
    ))
    field('Evidence ID', record['id'])
    if not ctx.get('source_assertions'):
        field('Source', 'unassigned')
    for source in ctx.get('source_assertions', []):
        field('Source', source.get('display_name'))
        if len(ctx.get('source_assertions', [])) > 1:
            field('Source ID', source.get('source_id'))
    field('Effective host', ctx.get('hostname') or 'unknown')
    field('Host basis', ctx.get('basis', 'unknown'))
    if ctx.get('username'):
        field('User', ctx['username'])
    if ctx.get('volume_root'):
        field('Volume root', ctx['volume_root'], path=True)
    field('File', src.get('source_file', record.get('source_file')), path=True)
    field('SHA-256', src.get('sha256', record.get('file_sha256')))
    locations = record.get('source_locations', [])
    if len(locations) > 1:
        field('Observed paths', len(locations))
        for path in locations[:5]:
            field('Path', path, path=True)
        footer = pagination(min(5, len(locations)), len(locations))
        if footer:
            lines.append(footer)
    if kind == 'prefetch':
        field('Executable', d.get('executable'))
        field('Recorded run count', d.get('run_count'))
    elif kind == 'mft':
        for key in (
            'record_number',
            'sequence_number',
            'file_size',
            'base_record',
            'base_sequence'
        ):
            if key in ('base_record', 'base_sequence') and d.get('base_record') == 0 and d.get('base_sequence') == 0:
                continue
            field(key.replace('_', ' ').capitalize(), d.get(key))
        from .mft_display import state
        field('State', state(d.get('allocated')))
        field('Type', {0: 'File', 1: 'Directory'}.get(d.get('directory'), 'Unknown'))
        for name in d.get('names', []):
            field('Name/path', name.get('reconstructed_path') or name.get('filename'), path=True)
    elif kind == 'registry':
        field('Key', d.get('key_path'), path=True)
        for key in ('value_name', 'value_type', 'value_data'):
            if key in d:
                field(key.replace('_', ' ').capitalize(), d[key])
        if 'value_ids' in d:
            field('Values in projection', len(d['value_ids']))
        if d.get('values_truncated'):
            lines.append(palette('warning', 'Registry value ID projection is bounded to 100.'))
    else:
        for key in (
            'event_id',
            'artifact_type',
            'provider',
            'channel',
            'username',
            'process_name',
            'parent_process_name',
            'command_line',
            'source_ip',
            'destination_ip',
            'target_account',
            'subject_account'
        ):
            if record.get(key) is not None:
                field(key.replace('_', ' ').capitalize(), record[key], path=key in ('process_name', 'parent_process_name'))
        if record.get('artifact_type') == 'file_create':
            field('PID', record.get('process_id'))
            field('Process GUID', record.get('process_guid'))
            field('System Security UserID', record.get('user_sid'))
            field('Target', file_create_target(record), path=True)
        from forensic_assistant.ingest.service import is_installation, fields, NOTE
        if is_installation(record):
            field('Computer', record.get('computer'))
            field('EventRecordID', record.get('record_id'))
            field('SystemTime (recorded)', record.get('timestamp_original'))
            for key, value in fields(record).items():
                field(key.replace('_', ' ').capitalize(), value, path=key == 'image_path')
            lines += ['', palette('heading', 'Forensic note'), palette('warning', '- ' + NOTE)]
        lines.append(palette('key', 'Observation: ') + palette('string_value', human_detail(record)))
    times = record.get('timestamps', [])
    populated = [t for t in times if t.get('timestamp_utc')]
    if times and kind == 'mft':
        from .mft_display import timestamp_label, ATTRIBUTES, LABELS
        grouped = {}
        for t in populated:
            attribute, label = timestamp_label(t)
            # Keep separate attribute instances (e.g. multiple FILE_NAME entries).
            instance = t['slot'].rsplit(':', 1)[0]
            grouped.setdefault((attribute, instance), []).append((label, t))
        for (attribute, instance), items in sorted(grouped.items(), key=lambda item: (
                {'SI': 0, 'FN': 1}.get(item[0][0], 2), item[0][1])):
            lines += ['', palette('heading', ATTRIBUTES.get(attribute, attribute) + ' [' + safe(instance) + ']')]
            for label, t in sorted(items, key=lambda item: list(LABELS.values()).index(item[0])
                                   if item[0] in LABELS.values() else 4):
                field(label, timestamp(t['timestamp_utc']) + ' UTC  [' + t['slot'] + ']')
        if len(populated) != len(times):
            field('Timestamps', f'{len(populated)} of {len(times)} slots populated')
    elif kind == 'prefetch':
        lines += ['', palette('heading', 'Run times')]
        standard_meaning = 'Recorded execution timestamp; not a process-instance identifier'
        meanings = {t.get('meaning') for t in populated}
        common_meaning = next(iter(meanings)) if len(meanings) == 1 else None
        if common_meaning and common_meaning != standard_meaning:
            field('Meaning', common_meaning)
        for t in populated:
            lines.append(palette('number_value', timestamp(t['timestamp_utc']) + ' UTC')
                         + '  ' + palette('secondary_text', '[' + safe(t['slot']) + ']'))
            if t.get('meaning') and t['meaning'] != standard_meaning and not common_meaning:
                field('Meaning', t['meaning'])
        if not populated:
            lines.append('No populated run times.')
        if len(populated) != len(times):
            field('Populated run slots', f'{len(populated)} of {len(times)}')
    elif times:
        lines += ['', palette('heading', f'Timestamps: {len(populated)} of {len(times)} slots populated')]
        meanings = {t.get('meaning') for t in populated}
        common_meaning = next(iter(meanings)) if len(meanings) == 1 else None
        if common_meaning:
            field('Meaning', common_meaning)
        for t in populated:
            field(t['slot'], timestamp(t['timestamp_utc']))
            if t.get('meaning') and not common_meaning:
                field('Meaning', t['meaning'])
            if t.get('inherited_from_key'):
                lines.append('Timestamp belongs to the containing key, not the value.')
    if kind == 'prefetch':
        candidates = sorted({o['original'] for o in record.get('objects', []) if o['role'] == 'executable_path_candidate'})
        for path in candidates:
            field('Executable path candidate', path, path=True)
        if record.get('objects_truncated') and not candidates:
            lines.append(palette('warning', 'Executable path candidate unavailable in the bounded projection.'))
        refs = d.get('references', [])
        total = d.get('reference_count', len(refs))
        field('Referenced files', total)
        for path in refs[:5]:
            lines.append('  ' + palette('string_value', safe_path(path)))
        footer = pagination(min(5, len(refs)), total)
        if footer:
            lines.append(footer)
        field('Volumes', len(d.get('volumes', [])))
    if ctx.get('conflicts'):
        lines.append(palette('warning', 'Conflicting context: ' + safe(', '.join(ctx['conflicts']))))
    warnings = list(record.get('warnings', []))
    for note in warnings:
        if is_identifier_note(note):
            field('Validation', note)
    warnings = [note for note in warnings if not is_identifier_note(note)]
    if kind == 'prefetch':
        # Only consolidate exact known interpretation cautions; unknown parser and
        # data-quality warnings must survive verbatim.
        standard = PREFETCH_CAUTIONS
        directory_warning = 'Referenced files are not all executed images; directory tables are not exposed by this binding' in warnings
        warnings = [w for w in warnings if w not in standard]
        lines += ['', palette('heading', 'Forensic notes')]
        from .artifact_notes import PREFETCH, PREFETCH_PARSER
        for note in PREFETCH:
            lines.append(palette('warning', '- ' + note))
        if directory_warning:
            lines += ['', palette('heading', 'Parser limitation'), palette(
                'warning', '- ' + PREFETCH_PARSER)]
    elif record.get('observation'):
        warnings.insert(0, record['observation'])
    if warnings:
        lines += ['', palette('heading', 'Limitations / data quality')]
        for warning in dict.fromkeys(warnings):
            lines.append(palette('warning', safe(warning)))
    return '\n'.join(lines)

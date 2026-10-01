"""Human search summaries only; evidence hydration and JSON stay unchanged."""
import shutil
from .presentation import safe, detail


def render(result, palette=None):
    from forensic_assistant.terminal import Palette, value_role
    palette = palette or Palette()
    try: width = max(40, min(120, shutil.get_terminal_size().columns))
    except OSError: width = 80
    def field(name, value):
        text = safe(value)
        room = max(16, width - len(name) - 4)
        if len(text) > room: text = text[:room-3] + '...'
        return '  ' + palette('key', name) + ': ' + palette(value_role(value), text)
    lines = [palette('heading', 'SEARCH RESULTS')]
    for r in result['records']:
        kind = r['source_type']; d = r.get('detail') or {}
        lines += ['', palette('evidence_id', safe(r['id'])), field('Artifact', r['artifact_type'])]
        ctx = r.get('context', {})
        lines.append(field('Host', 'CONFLICT' if 'hostname' in ctx.get('conflicts', []) else ctx.get('hostname') or 'unknown'))
        if ctx.get('hostname'): lines.append(field('Host basis', ctx.get('basis')))
        if kind == 'prefetch':
            times = [t['timestamp_utc'] for t in r.get('timestamps', []) if t.get('timestamp_utc')]
            candidates = sorted({o['original'] for o in r.get('objects', []) if o['role'] == 'executable_path_candidate'})
            lines += [field('Executable', d.get('executable')), field('Latest retained run (UTC)', max(times) if times else None),
                      field('Recorded run count', d.get('run_count'))]
            if candidates:
                lines.append(field('Candidate path', candidates[0]))
                if len(candidates)>1: lines.append('  Multiple candidate paths; inspect show.')
            elif r.get('objects_truncated'): lines.append('  Candidate path: not established in bounded projection; inspect show.')
        elif kind == 'mft':
            names = d.get('names', [])
            if names: lines.append(field('Name/path', names[0].get('reconstructed_path') or names[0].get('filename')))
            lines += [field('Record / sequence', f"{d.get('record_number')} / {d.get('sequence_number')}"),
                      field('Allocated', d.get('allocated')), field('Size', d.get('file_size'))]
        elif kind == 'registry':
            lines.append(field('Key', d.get('key_path')))
            if 'value_name' in d: lines += [field('Value name', d['value_name']), field('Value type', d.get('value_type'))]
        else:
            lines += [field('UTC', r.get('timestamp_utc')), field('Event ID', r.get('event_id')),
                      field('User', r.get('username')), field('Observation', detail(r))]
    count = len(result['records']); more = result['offset'] + count < result['total']
    lines += ['', f"Showing {count} of {result['total']} matching records; offset={result['offset']}, limit={result['limit']}; additional results={'yes' if more else 'no'}.",
              'Display fields may be shortened; evidence IDs are complete. Stored evidence is unchanged.',
              'Use show <evidence-id> for details; search --raw for verbose/raw output.']
    return '\n'.join(lines)

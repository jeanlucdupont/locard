"""Section-only advisory presentation; never interprets command syntax or claims."""
import re

from forensic_assistant.terminal import Palette, wrap_line
from forensic_assistant.retrieval.layout import terminal_width
from forensic_assistant.retrieval.presentation import safe_text

TITLES = ('Goal', 'Case inventory', 'Sources', 'Current assessment', 'Suggested approach',
          'Recommended commands', 'Important cautions', 'Next steps', 'Notes', 'Evidence needed')
DATA_SECTIONS = ('Case inventory', 'Sources')
INTERNAL_TERMS = ('manual_commands', 'case_context', 'context object', 'capability payload',
                  'structured message', 'prompt layer', 'injected context', 'evidence_supplied',
                  'system message', 'tool metadata', 'artifact_inventory')
_INTERNAL = re.compile(r'\b(?:' + '|'.join(re.escape(term) for term in INTERNAL_TERMS) + r')\b', re.I)


def sections(text):
    """Validate a small text convention inside the existing advice string."""
    if _INTERNAL.search(text):
        raise ValueError('Internal presentation vocabulary')
    result = []
    for line in text.splitlines():
        candidate = line.strip().removeprefix('## ').strip('[]').rstrip(':')
        if candidate in TITLES:
            if any(title == candidate for title, _ in result):
                raise ValueError('Repeated advisory section')
            result.append((candidate, []))
        elif line.strip():
            if not result or result[-1][0] in DATA_SECTIONS:
                raise ValueError('Unexpected advisory section content')
            result[-1][1].append(line.rstrip())
    if not 2 <= len(result) <= 5 or any(not lines and title not in DATA_SECTIONS for title, lines in result):
        raise ValueError('Expected two to five nonempty advisory sections')
    return result


def render(text, context, palette=None, *, width=None):
    palette = palette or Palette()
    width = terminal_width(width)
    output = []
    for title, lines in sections(text):
        output.extend(['', palette('heading', title)])
        if title == 'Case inventory':
            counts = context['artifact_inventory']
            padding = max(map(len, counts), default=0)
            lines = [f'{kind:<{padding}}  {count:,} records' for kind, count in counts.items()]
        elif title == 'Sources':
            sources = context['sources']
            lines = []
            if sources['total'] is None:
                lines.append('Source registry unavailable for this case schema.')
            elif sources['total'] == 0:
                lines.append('No registered sources.')
            else:
                lines.append(f"{sources['total']} sources; showing {sources['shown']} (analyst-supplied metadata).")
                for index, source in enumerate(sources['items'], 1):
                    details = [label + ': ' + safe_text(source[key]) for key, label in
                               (('hostname', 'host'), ('username', 'user'), ('volume_root', 'volume'))
                               if source[key] is not None]
                    label = safe_text(source['display_name'])
                    lines.append(f'{index}. {label}' + (' — ' + ', '.join(details) if details else ''))
                if sources['truncated']:
                    lines.append('Additional sources are not shown.')
            if context['truncated_fields']:
                lines.append('Some case/source labels or metadata were shortened.')
        for line in lines:
            # Indentation is layout only. Never tokenize, validate or run commands here.
            line = safe_text(line) if title in DATA_SECTIONS else line
            role = 'warning' if title == 'Important cautions' else 'key' if title == 'Recommended commands' else None
            if title in ('Important cautions', 'Current assessment') and not line.lstrip().startswith(('-', '*')):
                line = '- ' + line
            styled = palette(role, '  ' + line) if role else '  ' + line
            output.extend(wrap_line(styled, width))
    return '\n'.join(output)

"""Section-only advisory presentation; never interprets command syntax or claims."""
import re
import textwrap

from forensic_assistant.terminal import Palette
from forensic_assistant.retrieval.layout import terminal_width
from forensic_assistant.retrieval.presentation import safe_text

TITLES = ('Goal', 'Case inventory', 'Sources', 'Current assessment', 'Suggested approach',
          'Recommended commands', 'Important cautions', 'Next steps', 'Notes', 'Evidence needed')
DATA_SECTIONS = ('Case inventory', 'Sources')
INTERNAL_TERMS = ('manual_commands', 'case_context', 'context object', 'capability payload',
                  'structured message', 'prompt layer', 'injected context', 'evidence_supplied',
                  'system message', 'tool metadata', 'artifact_inventory')
_INTERNAL = re.compile(r'\b(?:' + '|'.join(re.escape(term) for term in INTERNAL_TERMS) + r')\b', re.I)


class PresentationError(ValueError):
    """A controlled, testable rejection reason independent of harmless layout."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def sections(text):
    """Keep recognized sections in order; None marks neutral unstructured prose."""
    if _INTERNAL.search(text):
        raise PresentationError('internal_vocabulary', 'Internal presentation vocabulary')
    result = []
    seen = set()
    for line in text.splitlines():
        candidate = line.strip().removeprefix('## ').strip('[]').rstrip(':')
        if candidate in TITLES:
            if candidate in seen:
                raise PresentationError('repeated_section', 'Repeated advisory section')
            seen.add(candidate)
            result.append((candidate, []))
        elif line.strip():
            if not result:
                result.append((None, []))
            if result[-1][0] not in DATA_SECTIONS:
                result[-1][1].append(line.rstrip())
    # Ten unique recognized titles bound structured output. Empty ordinary
    # headings contribute nothing; data headings are filled by Locard.
    result = [(title, lines) for title, lines in result if lines or title in DATA_SECTIONS]
    if not result:
        raise PresentationError('unusable_content', 'No usable advisory content')
    return result


def render(text, context, palette=None, *, width=None):
    palette = palette or Palette()
    width = terminal_width(width)
    output = []
    for title, lines in sections(text):
        if title is not None:
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
            line = safe_text(line)
            role = 'warning' if title == 'Important cautions' else 'key' if title == 'Recommended commands' else None
            if title in ('Important cautions', 'Current assessment') and not line.lstrip().startswith(('-', '*')):
                line = '- ' + line
            indent = '  ' + line[:len(line) - len(line.lstrip())]
            # Wrap escaped plain text before styling so ANSI sequences have no width.
            # Preserve indentation while bounding pathological model whitespace.
            indent = indent[:width // 2]
            rows = textwrap.wrap(line.lstrip(), width=width, initial_indent=indent,
                                 subsequent_indent=indent, break_long_words=True,
                                 break_on_hyphens=False, replace_whitespace=False)
            output.extend(palette(role, row) if role else row for row in rows)
    return '\n'.join(output)

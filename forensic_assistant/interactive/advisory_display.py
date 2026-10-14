"""Deterministic advisory presentation; never interprets command syntax or claims."""
import re
import textwrap

from forensic_assistant.terminal import Palette
from forensic_assistant.retrieval.layout import terminal_width
from forensic_assistant.retrieval.presentation import safe_text

INTERNAL_TERMS = ('manual_commands', 'case_context', 'context object', 'capability payload',
                  'structured message', 'prompt layer', 'injected context', 'evidence_supplied',
                  'system message', 'tool metadata', 'artifact_inventory')
_INTERNAL = re.compile(r'\b(?:' + '|'.join(re.escape(term) for term in INTERNAL_TERMS) + r')\b', re.I)


class PresentationError(ValueError):
    """A controlled, testable rejection reason independent of harmless layout."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def check_text(text):
    if _INTERNAL.search(text):
        raise PresentationError('internal_vocabulary', 'Internal presentation vocabulary')


def render(response, context, palette=None, *, width=None):
    from .advisory import INVENTORY_ADVICE
    palette = palette or Palette()
    width = terminal_width(width)
    output = []

    def heading(title):
        output.extend(['', palette('heading', title)])

    def line(value, indent='  ', role=None):
        # Escape before wrapping; style each row afterwards so ANSI has no width.
        for part in safe_text(value).splitlines():
            rows = textwrap.wrap(part, width=width, initial_indent=indent,
                                 subsequent_indent=indent, break_long_words=True,
                                 break_on_hyphens=False, replace_whitespace=False)
            output.extend(palette(role, row) if role else row for row in rows)

    if response is INVENTORY_ADVICE:
        heading('Case inventory')
        counts = context['artifact_inventory']
        padding = max(map(len, counts), default=0)
        for kind, count in counts.items():
            line(f'{kind:<{padding}}  {count:,} records')
        heading('Sources')
        sources = context['sources']
        if sources['total'] is None:
            line('Source registry unavailable for this case schema.')
        elif sources['total'] == 0:
            line('No registered sources.')
        else:
            line(f"{sources['total']} sources; showing {sources['shown']} (analyst-supplied metadata).")
            for index, source in enumerate(sources['items'], 1):
                details = [label + ': ' + safe_text(source[key]) for key, label in
                           (('hostname', 'host'), ('username', 'user'), ('volume_root', 'volume'))
                           if source[key] is not None]
                label = safe_text(source['display_name'])
                line(f'{index}. {label}' + (' — ' + ', '.join(details) if details else ''))
            if sources['truncated']:
                line('Additional sources are not shown.')
        if context['truncated_fields']:
            line('Some case/source labels or metadata were shortened.')
        heading('Current assessment')
        line('- Individual records have not been inspected.')
        line('- No forensic conclusions have been reached.')
        return '\n'.join(output)

    if response['goal'] and response['goal'].strip():
        heading('Goal')
        line(response['goal'])
    if response['assessment']:
        heading('Current assessment')
        for item in response['assessment']:
            line('- ' + item)
    if response['steps']:
        heading('Suggested approach')
        for index, step in enumerate(response['steps'], 1):
            if index > 1:
                output.append('')
            line(f'{index}. ' + step['text'])
            for command in step['commands']:
                line(command, indent='     ', role='key')
    if response['cautions']:
        heading('Important cautions')
        for item in response['cautions']:
            line('- ' + item, role='warning')
    return '\n'.join(output)

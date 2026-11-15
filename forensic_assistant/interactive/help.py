"""Help derived from the canonical parser tree."""
import argparse
import textwrap
from forensic_assistant.terminal import Palette, TextSpan, render_spans
from forensic_assistant.command_surface import FAMILIES

SHELL_COMMANDS = {'help': 'Show command help', '?': 'Show command help', 'quit': 'End the session', '!': 'Ask AI; existing disclosure and tool approvals apply'}


def command_help(name, palette=None):
    return render_spans((TextSpan(name, 'command'), TextSpan(': ', 'punctuation'),
                         TextSpan(SHELL_COMMANDS[name])), palette)


def paths(parser, prefix=()):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, child in action.choices.items():
                path = (*prefix, name)
                yield path, child
                yield from paths(child, path)


def catalog(parser, palette=None, *, all_commands=False):
    palette = palette or Palette()
    lines = ['']
    entries = [(' '.join(path), child.description or '') for path, child in paths(parser)] if all_commands else list(FAMILIES.items())
    entries += list(SHELL_COMMANDS.items())
    width = max(len(name) for name, _ in entries)
    for name, description in entries:
        summary = textwrap.shorten(description.splitlines()[0], width=90, placeholder='...') if description else ''
        lines.append(render_spans((TextSpan('  '), TextSpan(name.ljust(width), 'command'),
                                   TextSpan('  ' + summary)), palette))
    lines.extend(['', 'Use help <family> <operation> for options; help all lists advanced operations.',
                  render_spans((TextSpan('AI proposals are not evidence. Mutations and cloud disclosure retain their explicit approvals.', 'forensic_note'),), palette), ''])
    return '\n'.join(lines)

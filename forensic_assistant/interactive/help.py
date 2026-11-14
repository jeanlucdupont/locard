"""Help derived from the canonical parser tree."""
import argparse
from forensic_assistant.terminal import Palette
from forensic_assistant.command_surface import FAMILIES

SHELL_COMMANDS = {'help': 'Show command help', '?': 'Show command help', 'quit': 'End the session', '!': 'Ask AI; existing disclosure and tool approvals apply'}


def command_help(name):
    return name + ': ' + SHELL_COMMANDS[name]


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
        lines.append('  ' + palette('key', name.ljust(width)) + '  ' + description)
    lines.extend(['', 'Use help <family> <operation> for options; help all lists advanced operations.',
                  'AI proposals are not evidence. Mutations and cloud disclosure retain their explicit approvals.', ''])
    return '\n'.join(lines)

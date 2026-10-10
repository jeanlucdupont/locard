"""Interactive navigation built from the same parser used for dispatch."""
import argparse
from forensic_assistant.terminal import Palette
from forensic_assistant.retrieval.presentation import safe
from forensic_assistant.command_catalog import COMMANDS, SHELL_COMMANDS

# Argument syntax stays with the interactive command implementation.
SHELL_USAGE = {
    'ai': 'ai',
    'expert': 'expert',
    '?': '? [command]',
    'case': 'case [path|new]',
    'color': 'color [on|off]',
    'exit': 'exit',
    'help': 'help [command]',
    'version': 'version',
    'quit': 'quit',
}


def command_help(name):
    result = SHELL_USAGE[name] + ': ' + COMMANDS[name]
    if name in ('ai', 'expert'):
        result += ('\nUse ai to enter AI mode and expert to return to expert mode. '
                   'In AI mode, prefix natural-language requests with !. '
                   'All standard Locard commands remain available. '
                   'AI is advisory only: it does not execute commands. '
                   'The # prompt marks AI mode, not elevated OS privileges. '
                   'Each request is independent; no conversation or raw evidence is automatically supplied.')
    return result


def catalog(parser, palette=None):
    palette = palette or Palette()
    commands = dict(SHELL_COMMANDS)
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name in action.choices:
                commands[name] = COMMANDS[name]
    width = max(map(len, commands))
    lines = ['']
    for name, description in sorted(commands.items()):
        lines.append('  ' + palette('key', name.ljust(width)) + '  ' + safe(description))
    return '\n'.join([*lines, '', 'AI mode: !<text> asks the local advisory assistant; normal commands remain available.',
                      '', 'Type `help <command>` for details.\n'])

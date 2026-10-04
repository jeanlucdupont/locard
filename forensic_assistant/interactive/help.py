"""Interactive navigation built from the same parser used for dispatch."""
import argparse
from forensic_assistant.terminal import Palette
from forensic_assistant.retrieval.presentation import safe
from forensic_assistant.command_catalog import COMMANDS, SHELL_COMMANDS

# Argument syntax stays with the interactive command implementation.
SHELL_USAGE = {
    '?': '? [command]',
    'case': 'case [path|new]',
    'color': 'color [on|off]',
    'exit': 'exit',
    'help': 'help [command]',
    'version': 'version',
    'quit': 'quit',
}


def command_help(name):
    return SHELL_USAGE[name] + ': ' + COMMANDS[name]


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
    return '\n'.join([*lines, '', 'Type `help <command>` for details.\n'])

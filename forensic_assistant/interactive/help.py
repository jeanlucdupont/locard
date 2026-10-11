"""Interactive navigation built from the same parser used for dispatch."""
import argparse
from forensic_assistant.terminal import Palette
from forensic_assistant.retrieval.presentation import safe
from forensic_assistant.command_catalog import COMMANDS, SHELL_COMMANDS

# Argument syntax stays with the interactive command implementation.
SHELL_USAGE = {
    'add-evidence': 'add-evidence',
    'ai': 'ai',
    'expert': 'expert',
    '?': '? [command]',
    'case': 'case [path|new]',
    'new-case': 'new-case',
    'color': 'color [on|off]',
    'exit': 'exit',
    'help': 'help [command]',
    'version': 'version',
    'quit': 'quit',
}


def command_help(name):
    result = SHELL_USAGE[name] + ': ' + COMMANDS[name]
    if name == 'add-evidence':
        result += ('\nAppend evidence to the current case using guided mounted/extracted Windows scanning or manual '
                   'artifact selection. Existing evidence and case metadata are preserved. Optional source metadata '
                   'applies to the new source only. Mounted $MFT requires extraction as a standard file. '
                   'Type cancel to return without ingestion before confirmation. After ingestion starts, committed '
                   'work is retained on interruption. The current Expert/AI mode is preserved. No arguments are accepted.')
    if name == 'new-case':
        result += ('\nGuided setup: create a case and ingest evidence, investigate in Expert or AI-assisted mode, '
                   'then generate a report. Scan a mounted/extracted Windows filesystem, select artifacts manually, '
                   'or skip ingestion. A case name creates a managed workspace; analyst/organization are optional. '
                   'Select browser profiles explicitly. Mounted $MFT may require extraction. Administrator '
                   'access is recommended, not guaranteed. Type cancel to stop; Enter accepts defaults. '
                   'Review candidates and confirm before anything is created or ingested. '
                   'Disk images must be mounted/extracted separately. Existing case new and expert ingest-* '
                   'commands remain available for adding evidence later. Completion returns to Expert mode; '
                   'type ai for AI-assisted mode and prefix natural-language requests with !. '
                   'The prompt uses the human case name when available. No model is called during setup.')
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

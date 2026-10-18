"""Interactive navigation built from the same parser used for dispatch."""
import argparse
from forensic_assistant.terminal import Palette
from forensic_assistant.retrieval.presentation import safe
from forensic_assistant.command_catalog import COMMANDS, SHELL_COMMANDS, COMMAND_ALIASES, ADVANCED_COMMANDS

# Argument syntax stays with the interactive command implementation.
SHELL_USAGE = {
    'add-evidence': 'add-evidence',
    'ingest-wizard': 'ingest wizard',
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
        return result + '\nUse help ingest wizard for documentation.'
    if name == 'ingest-wizard':
        result += ('\nAppend evidence to the current case using guided mounted/extracted Windows scanning or manual '
                   'evidence selection. Existing evidence and case metadata are preserved. Optional source metadata '
                   'applies to the new source only. Mounted $MFT requires extraction as a standard file. '
                   'Type cancel to return without ingestion before confirmation. After ingestion starts, committed '
                   'work is retained on interruption. No arguments are accepted. Direct ingest subcommands accept a known artifact and explicit options. '
                   'Source metadata is analyst supplied; identities are never inferred from directory names.')
    if name == 'new-case':
        result += ('\nGuided setup: create a case and ingest evidence, investigate using commands or ! AI requests, '
                   'then generate a report. Scan a mounted/extracted Windows filesystem, select evidence manually, '
                   'or skip ingestion. A case name creates a managed workspace; analyst/organization are optional. '
                   'Select browser profiles explicitly. Mounted $MFT may require extraction. Administrator '
                   'access is recommended, not guaranteed. Type cancel to stop; Enter accepts defaults. '
                   'Review candidates and confirm before anything is created or ingested. '
                   'Disk images must be mounted/extracted separately. Existing case new and direct ingest '
                   'commands remain available for adding evidence later. Prefix natural-language requests with !. '
                   'The prompt uses the human case name when available. No model is called during setup.')
    if name == 'expert':
        result += ('\nPrefix a natural-language request with ! to ask the configured AI assistant. '
                   'Inventory and uncertain questions stay advisory; record-level questions use bounded investigation with approval before each proposed tool. '
                   'The prompt remains >; no mode change is needed.')
    return result


def catalog(parser, palette=None):
    palette = palette or Palette()
    commands = {name: text for name, text in SHELL_COMMANDS.items() if name not in COMMAND_ALIASES}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name in action.choices:
                if name not in set(COMMAND_ALIASES) | ADVANCED_COMMANDS:
                    commands[name] = COMMANDS[name]
    width = max(map(len, commands))
    lines = ['']
    for name, description in sorted(commands.items()):
        lines.append('  ' + palette('key', name.ljust(width)) + '  ' + safe(description))
    return '\n'.join([*lines, '', 'Prefix a natural-language request with ! to ask the configured AI assistant (approval required for each proposed tool).',
                      '', 'Type `help <command>` for details.\n'])

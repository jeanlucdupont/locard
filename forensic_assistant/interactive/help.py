"""Interactive navigation built from the same parser used for dispatch."""
import argparse
from forensic_assistant.terminal import Palette
from forensic_assistant.retrieval.presentation import safe

SHELL_COMMANDS={
    '?':'Provide help on a command (same as `help`)',
    'case':'Select or create a case',
    'color':'Control syntax coloring',
    'exit':'Exit Locard (Same as `quit`)',
    'help':'Provide help on a command',
    'version':'Show Locard\'s version',
    'quit':'Exit Locard (Same as `exit`)',
}


def catalog(parser,palette=None):
    palette=palette or Palette();commands=dict(SHELL_COMMANDS)
    for action in parser._actions:
        if isinstance(action,argparse._SubParsersAction):
            descriptions={entry.dest:entry.help for entry in action._choices_actions}
            for name,child in action.choices.items():
                commands[name]=descriptions.get(name) or ('Browse timestamped evidence' if name=='timeline' else child.description or 'Show command help')
    width=max(map(len,commands))
    lines = ['']
    for name,description in sorted(commands.items()):
        lines.append('  '+palette('key',name.ljust(width))+'  '+safe(description))
    return '\n'.join([*lines,'','Type `help <command>` for details.\n'])

"""Help derived from the canonical parser tree."""
import argparse
import textwrap
from forensic_assistant.terminal import Palette, TextSpan, render_spans
from forensic_assistant.command_surface import FAMILIES

SHELL_COMMANDS = {'help': 'Show command help', '?': 'Show command help', 'quit': 'End the session', '!': 'Ask AI'}


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
    import shutil
    terminal_width = max(24, shutil.get_terminal_size().columns - 2)
    width = min(max(len(name) for name, _ in entries), max(12, terminal_width // 2))
    for name, description in entries:
        summary = description.splitlines()[0] if description else ''
        continuation = ' ' * (width + 4)
        wrapped = textwrap.wrap(summary, max(12, terminal_width-width-4)) or ['']
        left = '  ' + name
        suffix = ('\n' + continuation if len(name) > width else ' ' * (width-len(name)+2))
        lines.append(render_spans((TextSpan(left, 'command'), TextSpan(suffix+wrapped[0])), palette))
        lines.extend(continuation + line for line in wrapped[1:])
    lines.append('')
    return '\n'.join(lines)


def contextual_help(parser, words, palette=None):
    """Resolve only canonical command paths; never parse or dispatch arguments."""
    from forensic_assistant.terminal import render_spans, TextSpan
    from forensic_assistant.cli_parser import semantic_help, UnknownCommand
    if len(words) == 1 and words[0] in SHELL_COMMANDS:
        return command_help(words[0], palette)
    for word in words:
        action = next((a for a in parser._actions if isinstance(a, argparse._SubParsersAction)), None)
        if action is None or word not in action.choices:
            text = 'Unknown help path: ' + ' '.join(words)
            raise UnknownCommand(text, [TextSpan(text, 'error')])
        parser = action.choices[word]
    return render_spans(semantic_help(parser), palette)

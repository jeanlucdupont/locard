"""Argparse presentation policy; accepted arguments and dispatch stay shared."""
import argparse
import inspect
from forensic_assistant.retrieval.presentation import safe


class UnknownCommand(Exception):
    def __init__(self, message, spans=None):
        super().__init__(message)
        self.spans = spans


class InvalidArguments(Exception):
    def __init__(self, message, spans=None):
        super().__init__(message)
        self.spans = spans


class VersionDetails(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        import json
        import sys
        from forensic_assistant.version import resolve
        parser._print_message(json.dumps(resolve(), indent=2) + '\n', sys.stdout)
        parser.exit()


class LocardParser(argparse.ArgumentParser):
    """Retain standard help actions without advertising their switches."""

    def __init__(self, *args, **kwargs):
        if "color" in inspect.signature(argparse.ArgumentParser).parameters:
            kwargs["color"] = False
        super().__init__(*args, **kwargs)
        for action in self._actions:
            if isinstance(action, argparse._HelpAction):
                action.help = argparse.SUPPRESS

    def print_help(self, file=None):
        import sys
        from forensic_assistant.terminal import Palette, enabled, write_spans
        stream = sys.stdout if file is None else file
        configured = getattr(self, 'context', {}).get('palette')
        allowed = enabled(stream=stream) and not getattr(self, '_help_no_color', False)
        palette = Palette(allowed and (configured is None or configured.enabled))
        write_spans(semantic_help(self), palette=palette, stream=stream)

    def parse_known_args(self, args=None, namespace=None):
        import sys
        argv = sys.argv[1:] if args is None else args
        if '--no-color' in argv or '--json' in argv:
            for parser in parser_tree(self):
                parser._help_no_color = True
        return super().parse_known_args(args, namespace)

    def selector_guidance(self, message):
        if message == 'one of the arguments --evidence --process is required':
            return getattr(self, 'missing_selector_guidance', None)
        return None

    def error(self, message):
        guidance = self.selector_guidance(message)
        if guidance:
            self._print_message(guidance + '\n')
        super().error(message)

    def parse_args(self, args=None, namespace=None):
        for parser in parser_tree(self):
            parser._help_no_color = False
        parsed = super().parse_args(args, namespace)
        if (getattr(parsed, 'command', None) == 'semantic'
                and getattr(parsed, 'semantic_command', None) == 'search' and parsed.limit is None):
            parsed.limit = 10 if isinstance(self, InteractiveParser) and not parsed.json else 20
        if getattr(parsed, '_interactive_text', False):
            # Resolve presentation after parsing; never insert synthetic argv.
            # Raw diagnostic output keeps its existing default JSON contract.
            if not parsed.json and not parsed.text:
                parsed.text = isinstance(self, InteractiveParser) and not parsed.raw
            parsed.json = not parsed.text
        from .cli_time import normalize_arguments
        try:
            return normalize_arguments(parsed)
        except ValueError as exc:
            self.error(str(exc))


class InteractiveParser(LocardParser):
    def parse_known_args(self, args=None, namespace=None):
        if hasattr(self, 'context'):
            self.context['active'] = self
        return super().parse_known_args(args, namespace)

    def _check_value(self, action, value):
        if isinstance(action, argparse._SubParsersAction) and action.dest == 'family' and value not in action.choices:
            from forensic_assistant.terminal import TextSpan
            raise UnknownCommand('Unknown command: ' + safe(value) + '\nType `help` to list available commands.',
                [TextSpan('Unknown command: ' + safe(value), 'error'), TextSpan('\nType '), TextSpan('help', 'command'), TextSpan(' to list available commands.')])
        return super()._check_value(action, value)

    def error(self, message):
        parser = self.context.get('active', self)
        guidance = parser.selector_guidance(message)
        from forensic_assistant.terminal import TextSpan
        if guidance:
            raise InvalidArguments(guidance, [TextSpan('Invalid arguments.\n', 'error'), TextSpan(guidance)])
        if parser.prog == 'Locard shell':
            raise InvalidArguments('Invalid arguments. Type `help` for command syntax.',
                [TextSpan('Invalid arguments. ', 'error'), TextSpan('Type '), TextSpan('help', 'command'), TextSpan(' for command syntax.')])
        message = 'Invalid arguments.\n' + parser.format_usage().rstrip() + '\nType `help ' + parser.prog + '` for details.'
        raise InvalidArguments(message, [TextSpan('Invalid arguments.\n', 'error'),
            *semantic_help(parser, usage_only=True), TextSpan('Type '),
            TextSpan('help ' + parser.prog, 'command'), TextSpan(' for details.')])



def configure_interactive(parser, path=(), context=None):
    context = {} if context is None else context
    parser.context = context
    parser.prog = ' '.join(path) if path else 'Locard shell'
    for action in parser._actions:
        if '--no-color' in action.option_strings:
            action.help = argparse.SUPPRESS
        if isinstance(action, argparse._SubParsersAction):
            for name, child in action.choices.items():
                configure_interactive(child, (*path, name), context)


def classify_help(parser):
    """Group presentation/diagnostic controls without changing parse semantics."""
    advanced = {'--raw', '--details', '--offset', '--evtx-after', '--parser-timeout',
                '--record-size', '--max-files', '--max-file-size', '--append', '--force'}
    visible = [a for a in parser._optionals._group_actions if a.help != argparse.SUPPRESS]
    complex_help = len(visible) > 8
    parser._optionals.title = 'Common options' if complex_help else 'Options'
    selected = [a for a in parser._optionals._group_actions
                if advanced.intersection(a.option_strings)]
    if selected and complex_help:
        group = parser.add_argument_group('Advanced options')
        for action in selected:
            parser._optionals._group_actions.remove(action)
            group._group_actions.append(action)
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            descriptions = {c.dest:c.help for c in action._choices_actions}
            for name, child in action.choices.items():
                if not child.description:
                    child.description = descriptions.get(name)
                classify_help(child)


def parser_tree(parser):
    yield parser
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                yield from parser_tree(child)


def semantic_help(parser, *, usage_only=False):
    """Build human help from actions/groups, never recolor formatted prose.

    Argparse retains ownership of argument syntax expansion, defaults and parsing.
    Only action syntax is tokenized into delimiters and selectable text.
    """
    import shutil
    import textwrap
    from forensic_assistant.terminal import TextSpan, safe_span_text
    width = max(24, shutil.get_terminal_size().columns - 2)
    formatter = parser._get_formatter()
    spans = []
    def add(text, role='label'):
        spans.append(TextSpan(text, role))
    def syntax(text):
        # This input is generated action syntax, not descriptions or arbitrary prose.
        from itertools import groupby
        for punctuation, chars in groupby(text, lambda c: c in '[]{}(),| '):
            add(''.join(chars), 'punctuation' if punctuation else 'syntax')
    def prose(text, indent=''):
        for line in str(text).splitlines():
            for wrapped in textwrap.wrap(safe_span_text(line), max(20, width-len(indent))) or ['']:
                add(indent + wrapped + '\n')
    def arguments(action):
        if isinstance(action, argparse._SubParsersAction):
            return '{' + ','.join(action.choices) + '} ...'
        return formatter._format_args(action, formatter._get_default_metavar_for_optional(action)
                                      if action.option_strings else formatter._get_default_metavar_for_positional(action))
    def invocation(action, usage=False):
        if action.option_strings:
            options = action.option_strings[:1] if usage else action.option_strings
            return ', '.join(opt + (' ' + arguments(action) if action.nargs != 0 else '') for opt in options)
        return arguments(action)
    visible = [a for a in parser._actions if a.help != argparse.SUPPRESS]
    add('usage: '); add(parser.prog, 'command')
    column = 7 + len(parser.prog)
    def usage_token(text):
        nonlocal column
        if column + 1 + len(text) > width:
            add('\n       '); column = 7
        else:
            add(' '); column += 1
        # Wrap generated syntax at separators, never split an option identifier.
        parts = textwrap.wrap(text.replace(',', ', '), max(8, width-column), break_long_words=False, break_on_hyphens=False) or ['']
        for index, part in enumerate(parts):
            if index:
                add('\n       '); column = 7
            syntax(part); column += len(part)
    grouped = set()
    for action in visible:
        if action in grouped:
            continue
        group = next((g for g in parser._mutually_exclusive_groups if action in g._group_actions), None)
        if group:
            members = [a for a in group._group_actions if a in visible]
            grouped.update(members)
            usage_token(('(' if group.required else '[') + ' | '.join(invocation(a, True) for a in members)
                   + (')' if group.required else ']'))
        else:
            text = invocation(action, True)
            usage_token('[' + text + ']' if action.option_strings and not action.required else text)
    add('\n')
    if usage_only:
        return spans
    add('\n')
    if parser.description:
        prose(parser.description); add('\n')
    for group in parser._action_groups:
        actions = [a for a in group._group_actions if a.help != argparse.SUPPRESS]
        if not actions:
            continue
        add(group.title + ':\n', 'heading')
        if group.description:
            prose(group.description, '  ')
        # Plain invocation widths determine the columns before any ANSI encoding.
        lefts = [invocation(a) for a in actions if not isinstance(a, argparse._SubParsersAction)]
        lefts += [c.metavar or c.dest for a in actions if isinstance(a, argparse._SubParsersAction) for c in a._choices_actions]
        left_width = min(max(map(len, lefts), default=12), max(12, width // 3))
        description_column = left_width + 4
        def row(left, description, indent=2):
            add(' ' * indent); syntax(left)
            if not description:
                add('\n'); return
            lines = []
            for line in str(description).splitlines():
                lines.extend(textwrap.wrap(safe_span_text(line), max(8, width-description_column)) or [''])
            if len(left) > left_width or width < 55:
                add('\n' + ' ' * description_column)
            else:
                add(' ' * (description_column-indent-len(left)))
            add(lines[0] + '\n')
            for line in lines[1:]:
                add(' ' * description_column + line + '\n')
        for action in actions:
            if not isinstance(action, argparse._SubParsersAction):
                row(invocation(action), formatter._expand_help(action) if action.help else '')
            if isinstance(action, argparse._SubParsersAction):
                for child in action._choices_actions:
                    if child.help != argparse.SUPPRESS:
                        row(child.metavar or child.dest, formatter._expand_help(child), indent=2)
        add('\n')
    if parser.epilog:
        prose(parser.epilog)
    return spans

"""Argparse presentation policy; accepted arguments and dispatch stay shared."""
import argparse
import inspect
from forensic_assistant.retrieval.presentation import safe


class UnknownCommand(Exception):
    pass


class InvalidArguments(Exception):
    pass


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
        return parsed


class InteractiveParser(LocardParser):
    def parse_known_args(self, args=None, namespace=None):
        if hasattr(self, 'context'):
            self.context['active'] = self
        return super().parse_known_args(args, namespace)

    def _check_value(self, action, value):
        if isinstance(action, argparse._SubParsersAction) and action.dest == 'family' and value not in action.choices:
            raise UnknownCommand('Unknown command: ' + safe(value) + '\nType `help` to list available commands.')
        return super()._check_value(action, value)

    def error(self, message):
        parser = self.context.get('active', self)
        guidance = parser.selector_guidance(message)
        if guidance:
            raise InvalidArguments(guidance)
        if parser.prog == 'Locard shell':
            raise InvalidArguments('Invalid arguments. Type `help` for command syntax.')
        raise InvalidArguments('Invalid arguments.\n' + parser.format_usage().rstrip() +
                               '\nType `help ' + parser.prog + '` for details.')


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
    parser._optionals.title = 'Common options'
    selected = [a for a in parser._optionals._group_actions
                if advanced.intersection(a.option_strings)]
    if selected:
        group = parser.add_argument_group('Advanced options',
            'Diagnostic, resource or output controls; existing validation still applies.')
        for action in selected:
            parser._optionals._group_actions.remove(action)
            group._group_actions.append(action)
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                classify_help(child)


def parser_tree(parser):
    yield parser
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                yield from parser_tree(child)


def semantic_help(parser):
    """Build human help from actions/groups, never recolor formatted prose.

    Argparse retains ownership of argument syntax expansion, defaults and parsing.
    Only action syntax is tokenized into delimiters and selectable text.
    """
    import shutil
    import textwrap
    from forensic_assistant.terminal import TextSpan, safe_span_text
    width = max(40, min(100, shutil.get_terminal_size().columns - 2))
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
    add('usage: ', 'heading'); add(parser.prog, 'command')
    grouped = set()
    for action in visible:
        if action in grouped:
            continue
        group = next((g for g in parser._mutually_exclusive_groups if action in g._group_actions), None)
        add(' ')
        if group:
            members = [a for a in group._group_actions if a in visible]
            grouped.update(members)
            syntax(('(' if group.required else '[') + ' | '.join(invocation(a, True) for a in members)
                   + (')' if group.required else ']'))
        else:
            text = invocation(action, True)
            syntax('[' + text + ']' if action.option_strings and not action.required else text)
    add('\n\n')
    if parser.description:
        prose(parser.description); add('\n')
    for group in parser._action_groups:
        actions = [a for a in group._group_actions if a.help != argparse.SUPPRESS]
        if not actions:
            continue
        add(group.title + ':\n', 'heading')
        if group.description:
            prose(group.description, '  ')
        for action in actions:
            add('  '); syntax(invocation(action)); add('\n')
            if action.help:
                prose(formatter._expand_help(action), '    ')
            if isinstance(action, argparse._SubParsersAction):
                for child in action._choices_actions:
                    if child.help != argparse.SUPPRESS:
                        add('    '); syntax(child.metavar or child.dest); add('\n')
                        prose(formatter._expand_help(child), '      ')
        add('\n')
    if parser.epilog:
        prose(parser.epilog)
    return spans

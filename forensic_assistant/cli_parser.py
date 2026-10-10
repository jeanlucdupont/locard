"""Argparse presentation policy; accepted arguments and dispatch stay shared."""
import argparse
from forensic_assistant.retrieval.presentation import safe


class UnknownCommand(Exception):
    pass


class InvalidArguments(Exception):
    pass


class LocardParser(argparse.ArgumentParser):
    """Retain standard help actions without advertising their switches."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for action in self._actions:
            if isinstance(action, argparse._HelpAction):
                action.help = argparse.SUPPRESS

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
        parsed = super().parse_args(args, namespace)
        if getattr(parsed, '_interactive_text', False):
            # Resolve presentation after parsing; never insert synthetic argv.
            # Raw diagnostic output keeps its existing default JSON contract.
            if not parsed.json and not parsed.text:
                parsed.text = isinstance(self, InteractiveParser) and not parsed.raw
            parsed.json = not parsed.text
        return parsed


class InteractiveParser(LocardParser):
    def print_help(self, file=None):
        import sys
        if file is None:
            file = sys.stdout
        from forensic_assistant.terminal import Palette
        palette = self.context.get('palette', Palette())
        lines = self.format_help().splitlines(keepends=True)
        self._print_message(
            ''.join(palette('key' if line.lstrip().startswith('-') else 'heading', line.rstrip('\n')) + '\n'
                    if line.startswith('usage:') or line.rstrip().endswith(':') or line.lstrip().startswith('-')
                    else line for line in lines),
            file
        )

    def parse_known_args(self, args=None, namespace=None):
        if hasattr(self, 'context'):
            self.context['active'] = self
        return super().parse_known_args(args, namespace)

    def _check_value(self, action, value):
        if isinstance(action, argparse._SubParsersAction) and action.dest == 'command' and value not in action.choices:
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

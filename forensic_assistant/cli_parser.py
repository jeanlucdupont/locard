"""Argparse presentation policy; accepted arguments and dispatch stay shared."""
import argparse
from forensic_assistant.retrieval.presentation import safe


class UnknownCommand(Exception):
    pass


class InvalidArguments(Exception):
    pass


class InteractiveParser(argparse.ArgumentParser):
    def parse_known_args(self, args=None, namespace=None):
        if hasattr(self,'context'):self.context['active']=self
        return super().parse_known_args(args,namespace)

    def _check_value(self, action, value):
        if isinstance(action,argparse._SubParsersAction) and action.dest=='command' and value not in action.choices:
            raise UnknownCommand('Unknown command: '+safe(value)+'\nType `help` to list available commands.')
        return super()._check_value(action,value)

    def error(self, message):
        parser=self.context.get('active',self)
        if parser.prog=='Locard shell':
            raise InvalidArguments('Invalid arguments. Type `help` for command syntax.')
        raise InvalidArguments('Invalid arguments.\n'+parser.format_usage().rstrip()+
                               '\nType `help '+parser.prog+'` for details.')


def configure_interactive(parser, path=(), context=None):
    context={} if context is None else context
    parser.context=context
    parser.prog=' '.join(path) if path else 'Locard shell'
    for action in parser._actions:
        if '--no-color' in action.option_strings:action.help=argparse.SUPPRESS
        if isinstance(action,argparse._SubParsersAction):
            for name,child in action.choices.items():configure_interactive(child,(*path,name),context)

"""Metadata-only completion. Argparse introspection is isolated in this module."""
import argparse
from dataclasses import dataclass
from functools import lru_cache
from os.path import commonprefix

from forensic_assistant.command_catalog import COMMANDS


class MetadataUnavailable(ValueError):
    """A parser definition cannot safely supply completion metadata."""


@dataclass(frozen=True)
class Completion:
    text: str
    cursor: int
    candidates: tuple[str, ...] = ()


@lru_cache(maxsize=1)
def _parser():
    # Construct metadata once, on first argument completion; never parse/dispatch.
    from forensic_assistant.cli import build_parser
    try:
        return build_parser(interactive=True)
    except argparse.ArgumentError as exc:
        raise MetadataUnavailable(str(exc)) from exc


def _options(parser):
    return {option: action for action in parser._actions for option in action.option_strings}


def _positionals(parser):
    return [action for action in parser._actions if not action.option_strings]


def _option(parser, name):
    options = _options(parser)
    if name in options:
        return options[name]
    if parser.allow_abbrev and name.startswith('--'):
        matches = [action for option, action in options.items() if option.startswith(name)]
        if len(matches) == 1:
            return matches[0]
    return None


def _context(words):
    """Follow only argument arity and subparser boundaries, not argument values."""
    parser = _parser()
    position = 0
    consumed = 0
    pending = 0
    variable = None
    for word in words:
        action = _option(parser, word.partition('=')[0]) if word.startswith('-') else None
        if pending:
            if action is not None or word == '--':
                return None
            pending -= 1
            continue
        if variable:
            if action is None:
                if variable == '?':
                    variable = None
                continue
            variable = None
        if word == '--':
            return None
        if word.startswith('-'):
            if action is None:
                return None
            count = 1 if action.nargs is None else action.nargs
            inline = '=' in word
            if isinstance(count, int):
                if inline and count != 1:
                    return None
                pending = count - int(inline)
            elif count in ('?', '*', '+'):
                variable = None if inline else count
            else:
                return None
            continue
        positional = _positionals(parser)
        if position >= len(positional):
            return None
        action = positional[position]
        if isinstance(action, argparse._SubParsersAction):
            if word not in action.choices:
                return None
            parser = action.choices[word]
            position = consumed = 0
        elif action.nargs in (None, '?'):
            position += 1
        elif isinstance(action.nargs, int):
            consumed += 1
            if consumed == action.nargs:
                position += 1
                consumed = 0
        elif action.nargs not in ('*', '+'):
            return None
    if pending or variable:
        return None
    return parser, _positionals(parser)[position:]


def _token(text, cursor):
    """Find a token span using Locard's literal-backslash/doubled-quote rules."""
    i = 0
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        start = i
        quote = None
        quoted = False
        while i < len(text):
            char = text[i]
            if quote:
                if char == quote:
                    if i + 1 < len(text) and text[i + 1] == quote:
                        i += 1
                    else:
                        quote = None
            elif char in ('"', "'"):
                quoted = True
                quote = char
            elif char.isspace():
                break
            i += 1
        if start <= cursor <= i:
            return start, i, quoted
    return cursor, cursor, False


def complete(text, cursor):
    unchanged = Completion(text, cursor)
    if not 0 <= cursor <= len(text) or len(text) > 65536 or any(c in text for c in '\r\n\x00'):
        return unchanged
    start, end, quoted = _token(text, cursor)
    if quoted:
        return unchanged
    prefix, suffix = text[start:cursor], text[cursor:end]
    # Reuse the submission tokenizer for completed tokens. Unfinished quotes or
    # unsupported shell syntax are ordinary incomplete input, not editor errors.
    from .shell import split
    try:
        words = split(text[:start])
    except ValueError:
        return unchanged
    help_target = bool(words and words[0] in ('help', '?'))
    if help_target:
        words = words[1:]
        if prefix.startswith('-'):
            return unchanged
    if not words:
        names = COMMANDS
    else:
        if words[0] not in COMMANDS:
            return unchanged
        try:
            context = _context(words)
        except MetadataUnavailable:
            return unchanged
        if context is None:
            return unchanged
        parser, remaining = context
        if remaining and isinstance(remaining[0], argparse._SubParsersAction) and not prefix.startswith('-'):
            names = remaining[0].choices
        elif not help_target and (prefix.startswith('-') or (not prefix and not any(a.required for a in remaining))):
            names = [name for name, action in _options(parser).items() if action.help != argparse.SUPPRESS]
        else:
            return unchanged
    matches = tuple(sorted(name for name in names if name.startswith(prefix) and name.endswith(suffix)
                           and len(name) >= len(prefix) + len(suffix)))
    if not matches:
        return unchanged
    if len(matches) == 1:
        replacement = matches[0]
        rest = text[end:]
        # Reuse existing whitespace, never duplicate it or discard right-hand text.
        if not rest:
            rest = ' '
        return Completion(text[:start] + replacement + rest, start + len(replacement) + 1)
    shared = commonprefix(matches)
    shared = shared[:min(len(name) - len(suffix) for name in matches)]
    if len(shared) > len(prefix):
        return Completion(text[:start] + shared + text[cursor:], start + len(shared))
    return Completion(text, cursor, matches)

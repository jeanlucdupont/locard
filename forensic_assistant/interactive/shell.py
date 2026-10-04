"""Synchronous interface over the ordinary Locard parser and dispatcher."""
import gc
import os
import sqlite3
from forensic_assistant.interactive.case import validate
from forensic_assistant.interactive.console import Reader, safe
from forensic_assistant.interactive.state import State, state_path
from forensic_assistant.cli import get_liner
from forensic_assistant.terminal import Palette, enabled

def split(line):
    """Backslashes are literal. Single/double quotes group; doubled quotes escape."""
    if len(line) > 65536 or any(c in line for c in '\r\n\x00'):
        raise ValueError('Invalid or oversized input line')
    words = []
    word = []
    quote = None
    started = False
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == quote:
                if i + 1 < len(line) and line[i + 1] == quote:
                    word.append(c)
                    i += 1
                else:
                    quote = None
            else:
                word.append(c)
        elif c in ('"', "'"):
            quote = c
            started = True
        elif c.isspace():
            if started:
                words.append(''.join(word))
                word = []
                started = False
        elif c in ';|&<>':
            raise ValueError('Shell operators are not supported; quote literal values')
        else:
            word.append(c)
            started = True
        i += 1
    if quote:
        raise ValueError('Unclosed quote')
    if started:
        words.append(''.join(word))
    return words


class Shell:
    def __init__(self, state, reader=None, *, no_color=False):
        self.state = state
        self.reader = reader or Reader()
        self.active = None
        self.last_status = 0
        self.no_color = no_color

    def activate(self, path):
        target = validate(path)
        self.active = target
        self.reader.clear()
        try:
            self.state.remember(target)
        except (OSError, ValueError) as exc:
            print('Recent case not saved: ' + safe(exc))
        from contextlib import closing
        from .case import open_existing
        with closing(open_existing(target)) as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
        print('Database: ' + safe(target) + '\n')

    def choose(self, path=None):
        if path is not None:
            if str(path).startswith(('"', "'")):
                parts = split(str(path))
                if len(parts) != 1:
                    raise ValueError('Enter one database path')
                path = parts[0]
            self.activate(path)
            return True
        print('[N] New case')
        if self.active:
            print('Current database: ' + safe(self.active))
        if self.state.recent:
            print('Recent databases:')
            for n, value in enumerate(self.state.recent, 1):
                print(f'  {n}. ' + safe(value))
        while True:
            try:
                line = self.reader.read('Database path or recent number (Enter cancels): ').strip()
                if not line or line in ('exit', 'quit'):
                    return False
                if line.casefold() in ('n', 'new'):
                    return self.new()
                if line.isdecimal() and 1 <= int(line) <= len(self.state.recent):
                    path = self.state.recent[int(line) - 1]
                elif line.startswith(('"', "'")):
                    parts = split(line)
                    if len(parts) != 1:
                        raise ValueError('Enter one database path')
                    path = parts[0]
                else:
                    path = line
                self.activate(path)
                return True
            except (OSError, ValueError, sqlite3.Error) as exc:
                print('Cannot select database: ' + safe(exc))
            except (EOFError, KeyboardInterrupt):
                print()
                return False

    def startup(self):
        from forensic_assistant import __version__
        print('                         Version ' + __version__)
        print(get_liner())
        if self.state.warning:
            print(safe(self.state.warning))
        if self.state.recent:
            try:
                validate(self.state.recent[0])
            except (OSError, ValueError, sqlite3.Error) as exc:
                print('Remembered database unavailable: ' + safe(exc))
                return self.menu()
            except (EOFError, KeyboardInterrupt):
                print()
                return False
            print('Last database: ' + safe(self.state.recent[0]) + '\n')
            try:
                response = self.reader.read('Use this database? [Y/n]: ').strip().casefold()
                if response in ('', 'y', 'yes'):
                    try:
                        self.activate(self.state.recent[0])
                        return True
                    except (OSError, ValueError, sqlite3.Error) as exc:
                        print('Remembered database unavailable: ' + safe(exc))
                elif response in ('exit', 'quit'):
                    return False
            except (EOFError, KeyboardInterrupt):
                print()
                return False
        return self.menu()

    def new(self):
        from .creation import create
        return create(self)

    def menu(self):
        while True:
            print("No active case.\n[1] Create a new case\n[2] Open an existing case\n[3] Exit")
            try:
                choice = self.reader.read("Selection (or existing database path): ").strip()
                if choice in ("", "3", "exit", "quit"):
                    return False
                if choice == "1":
                    if self.new():
                        return True
                elif choice == "2":
                    if self.choose():
                        return True
                else:
                    if self.choose(choice):
                        return True
            except (OSError, ValueError, sqlite3.Error) as exc:
                print("Cannot select database: " + safe(exc))
            except (EOFError, KeyboardInterrupt):
                print()
                return False

    def run(self):
        from forensic_assistant.cli import build_parser, dispatch
        from forensic_assistant.cli_parser import UnknownCommand, InvalidArguments
        from forensic_assistant.terminal import Palette, enabled, clear_screen
        if not self.startup():
            return 0
        try:
            while True:
                try:
                    validate(self.active)
                except KeyboardInterrupt:
                    print('\nValidation interrupted; retrying before accepting commands.')
                    continue
                except (OSError, ValueError, sqlite3.Error) as exc:
                    print('Active case unavailable: ' + safe(exc))
                    self.active = None
                    self.reader.clear()
                    if not self.menu():
                        return 0
                label = safe(self.active.parent.name + '/' + self.active.name)
                if len(label) > 80:
                    label = label[:38] + '...' + label[-39:]
                executing = False
                try:
                    prompt = Palette(enabled(self))('prompt', 'locard[' + label + ']> ')
                    words = split(self.reader.read(prompt, remember=True))
                    if not words:
                        continue
                    if words[0] in ('exit', 'quit'):
                        if len(words) != 1:
                            raise ValueError('exit takes no arguments')
                        return 0
                    if words[0] == 'version':
                        if len(words) != 1:
                            raise ValueError('version takes no arguments')
                        from forensic_assistant import __version__
                        print('Locard version ' + __version__)
                        self.last_status = 0
                        continue
                    if words[0] == 'case':
                        if len(words) > 2:
                            raise ValueError('Use case or case "database path"')
                        if len(words) == 2 and words[1] == 'new':
                            self.new()
                        else:
                            self.choose(words[1] if len(words) == 2 else None)
                        continue
                    if words[0] == 'color':
                        if len(words) > 2 or (len(words) == 2 and words[1] not in ('on', 'off')):
                            raise ValueError('Usage: color [on|off]')
                        if len(words) == 2:
                            self.no_color = words[1] == 'off'
                        if words == ['color', 'on'] and 'NO_COLOR' in os.environ:
                            print('Color remains disabled because NO_COLOR is set.')
                        elif words == ['color', 'on'] and not enabled(self):
                            print('Color remains disabled because the terminal does not support styling.')
                        else:
                            print('Color: ' + ('on' if enabled(self) else 'off'))
                        continue
                    if words[0] in ('help', '?'):
                        if len(words) == 1:
                            from .help import catalog
                            print(catalog(build_parser(interactive=True), Palette(enabled(self))))
                            self.last_status = 0
                            continue
                        if len(words) == 2 and words[1] in ('color', 'case', 'exit', 'quit', 'help', 'version', '?'):
                            print({
                                'color': 'color [on|off]: Turn terminal colors on or off.',
                                'case': 'case [path|new]: Open or create a case',
                                'exit': 'exit: leave Locard. (alias for quit)',
                                'quit': 'quit: leave Locard. (alias for exit)',
                                'help': 'help [command]: show Locard command help.',
                                'version': 'version: show Locard version.',
                                '?': '? [command]: show Locard command help. (alias for help)'
                            }[words[1]])
                            continue
                        words = words[1:] + ['--help']
                    parser = build_parser(interactive=True)
                    parser.context['palette'] = Palette(enabled(self))
                    try:
                        args = parser.parse_args(['--db', str(self.active), *words])
                    except SystemExit as exc:
                        self.last_status = int(exc.code)
                        continue
                    except (UnknownCommand, InvalidArguments) as exc:
                        print(Palette(enabled(self))('error', str(exc)))
                        self.last_status = 2
                        continue
                    if self.no_color:
                        args.no_color = True
                    # Also rejects argparse global-option abbreviations/equals forms.
                    if args.db != str(self.active) or any(w == '--db' or w.startswith('--db=') for w in words):
                        raise ValueError('Use case to change the active database')
                    executing = True
                    from .sources import prepare
                    if not prepare(self, args):
                        continue
                    self.last_status = dispatch(args, existing_only=True)
                except EOFError:
                    print()
                    return 0
                except KeyboardInterrupt:
                    text = ('Interrupted.' if executing else 'Input cancelled.')
                    print('\n' + Palette(enabled(self))('error', text))
                    self.last_status = 130
                except (ValueError, OSError, sqlite3.Error) as exc:
                    print(Palette(enabled(self))('error', 'Locard: ' + safe(exc)))
                    self.last_status = 2
                finally:
                    # Release cyclic command-local objects; retain only schema metadata.
                    gc.collect()
        finally:
            self.reader.clear()


def run(*, no_color=False):
    try:
        state = State(state_path()).load()
    except (OSError, ValueError) as exc:
        state = State(None)
        state.warning = str(exc)
    return Shell(state, no_color=no_color).run()

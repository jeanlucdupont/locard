"""Synchronous interface over the ordinary Locard parser and dispatcher."""
from forensic_assistant.retrieval.presentation import human_error
import gc
import os
import sqlite3
from forensic_assistant.interactive.case import validate
from forensic_assistant.interactive.console import Reader, safe
from forensic_assistant.interactive.state import State, state_path
from forensic_assistant.cli import get_liner, get_ender, get_thin
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
        self.case_label = None
        self.audit = None
        self.last_status = 0
        self.no_color = no_color

    def prompt(self, label):
        return Palette(enabled(self))('prompt', '[' + label + ']> ')

    def request_advice(self, request):
        from .ai_routing import needs_investigation
        if needs_investigation(request):
            from forensic_assistant.cli import build_parser, dispatch
            from forensic_assistant import activity
            print('More evidence needs to be inspected.\n\n'
                  'Locard may propose additional forensic lookups.\n'
                  'You will be asked to approve each one before it runs.')
            words = ['investigate-ai', '--approve-tools', '--', request]
            args = build_parser(interactive=True).parse_args(['--db', str(self.active), *words])
            args.no_color = self.no_color
            args._argv = words
            args._audit_session = self.audit
            with activity.bind(self.audit):
                self.last_status = dispatch(args, existing_only=True)
            return
        from .advisory import advise, AdvisoryError, response_characters
        from forensic_assistant.terminal_activity import ActivityIndicator
        try:
            from .ai_context import build_ai_case_context
            with ActivityIndicator('Preparing case context...', args=self) as indicator:
                try:
                    context = build_ai_case_context(self.active, self.case_label)
                except (OSError, ValueError, sqlite3.Error):
                    raise AdvisoryError('AI case context unavailable. No action was taken.') from None
                from forensic_assistant.ai.backend import status_callback, waiting_label
                indicator.update(waiting_label())
                with status_callback(indicator.update):
                    response = advise(context, request)
        except KeyboardInterrupt:
            self.audit.record('AI_ADVICE', 'cancelled', request_characters=len(request))
            raise
        except AdvisoryError:
            self.audit.record('AI_ADVICE', 'failure', request_characters=len(request))
            raise
        self.audit.record('AI_ADVICE', request_characters=len(request), response_characters=response_characters(response),
                          basis='Derived advisory text; no evidence supplied; no commands executed')
        print(Palette(enabled(self))('ai_prompt', 'AI assistant — advisory, not evidence'))
        from .advisory_display import render
        print(render(response, context, Palette(enabled(self))))
        self.last_status = 0

    def activate(self, path, *, activity_session=None, announce=True):
        target = validate(path)
        from contextlib import closing
        from .case import open_existing
        with closing(open_existing(target)) as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
        from forensic_assistant import activity
        if self.audit:
            self.audit.end('case switch')
        self.audit = activity_session or activity.Session(target)
        self.audit.start()
        self.active = target
        from .workspace import case_label
        self.case_label = case_label(target)
        self.reader.clear()
        try:
            self.state.remember(target)
        except (OSError, ValueError) as exc:
            print('Recent case not saved: ' + human_error(exc))
        if announce:
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
                print('Cannot select database: ' + human_error(exc))
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
                print('Remembered database unavailable: ' + human_error(exc))
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
                        print('Remembered database unavailable: ' + human_error(exc))
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
            print('\n' + get_thin())
            print("[1] Create a case\n[2] Open a case\n[3] Exit")
            try:
                choice = self.reader.read("Selection or case path: ").strip()
                if choice in ("", "3", "exit", "quit"):
                    return False
                if choice == '1':
                    from .setup import create
                    if create(self):
                        return True
                elif choice == "2":
                    if self.choose():
                        return True
                else:
                    if self.choose(choice):
                        return True
            except (OSError, ValueError, sqlite3.Error) as exc:
                print("Cannot select database: " + human_error(exc))
            except (EOFError, KeyboardInterrupt):
                print()
                return False

    def run(self):
        result = self._run_session()
        if self.audit:
            self.audit.end()
        # Render only after normal return and command cleanup, never on a fatal error.
        print('\nLocard session ended.')
        if self.active is not None:
            print('Case: ' + safe(self.active))
        print(get_ender())
        return result

    def _run_session(self):
        from forensic_assistant.cli import build_parser, dispatch
        from forensic_assistant.cli_parser import UnknownCommand, InvalidArguments
        from forensic_assistant.terminal import Palette, enabled, clear_screen
        if not self.startup():
            return 0
        from forensic_assistant.ai.cli import offer_setup
        offer_setup(self.reader.read)
        try:
            while True:
                try:
                    validate(self.active)
                except KeyboardInterrupt:
                    print('\nValidation interrupted; retrying before accepting commands.')
                    continue
                except (OSError, ValueError, sqlite3.Error) as exc:
                    print('Active case unavailable: ' + human_error(exc))
                    if self.audit:
                        self.audit.record('CASE_UNAVAILABLE', 'failure', message=human_error(exc))
                        self.audit.end('case unavailable')
                        self.audit = None
                    self.active = None
                    self.reader.clear()
                    if not self.menu():
                        return 0
                label = safe(self.case_label or self.active.name)
                if len(label) > 80:
                    label = label[:38] + '...' + label[-39:]
                executing = False
                try:
                    line = self.reader.read(self.prompt(label), remember=True)
                    # Natural-language quotes, backslashes and later ! stay data.
                    stripped = line.lstrip()
                    if stripped.startswith('!'):
                        request = stripped[1:]
                        if request.startswith(' '):
                            request = request[1:]
                        executing = True
                        self.request_advice(request)
                        continue
                    if stripped == 'ask' or stripped.startswith(('ask ', 'ask\t')):
                        print('`ask` is deprecated. Prefix AI requests with ! instead.')
                        executing = True
                        self.request_advice(stripped[3:].lstrip())
                        continue
                    words = split(line)
                    if not words:
                        continue
                    if words[0] == 'expert':
                        if len(words) != 1:
                            raise ValueError(words[0] + ' takes no arguments')
                        print('Locard now uses a single shell mode. No mode change is required.')
                        self.last_status = 0
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
                        self.audit.record('COMMAND', command='version', argv=words)
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
                    if words[0] in ('ingest-wizard', 'add-evidence') or words[:2] == ['ingest', 'wizard']:
                        if len(words) != (2 if words[0] == 'ingest' else 1):
                            raise ValueError('ingest wizard takes no arguments')
                        if words[0] != 'ingest':
                            print('`' + words[0] + '` is deprecated. Use `ingest wizard`.')
                        from .setup import add_evidence
                        self.last_status = 0 if add_evidence(self) else 1
                        continue
                    if words[0] == 'new-case':
                        if len(words) != 1:
                            raise ValueError('new-case takes no arguments')
                        from .setup import create
                        create(self)
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
                        self.audit.record('COMMAND', command='color', argv=words)
                        continue
                    if words[0] in ('help', '?'):
                        from .help import catalog, command_help, SHELL_COMMANDS
                        if len(words) == 1:
                            print(catalog(build_parser(interactive=True), Palette(enabled(self))))
                            self.audit.record('COMMAND', command='help', argv=words)
                            self.last_status = 0
                            continue
                        if words[1:] == ['ingest', 'wizard']:
                            print(command_help('ingest-wizard'))
                            self.audit.record('COMMAND', command='help', argv=words)
                            self.last_status = 0
                            continue
                        if len(words) == 2 and words[1] == 'ask':
                            print('`ask` is deprecated. Prefix AI requests with ! instead. Interactive ask uses the same AI routing.')
                            self.audit.record('COMMAND', command='help', argv=words)
                            self.last_status = 0
                            continue
                        if len(words) == 2 and words[1] in SHELL_COMMANDS:
                            print(command_help(words[1]))
                            self.audit.record('COMMAND', command='help', argv=words)
                            continue
                        words = words[1:] + ['--help']
                    parser = build_parser(interactive=True)
                    parser.context['palette'] = Palette(enabled(self))
                    try:
                        args = parser.parse_args(['--db', str(self.active), *words])
                    except SystemExit as exc:
                        if not exc.code:
                            self.audit.record('COMMAND', command='help', argv=words)
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
                    if args.command == 'ask':
                        # Quoted command names/global flags must not reach legacy CLI retrieval.
                        print('`ask` is deprecated. Prefix AI requests with ! instead.')
                        executing = True
                        self.request_advice(args.question)
                        continue
                    executing = True
                    from .sources import prepare
                    from forensic_assistant import activity
                    args._argv = list(words)
                    args._audit_session = self.audit
                    args._confirm = self.reader.read
                    with activity.bind(self.audit):
                        try:
                            prepared = prepare(self, args)
                        except (EOFError, KeyboardInterrupt):
                            self.audit.record('COMMAND', 'cancelled', command=args.command, argv=activity.redact_argv(words))
                            raise
                        except (ValueError, OSError, sqlite3.Error) as exc:
                            self.audit.record('COMMAND', 'failure', command=args.command,
                                              argv=activity.redact_argv(words), **activity.error_data(exc))
                            raise
                        if not prepared:
                            self.audit.record('COMMAND', 'cancelled', command=args.command, argv=activity.redact_argv(words))
                            if args.command == 'source':
                                self.audit.record('SOURCE_' + args.source_command.upper(), 'cancelled', source_id=args.source_id)
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
                    print(Palette(enabled(self))('error', 'Locard: ' + human_error(exc)))
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

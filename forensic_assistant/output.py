"""Explicit derived output destinations. Never invokes an operating-system shell."""
import argparse
from contextlib import contextmanager, closing
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
from forensic_assistant.retrieval.presentation import safe, safe_path
from forensic_assistant.terminal import Palette, enabled, render_json, wrap_line, message


def configure(commands):
    def add(parser, *, report_generate=False):
        parser.add_argument(
            '--no-color',
            action='store_true',
            default=argparse.SUPPRESS,
            help='Disable terminal styling (also respects NO_COLOR)'
        )
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            '--page',
            action='store_true',
            default=argparse.SUPPRESS,
            help='Review output with the internal pager (Space/Enter/Q)'
        )
        if not report_generate:
            group.add_argument(
                '--output',
                dest='output_file',
                metavar='FILE',
                default=argparse.SUPPRESS,
                help='Replace a derived output file (UTF-8)'
            )
        group.add_argument(
            '--append',
            dest='append_file',
            metavar='FILE',
            default=argparse.SUPPRESS,
            help='Append rendered output to a derived UTF-8 file'
        )
    for name, parser in commands.choices.items():
        add(parser)
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for child_name, child in action.choices.items():
                    add(child, report_generate=name == 'report' and child_name == 'generate')


@contextmanager
def keyboard():
    """Synchronous key input, with terminal mode restored on every exit."""
    if os.name == 'nt':
        from forensic_assistant.interactive.console import WindowsKeys, windows_input
        source = WindowsKeys()
        def read():
            while True:
                key = source.poll()
                if key is not None:
                    return key
                time.sleep(.02)
        with windows_input():
            try:
                yield read
            finally:
                source.flush()
    else:
        import termios
        import tty
        fd = sys.stdin.fileno()
        original = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            yield lambda: os.read(fd, 1).decode('utf-8', errors='replace')
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, original)


def page(stream, palette=None):
    palette = palette if palette is not None else Palette()
    if not sys.stdout.isatty() or not sys.stdin.isatty():
        shutil.copyfileobj(stream, sys.stdout)
        return
    try:
        size = shutil.get_terminal_size(fallback=(80, 24))
        height, width = max(1, size.lines - 2), max(1, size.columns - 1)
    except (OSError, ValueError):
        height, width = 22, 79
    # Account for wrapping, including full evidence IDs and verbose JSON lines.
    def rows():
        for line in stream:
            line = line.rstrip('\n')
            yield from wrap_line(line, width)
    iterator = iter(rows())
    pending = next(iterator, None)
    prompt = '-- More -- Space: page, Enter: line, Q: quit'
    try:
        with keyboard() as read:
            allowance = height
            while pending is not None:
                for _ in range(allowance):
                    print(pending)
                    pending = next(iterator, None)
                    if pending is None:
                        return
                print(palette('info_bar', prompt), end='', flush=True)
                try:
                    while True:
                        key = read()
                        if key in ('q', 'Q', '\x03', '\x04', '\x1a', ''):
                            return
                        if key == ' ':
                            allowance = height
                            break
                        if key in ('\r', '\n'):
                            allowance = 1
                            break
                finally:
                    print('\r' + ' ' * len(prompt) + '\r', end='', flush=True)
    except (KeyboardInterrupt, EOFError):
        pass
    except (OSError, RuntimeError, ValueError) as exc:
        print('Locard: paging stopped: ' + safe(exc), file=sys.stderr)


def same_path(a, b):
    if a.resolve() == b.resolve():
        return True
    return a.exists() and b.exists() and os.path.samefile(a, b)


def validate_destination(target, args):
    """Reject known evidence/case inputs, aliases and SQLite files before writing."""
    if not target.parent.is_dir():
        raise ValueError('Output parent directory does not exist')
    for part in (target, *target.parents):
        if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()):
            raise ValueError('Output paths cannot traverse symbolic links or junctions')
    if target.exists() and not target.is_file():
        raise ValueError('Output destination must be a regular file')
    if os.name == 'nt' and (':' in target.name or target.is_reserved()):
        raise ValueError('Output destination cannot be a device or alternate data stream')
    protected = []
    for name in ('db', 'case'):
        value = getattr(args, name, None)
        if not value or value == ':memory:':
            continue
        case = Path(value).absolute()
        protected += [case, *[Path(str(case) + s) for s in ('-wal', '-shm', '-journal')]]
        if case.is_file():
            # This opener cannot create a case or alter its schema.
            from forensic_assistant.investigation_ai.case import open_readonly
            with closing(open_readonly(case, deadline=time.monotonic() + 10)) as db:
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                for table in ('source_locations', 'ingestion_runs'):
                    if table in tables:
                        for (source,) in db.execute('SELECT source_file FROM ' + table):
                            if same_path(target, Path(source)):
                                raise ValueError('Output destination is recorded source evidence')
    for name in (
        'path',
        'directory',
        'output',
        'transcripts',
        'transcript_root',
        'index',
        'semantic_index',
        'model_path',
        'embedding_model',
        'destination'
    ):
        if name == 'path' and getattr(args, 'command', None) == 'source' and getattr(args, 'source_command', None) == 'assign':
            continue  # Historical selector list, not a current filesystem input.
        value = getattr(args, name, None)
        if value:
            p = Path(value).absolute()
            protected.append(p)
            if p.is_dir() or name in (
                'output',
                'transcripts',
                'transcript_root',
                'index',
                'semantic_index',
                'destination'
            ):
                if target.resolve().is_relative_to(p.resolve()):
                    raise ValueError('Output destination overlaps command input/output directory')
    for p in protected:
        if same_path(target, p):
            raise ValueError('Output destination overlaps case or command input')
    if target.exists():
        with target.open('rb') as f:
            head = f.read(16)
            if head == b'SQLite format 3\x00':
                raise ValueError('Output destination is a SQLite database')
            if head.startswith((b'ElfFile\x00', b'regf', b'FILE', b'MAM')) or head[4:8] == b'SCCA':
                raise ValueError('Output destination has a forensic artifact signature')


class Output:
    def __init__(self, args):
        self.args = args
        self.paged = getattr(args, 'page', False)
        self.append = getattr(args, 'append_file', None)
        output = getattr(args, 'output_file', None)
        if output == '' or self.append == '':
            raise ValueError('Output file path cannot be empty')
        if sum(bool(v) for v in (self.paged, self.append, output)) > 1:
            raise ValueError('--page, --output and --append are mutually exclusive')
        if self.paged and getattr(args, 'json', False):
            raise ValueError('--json cannot be combined with --page')
        self.target = Path(output or self.append).absolute() if output or self.append else None
        self.palette = Palette(enabled(args, file_output=bool(self.target)))
        if self.target:
            validate_destination(self.target, args)
        self.stream = tempfile.SpooledTemporaryFile(
            mode='w+',
            encoding='utf-8',
            newline='\n',
            max_size=1024 * 1024
        ) if self.target or self.paged else None

    def write(self, text):
        print(text, file=self.stream or sys.stdout)

    def json(self, value):
        self.write(render_json(value, self.palette))

    def finish(self):
        if self.stream is None:
            return
        if self.stream.tell() == 0:
            return
        self.stream.seek(0)
        if self.target:
            validate_destination(self.target, self.args)
            if self.append:
                # No truncation. A failure may leave a partial append; report it honestly.
                with self.target.open('a', encoding='utf-8', newline='\n') as out:
                    if out.tell():
                        out.write('\n')
                    shutil.copyfileobj(self.stream, out)
                verb = 'appended to'
            else:
                temporary = None
                try:
                    with tempfile.NamedTemporaryFile(
                        mode='w',
                        encoding='utf-8',
                        newline='\n',
                        dir=self.target.parent,
                        prefix='.locard-output-',
                        delete=False
                    ) as out:
                        temporary = Path(out.name)
                        shutil.copyfileobj(self.stream, out)
                    validate_destination(self.target, self.args)
                    os.replace(temporary, self.target)
                finally:
                    if temporary is not None:
                        temporary.unlink(missing_ok=True)
                verb = 'written to'
            message('Output ' + verb + ': ' + safe_path(self.target), self.args, role='success')
        else:
            page(self.stream, self.palette)

    def close(self):
        if self.stream is not None:
            self.stream.close()

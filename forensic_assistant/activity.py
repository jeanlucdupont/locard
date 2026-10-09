"""Derived analyst activity: locked JSONL appends, never forensic evidence.

The dispatcher owns COMMAND events; sessions own open/start/end; command adapters
own semantic mutations. INTENT is durable before mutation, COMPLETE follows it.
The sidecar and SQLite are not one atomic transaction. An unresolved intent needs
reconciliation against authoritative provenance/output, never an assumed rollback.
"""
from collections import deque
from contextlib import contextmanager, closing
from contextvars import ContextVar
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sqlite3
import sys
import threading
import time
import uuid

MAX_ENTRY = 1024 * 1024
_THREAD_LOCK = threading.RLock()
CURRENT = ContextVar('locard_activity_session', default=None)
COMMAND = ContextVar('locard_activity_command', default=None)
SECRET = re.compile(r'(?:^|[-_])(?:password|passwd|token|secret|credentials|authorization|api[-_]key)$', re.I)


class AuditError(ValueError):
    pass


class Cancelled(ValueError):
    pass


def sidecar(case):
    return Path(str(Path(case).absolute()) + '.audit.jsonl')


def is_sidecar(path):
    return str(path).casefold().endswith('.audit.jsonl')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('utf-8')


def redact_argv(argv):
    result, pending = [], False
    for value in map(str, argv):
        if pending:
            result.append('<redacted>')
            pending = False
            continue
        key, separator, rest = value.partition('=')
        if key.startswith('--') and SECRET.search(key[2:]):
            result.append(key + '=<redacted>' if separator else key)
            pending = not separator
        else:
            result.append(value)
    return result


def clean(value):
    if isinstance(value, dict):
        return {str(k): '<redacted>' if SECRET.search(str(k)) else clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    return value


def error_data(exc):
    # Exception messages can echo command values. Replace known secret values only.
    from .retrieval.presentation import human_error
    message = human_error(exc)
    command = COMMAND.get()
    if command:
        raw, redacted = command.argv, redact_argv(command.argv)
        for original, replacement in zip(raw, redacted):
            if original != replacement:
                secret = original.partition('=')[2] if original.startswith('--') and '=' in original else original
                if secret:
                    message = message.replace(secret, '<redacted>')
    return dict(error_category=type(exc).__name__, message=message[:2048])


def _safe(path):
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction()):
            raise AuditError('Audit path cannot traverse links or junctions')
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AuditError('Audit log must be an unaliased regular file')


@contextmanager
def locked(path, *, write=False):
    """Serialize processes and threads; no persistent database/file handles."""
    path = Path(path)
    _safe(path)
    with _THREAD_LOCK:
        with path.open('a+b' if write else 'rb', buffering=0) as stream:
            info = os.fstat(stream.fileno())
            current = path.stat()
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino) or info.st_nlink != 1:
                raise AuditError('Audit path changed while opening')
            deadline = time.monotonic() + 3
            acquired = False
            try:
                while True:
                    try:
                        stream.seek(0)
                        if os.name == 'nt':
                            import msvcrt
                            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK if write else msvcrt.LK_NBRLCK, 1)
                        else:
                            import fcntl
                            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        acquired = True
                        break
                    except OSError as exc:
                        if time.monotonic() >= deadline:
                            raise AuditError('Audit log is busy; retry the command') from exc
                        time.sleep(.01)
                _safe(path)
                current = path.stat()
                if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                    raise AuditError('Audit path changed while acquiring the lock')
                yield stream
            finally:
                if acquired:
                    stream.seek(0)
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditError('Duplicate JSON key')
        result[key] = value
    return result


def decode(raw):
    try:
        if len(raw) > MAX_ENTRY or not raw.endswith(b'\n'):
            raise AuditError('Oversized or partial audit entry')
        entry = json.loads(raw, object_pairs_hook=_pairs)
        if not isinstance(entry, dict):
            raise AuditError('Audit entry must be an object')
        claimed = entry['entry_hash']
        body = {k: v for k, v in entry.items() if k != 'entry_hash'}
        if claimed != hashlib.sha256(canonical(body)).hexdigest():
            raise AuditError('Entry hash mismatch')
        if entry['audit_version'] != 1 or type(entry['sequence']) is not int or entry['sequence'] < 1:
            raise AuditError('Invalid audit version/sequence')
        for name in ('action', 'outcome', 'session_id', 'timestamp_utc'):
            if not isinstance(entry[name], str) or not entry[name]:
                raise AuditError('Invalid audit core field: ' + name)
        stamp = datetime.fromisoformat(entry['timestamp_utc'])
        if not entry['timestamp_utc'].endswith('Z') or stamp.utcoffset().total_seconds() != 0:
            raise AuditError('Audit timestamp must be UTC')
        previous = entry['previous_entry_hash']
        if previous is not None and (not isinstance(previous, str) or not re.fullmatch('[0-9a-f]{64}', previous)):
            raise AuditError('Invalid previous-entry hash')
        return entry
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError, OverflowError) as exc:
        raise AuditError('Malformed audit entry: ' + str(exc)) from exc


def tail(stream):
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    if not size:
        return None
    chunk = b''
    position = size
    while position:
        count = min(4096, position)
        position -= count
        stream.seek(position)
        chunk = stream.read(count) + chunk
        if not chunk.endswith(b'\n'):
            raise AuditError('Partial trailing audit entry; verification/reconciliation required')
        start = chunk.rfind(b'\n', 0, len(chunk) - 1) + 1
        if start or position == 0:
            break
        if len(chunk) > MAX_ENTRY:
            raise AuditError('Oversized trailing audit entry')
    entry = decode(chunk[start:])
    if (entry['sequence'] == 1) != (entry['previous_entry_hash'] is None):
        raise AuditError('Invalid genesis linkage')
    return entry


def append(log_path, session_id, action, outcome, **fields):
    with locked(log_path, write=True) as stream:
        previous = tail(stream)
        entry = dict(clean(fields), audit_version=1,
                     timestamp_utc=datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                     session_id=session_id, sequence=previous['sequence'] + 1 if previous else 1,
                     action=action, outcome=outcome, previous_entry_hash=previous['entry_hash'] if previous else None)
        entry['entry_hash'] = hashlib.sha256(canonical(entry)).hexdigest()
        raw = canonical(entry) + b'\n'
        if len(raw) > MAX_ENTRY:
            raise AuditError('Audit entry exceeds size limit')
        stream.seek(0, os.SEEK_END)
        original_size = stream.tell()
        try:
            if stream.write(raw) != len(raw):
                raise OSError('Short audit write')
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            # Only this failed append, under the exclusive lock, may be removed.
            stream.truncate(original_size)
            stream.flush()
            raise
        return entry


def inspect(path, limit=20):
    if not 1 <= limit <= 1000:
        raise ValueError('Activity limit must be between 1 and 1000')
    records = deque(maxlen=limit)
    result = dict(valid=True, entries=0, records=[], head_hash=None)
    if not Path(path).exists():
        return {**result, 'exists': False}
    with locked(path) as raw_stream:
        stream = io.BufferedReader(raw_stream)
        try:
            previous = None
            while raw := stream.readline(MAX_ENTRY + 1):
                index = result['entries'] + 1
                try:
                    entry = decode(raw)
                    if entry['sequence'] != index or entry['previous_entry_hash'] != previous:
                        raise AuditError('Sequence or chain linkage mismatch')
                except AuditError as exc:
                    return {**result, 'valid': False, 'first_invalid_entry': index, 'error': str(exc), 'records': list(records)}
                result['entries'] = index
                previous = entry['entry_hash']
                records.append(entry)
            result.update(records=list(records), head_hash=previous, exists=True)
        finally:
            # The lock owner seeks/unlocks/closes the unbuffered handle.
            stream.detach()
    return result


class Session:
    def __init__(self, case):
        self.case = Path(case).absolute()
        self.path = sidecar(self.case)
        self.id = str(uuid.uuid4())
        self.started = False

    def record(self, action, outcome='success', *, required=False, **fields):
        try:
            return append(self.path, self.id, action, outcome, **fields)
        except (OSError, ValueError) as exc:
            message = 'Activity log unavailable: ' + str(exc)
            if required:
                raise AuditError(message) from exc
            from .retrieval.presentation import safe_text
            print('Warning: ' + safe_text(message), file=sys.stderr)
            return None

    def start(self):
        if not self.started:
            from importlib.metadata import version
            self.record('CASE_OPEN', case_path=str(self.case))
            self.record('SESSION_START', case_path=str(self.case), application_version=version('locard-forensics'))
            self.started = True

    def end(self, reason='normal'):
        if self.started:
            self.record('SESSION_END', reason=reason)
            self.started = False


@contextmanager
def bind(session):
    token = CURRENT.set(session)
    try:
        yield
    finally:
        CURRENT.reset(token)


def event(action, outcome='success', *, required=False, **fields):
    session = CURRENT.get()
    if session:
        return session.record(action, outcome, required=required, **fields)


@contextmanager
def mutation(action, **fields):
    """Persist an intent before yielding. Never silently lose a completion."""
    operation_id = str(uuid.uuid4())
    event(action, 'pending', required=True, phase='intent', operation_id=operation_id, **fields)
    result = dict(fields)
    try:
        yield result
    except BaseException as exc:
        event(action, 'cancelled' if isinstance(exc, (KeyboardInterrupt, EOFError, Cancelled)) else 'failure',
              phase='complete', operation_id=operation_id, **result, **error_data(exc))
        raise
    else:
        try:
            event(action, result.pop('_outcome', 'success'), required=True, phase='complete', operation_id=operation_id, **result)
        except AuditError as exc:
            failure = AuditError('Action completed but its audit completion failed; the durable intent remains. '
                                 'Inspect authoritative provenance/output before retrying. ' + str(exc))
            failure.action_completed = True
            raise failure from exc


def note_error(exc):
    command = COMMAND.get()
    if command:
        command.details.update(error_data(exc))


def result_count(result):
    command = COMMAND.get()
    if command and isinstance(result, dict) and type(result.get('total')) is int:
        command.details['result_count'] = result['total']


class Command:
    def __init__(self, args):
        self.args = args
        self.name = ' '.join(str(getattr(args, key)) for key in
                             ('command', 'source_command', 'report_command', 'semantic_command', 'investigation_command')
                             if getattr(args, key, None))
        self.argv = list(getattr(args, '_argv', [self.name]))
        self.details = {}
        self.code = 2
        self.session = getattr(args, '_audit_session', None)
        self.owned = self.session is None
        self.started = False

    def attach(self, path, *, created=False):
        if self.session is None and str(path) != ':memory:':
            self.session = Session(path)
            CURRENT.set(self.session)
            if created:
                self.session.record('CASE_CREATE', case_path=str(self.session.case))
            self.session.start()
            self.begin()

    def begin(self):
        if self.session and not self.started:
            self.started = True
            if self.args.command != 'activity':
                event('COMMAND', 'pending', phase='invoke', command=self.name, argv=redact_argv(self.argv))

    def __enter__(self):
        self.clock = time.monotonic()
        self.session_token = CURRENT.set(self.session)
        self.command_token = COMMAND.set(self)
        try:
            if self.session is None:
                path = getattr(self.args, 'db', None)
                if self.args.command == 'report' and self.args.report_command != 'generate':
                    path = getattr(self.args, 'case', None)
                if self.args.command == 'semantic' and self.args.semantic_command == 'setup':
                    path = None
                if path and Path(path).is_file():
                    from .interactive.case import validate
                    try:
                        validate(path)
                    except (OSError, ValueError, sqlite3.Error):
                        pass  # The ordinary dispatcher reports invalid-case errors.
                    else:
                        self.attach(path)
            self.begin()
        except BaseException:
            COMMAND.reset(self.command_token)
            CURRENT.reset(self.session_token)
            raise
        return self

    def __exit__(self, kind, exc, traceback):
        try:
            outcome = 'cancelled' if isinstance(exc, (KeyboardInterrupt, EOFError, Cancelled)) or self.code == 130 else (
                'failure' if exc is not None or self.code else 'success')
            if exc is not None:
                self.details.update(error_data(exc))
            params = {key: value for key, value in vars(self.args).items()
                      if not key.startswith('_') and value is not None and isinstance(value, (str, int, float, bool, list))}
            event('COMMAND', outcome, phase='complete', command=self.name, argv=redact_argv(self.argv),
                  parameters=clean(params), duration_ms=round((time.monotonic() - self.clock) * 1000, 3), **self.details)
            if self.args.command in ('show', 'around', 'investigate'):
                fields = {name: getattr(self.args, name) for name in ('evidence_id', 'timestamp_slot', 'seconds', 'direction')
                          if getattr(self.args, name, None) is not None}
                event(self.args.command.upper(), outcome, **fields)
            if self.owned and self.session and (exc is None or isinstance(exc, (ValueError, OSError, KeyboardInterrupt, EOFError))):
                self.session.end()
        finally:
            COMMAND.reset(self.command_token)
            CURRENT.reset(self.session_token)


def configure(commands):
    from .command_catalog import COMMANDS
    parser = commands.add_parser('activity', help=COMMANDS['activity'])
    parser.add_argument('--limit', type=int, default=20)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--verify', action='store_true', help='Verify every entry and chain link in the activity sidecar')


def render(result, *, verify=False, palette=None):
    from .terminal import Palette
    from .retrieval.presentation import safe_text
    palette = palette or Palette()
    if not result['valid']:
        return palette('error', 'Audit log verification FAILED.\nFirst invalid entry: '
                       + str(result['first_invalid_entry']) + '\n' + safe_text(result['error']))
    if verify:
        return f"Audit log verified.\nEntries: {result['entries']}\nChain: valid"
    from .retrieval.layout import table
    rows = []
    for entry in result['records']:
        details = entry.get('command') or entry.get('evidence_id') or entry.get('path') or entry.get('case_path') or entry.get('source_id', '')
        if entry.get('changes'):
            details = '; '.join(k + ': ' + str(v['previous_value']) + ' -> ' + str(v['new_value'])
                                for k, v in entry['changes'].items())
        rows.append([entry['timestamp_utc'], entry['action'], entry['outcome'], details])
    if not rows:
        return 'No activity recorded.'
    return '\n'.join(table(['TIME (UTC)', 'ACTION', 'OUTCOME', 'DETAILS'], rows, palette,
                           minimums=[20, 12, 9, 16], maximums=[27, 20, 9, 65],
                           roles=['number_value', 'key', 'secondary_text', 'string_value'], text=safe_text))

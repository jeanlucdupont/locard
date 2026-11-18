"""Bounded interaction records, anchored in the existing activity audit.

This is derived process history, never evidence or investigation authority.
No recording is installed at import time. Embedders explicitly use execution().
"""
from forensic_assistant.terminal import aligned_lines
from contextlib import contextmanager
from contextvars import ContextVar
from collections import deque
from datetime import datetime, timezone
import builtins
import hashlib
import logging
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import threading
import time
import traceback
import uuid

from . import activity
from .investigation_ai.storage import DirectoryGuard, local_path

ACTIVE = ContextVar('session_recorder', default=None)
SUPPRESS = ContextVar('session_capture_suppressed', default=False)
COMPLETING = ContextVar('session_mutation_completion', default=None)
EVENT_BYTES = 16 * 1024
OUTPUT_BYTES = 64 * 1024
SESSION_BYTES = 2 * 1024 * 1024
ROOT_BYTES = 100 * 1024 * 1024
MAX_FILES = 1000
RESERVE = 64 * 1024
# A mutation holds this capacity through its body, including nested mutations.
# Completion needs a bounded check, activity reference and checkpoint, or a
# bounded failure record. The terminal reserve is separate.
MUTATION_BYTES = 128 * 1024
CONTRACT = 'session-record-v2'
SECRET = re.compile(r'password|passwd|secret|credential|authorization|api.?key|access.?token|refresh.?token|^token$', re.I)
ANSI = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))')
ASSIGNMENT = re.compile(r'(?i)((?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|credentials|authorization)["\x27]?\s*[:=]\s*)(?:"[^"\r\n]*"|\x27[^\x27\r\n]*\x27|[^\s,;}]+)')
BEARER = re.compile(r'(?i)\bBearer\s+[^\s,;"\x27]+')


def audit_failure(reason):
    error = activity.AuditError(reason)
    error.reason_code = reason
    return error


def failure_reason(exc):
    if isinstance(exc, PermissionError):
        return 'writer_permission_failure'
    if getattr(exc, 'reason_code', None):
        return exc.reason_code
    if str(exc) in ('Case location identity changed', 'Session file identity changed',
                    'Audit path changed while opening', 'Audit path changed while acquiring the lock'):
        return 'file_identity_mismatch'
    if isinstance(exc, OSError):
        return 'writer_io_failure'
    return 'session_unavailable'


def app_root():
    base = os.environ.get('LOCALAPPDATA')
    if not base or not Path(base).is_absolute():
        raise activity.AuditError('LOCALAPPDATA is required for application audit storage')
    return local_path(Path(base) / 'Locard' / 'logs')


def locations(case=None):
    if case is None:
        root = app_root()
        return root / 'sessions', root / 'application.audit.jsonl'
    case = local_path(case)
    return case.parent / 'logs' / case.name / 'sessions', activity.sidecar(case)


def private_directory(path):
    """Create new directories privately; never change existing permissions."""
    from .investigation_ai.snapshot import _private_mkdir
    path = local_path(path)
    if not path.exists():
        private_directory(path.parent)
        with DirectoryGuard(path.parent):
            try:
                _private_mkdir(path)
            except FileExistsError:
                pass
    if not path.is_dir():
        raise activity.AuditError('Session destination is not a directory')
    return path


class Redactor:
    def __init__(self):
        self.values = set()
        for key, value in os.environ.items():
            if SECRET.search(key) and value:
                self.values.add(value)

    def text(self, value):
        value = ANSI.sub('', str(value))
        for secret in sorted(self.values, key=len, reverse=True):
            value = value.replace(secret, '<redacted>')
        value = re.sub(r'(?im)((?:proxy-)?authorization\s*:\s*)[^\r\n]+', r'\1<redacted>', value)
        value = BEARER.sub('Bearer <redacted>', value)
        value = ASSIGNMENT.sub(lambda m: m[1] + '<redacted>', value)
        return re.sub(r'\bsk-[A-Za-z0-9_-]{8,}', '<redacted>', value)

    def clean(self, value):
        if isinstance(value, dict):
            # Register values first, so a sibling exception/message cannot echo them.
            for key, item in value.items():
                if SECRET.search(str(key)) and isinstance(item, str) and item:
                    self.values.add(item)
            return {str(k): '<redacted>' if SECRET.search(str(k)) else self.clean(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.clean(v) for v in value]
        if isinstance(value, (str, Path)):
            return self.text(value)
        if value is None or type(value) in (int, float, bool):
            return value
        return '<unsupported diagnostic value>'

    def argv(self, argv):
        pending = False
        result = []
        for item in map(str, argv):
            key, sep, val = item.partition('=')
            if pending:
                if item:
                    self.values.add(item)
                result.append('<redacted>')
                pending = False
            elif key.startswith('--') and SECRET.search(key[2:]):
                if sep and val:
                    self.values.add(val)
                result.append(key + '=<redacted>' if sep else key)
                pending = not sep
            else:
                result.append(item)
        return [self.text(x) for x in result]


def sanitized(value):
    recorder = ACTIVE.get()
    return (recorder.redactor if recorder else Redactor()).clean(value)


@contextmanager
def suspended():
    token = SUPPRESS.set(True)
    try:
        yield
    finally:
        SUPPRESS.reset(token)


@contextmanager
def completing(recorder, operation_id):
    """Only the completing thread may spend this mutation's held capacity."""
    token = COMPLETING.set((recorder, operation_id))
    try:
        yield
    finally:
        COMPLETING.reset(token)


class Recorder:
    def __init__(self, warning_stream=None):
        from . import __version__
        self.version = __version__
        self.id = uuid.uuid4().hex
        self.operation_id = None
        self.redactor = Redactor()
        self.warning_stream = warning_stream or sys.stderr
        self.lock = threading.RLock()
        self.path = self.authority = self.case = self.binding = None
        self.segment = self.head = None
        self.file_identity = None
        self.broken = False
        self.output_bytes = self.omitted_bytes = self.size = 0
        self.pending = {'stdout': '', 'stderr': ''}
        self.buffered = {'stdout': '', 'stderr': ''}
        self.events = []
        self.event_bytes = 0
        self.chain_id = None
        self.segment_index = 0
        self.previous_segment = None
        self.reservations = set()
        self.rotating = False
        self.failure_reason = None

    def warning(self):
        # Fixed text: filesystem/provider exceptions can contain secrets.
        self.warning_stream.write('Warning: session audit coverage degraded; required actions are blocked. Review audit diagnostics/storage.\n')
        self.warning_stream.flush()

    def fail(self, exc, required=False):
        first = not self.broken
        self.broken = True
        reason = failure_reason(exc)
        if first:
            self.failure_reason = reason
        if first and self.authority:
            try:
                # Independent authority can still record loss of its supplemental file.
                self.check_binding()
                with DirectoryGuard(self.authority.parent):
                    activity.append(self.authority, self.id, 'SESSION_CAPTURE_FAILURE', 'failure',
                                    recording_id=self.segment, error_category=type(exc).__name__,
                                    reason_code=reason, session_bytes=self.size,
                                    underlying_reason=getattr(exc, 'underlying_reason', None),
                                    underlying_exception=getattr(exc, 'underlying_exception', None),
                                    buffered_estimated_bytes=self.event_bytes,
                                    operation_id=self.operation_id)
            except (OSError, ValueError):
                pass  # Fixed visible warning is the remaining channel.
        if first or required:
            self.warning()
        if required:
            error = activity.AuditError('Required session audit could not be persisted [' +
                                        (self.failure_reason or reason) + ']')
            error.reason_code = self.failure_reason or reason
            raise error from exc

    def allocate_segment(self, root, identity):
        """Serialize quota admission with other writers; scan only on allocation.

        Unclosed/empty segments reserve their entire 2 MiB envelope, so concurrent
        application sessions cannot overcommit the directory's existing quota.
        """
        with DirectoryGuard(root), activity.locked(self.authority, write=True):
            total = count = 0
            for file in root.iterdir():
                activity._safe(file)
                size = file.stat().st_size
                charge = size
                if re.fullmatch(r'[0-9a-f]{32}\.jsonl', file.name):
                    with file.open('rb') as stream:
                        last = activity.tail(stream)
                    if not last or last['action'] != 'session_end':
                        charge = max(size, SESSION_BYTES)
                total += charge
                count += 1
            if count >= MAX_FILES or total + SESSION_BYTES > ROOT_BYTES:
                raise audit_failure('session_directory_quota_exceeded')
            if shutil.disk_usage(root).free < SESSION_BYTES + RESERVE:
                raise audit_failure('insufficient_storage')
            path = root / (identity + '.jsonl')
            with path.open('xb'):
                pass
            return path

    def start_segment(self, path):
        self.path, self.segment = path, path.stem
        self.head = None
        self.size = self.event_bytes = 0
        self.events = []
        info = path.stat()
        self.file_identity = (info.st_dev, info.st_ino)
        self.emit('session_start', dict(application_version=self.version, case_binding=self.binding,
                  limitations=['bounded output; no external editor keystrokes',
                               'parent-visible worker diagnostics only; raw AI debug output excluded']), required=True)
        self.anchor('SESSION_RECORD_START', required=True)

    def rotate(self):
        if self.rotating or self.broken:
            raise audit_failure('segment_rotation_failed')
        self.rotating = True
        try:
            self.flush_events(required=True)
            following = uuid.uuid4().hex
            # Failure here leaves the old segment unsealed and blocks admission.
            path = self.allocate_segment(self.path.parent, following)
            self.emit('session_end', dict(reason='rotation', next_segment=following), required=True)
            self.anchor('SESSION_RECORD_END', required=True)
            self.previous_segment = dict(recording_id=self.segment, sequence=self.head['sequence'],
                                         entry_hash=self.head['entry_hash'], bytes=self.size)
            self.segment_index += 1
            self.start_segment(path)
        except (OSError, ValueError) as exc:
            error = audit_failure('segment_rotation_failed')
            error.underlying_reason = failure_reason(exc)
            error.underlying_exception = type(exc).__name__
            self.fail(error, True)
        except (KeyboardInterrupt, SystemExit):
            self.fail(audit_failure('segment_rotation_interrupted'))
            raise
        finally:
            self.rotating = False

    def reserve_mutation(self, operation_id):
        with self.lock:
            self.require()
            held = (len(self.reservations) + 1) * MUTATION_BYTES
            if held + RESERVE + EVENT_BYTES >= SESSION_BYTES:
                raise audit_failure('session_capacity_exhausted')
            if self.size + self.event_bytes + held + RESERVE + EVENT_BYTES > SESSION_BYTES:
                self.rotate()
            self.reservations.add(operation_id)

    def release_mutation(self, operation_id):
        with self.lock:
            self.reservations.discard(operation_id)

    def check_binding(self):
        if self.case:
            local_path(self.case)
            info = self.case.stat()
            if (info.st_dev, info.st_ino) != (self.binding['device'], self.binding['inode']):
                raise activity.AuditError('Case location identity changed')

    def open(self, case=None):
        with self.lock:
            if self.segment and self.case == (Path(case).absolute() if case else None):
                self.check_binding()
                return
            if self.reservations:
                raise audit_failure('case_transition_during_mutation')
            self.close('case transition')
            self.path = self.segment = self.head = self.authority = None
            self.case = Path(case).absolute() if case else None
            self.binding = None
            self.broken = False
            self.output_bytes = self.omitted_bytes = self.size = 0
            self.events = []
            self.event_bytes = 0
            self.chain_id = uuid.uuid4().hex
            self.segment_index = 0
            self.previous_segment = None
            self.failure_reason = None
            try:
                if self.case:
                    from .case_management import validate_identity
                    from .interactive.case import validate
                    validate_identity(validate(self.case))
                    info = self.case.stat()
                    self.binding = dict(path=str(self.case), device=info.st_dev, inode=info.st_ino)
                root, authority = locations(self.case)
                private_directory(root)
                # One historical scan on attachment; appends only inspect the tail.
                if not activity.inspect(authority, limit=1)['valid']:
                    raise activity.AuditError('Existing activity chain is corrupt')
                if self.case and authority.exists():
                    with activity.locked(authority) as stream:
                        while raw := stream.readline(activity.MAX_ENTRY + 1):
                            previous = activity.decode(raw)
                            bound = previous.get('case_binding')
                            if bound is not None and bound != self.binding:
                                raise activity.AuditError('Recorded case location identity mismatch; no history attachment')
                self.authority = authority
                self.start_segment(self.allocate_segment(root, uuid.uuid4().hex))
            except (OSError, ValueError, sqlite3.Error) as exc:
                self.fail(exc)

    def emit(self, kind, data=None, *, required=False, outcome='success'):
        with self.lock:
            if self.broken or self.path is None:
                if required:
                    self.fail(activity.AuditError('No usable session recording'), True)
                return None
            try:
                self.check_binding()
                info = self.path.stat()
                if (info.st_dev, info.st_ino) != self.file_identity:
                    raise activity.AuditError('Session file identity changed')
                data = self.redactor.clean(data or {})
                raw = activity.canonical(data)
                if len(raw) > EVENT_BYTES // 2:
                    # Do not cut JSON or silently lose a structural value.
                    data = dict(capture_gap='event_payload_limit', omitted_serialized_bytes=len(raw))
                fields = dict(contract=CONTRACT, chain_id=self.chain_id, segment_index=self.segment_index,
                              previous_segment=self.previous_segment, event_id=uuid.uuid4().hex,
                              observed_utc=datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                              application_session_id=self.id, operation_id=self.operation_id, data=data)
                terminal = kind == 'session_end'
                completing_id = COMPLETING.get()
                spending = (completing_id is not None and completing_id[0] is self
                            and completing_id[1] in self.reservations)
                held = len(self.reservations) - int(spending)
                ceiling = SESSION_BYTES if terminal else SESSION_BYTES - RESERVE - held * MUTATION_BYTES
                estimate = len(activity.canonical(fields)) + 1024
                if self.size + self.event_bytes + estimate > ceiling:
                    if self.size > SESSION_BYTES or self.rotating or terminal:
                        raise audit_failure('session_capacity_exhausted')
                    self.rotate()
                    # Rebuild the event with the new immutable segment binding.
                    return self.emit(kind, data, required=required, outcome=outcome)
                self.events.append((kind, outcome, fields))
                self.event_bytes += estimate
                if required or self.event_bytes >= EVENT_BYTES or len(self.events) >= 100:
                    self.flush_events(required=required)
                return self.head if required else None
            except (OSError, ValueError) as exc:
                self.fail(exc, required)
                return None

    def flush_events(self, *, required=False):
        if not self.events or self.broken:
            if required and self.broken:
                self.fail(activity.AuditError('Session buffer unavailable'), True)
            return
        try:
            self.check_binding()
            info = self.path.stat()
            if (info.st_dev, info.st_ino) != self.file_identity:
                raise activity.AuditError('Session file identity changed')
            with DirectoryGuard(self.path.parent):
                rows = activity.append_batch(self.path, self.segment, self.events)
            self.head = rows[-1]
            self.size += sum(len(activity.canonical(row)) + 1 for row in rows)
            self.events = []
            self.event_bytes = 0
        except (OSError, ValueError) as exc:
            self.fail(exc, required)

    def anchor(self, action='SESSION_RECORD_CHECKPOINT', *, required=False):
        self.flush_events(required=required)
        if self.broken or self.head is None:
            if required:
                self.fail(activity.AuditError('Session checkpoint unavailable'), True)
            return
        try:
            self.check_binding()
            with DirectoryGuard(self.authority.parent):
                activity.append(self.authority, self.id, action, 'success',
                                recording_contract=CONTRACT, recording_id=self.segment,
                                chain_id=self.chain_id, segment_index=self.segment_index,
                                previous_segment=self.previous_segment,
                                next_segment=self.head.get('data', {}).get('next_segment'),
                                recording_sequence=self.head['sequence'], recording_hash=self.head['entry_hash'],
                                recording_bytes=self.size, case_binding=self.binding,
                                application_version=self.version, operation_id=self.operation_id)
        except (OSError, ValueError) as exc:
            self.fail(exc, required)

    def require(self):
        self.flush()
        self.emit('required_audit_check', required=True)
        self.anchor(required=True)

    def output(self, text, channel='stdout'):
        with self.lock:
            if SUPPRESS.get() or not text:
                return
            # Strip complete styling before bounding: no cut SGR and no color-byte charge.
            encoded = ANSI.sub('', str(text)).encode('utf-8', errors='replace')
            available = max(0, OUTPUT_BYTES - self.output_bytes)
            kept = encoded[:available].decode('utf-8', errors='ignore')
            used = len(kept.encode('utf-8'))
            self.output_bytes += used
            self.omitted_bytes += len(encoded) - used
            # Small chunks bound serialization even for multi-million-row outputs.
            overlap = max((len(s.encode('utf-8')) for s in self.redactor.values), default=0)
            preview = encoded[:available + overlap].decode('utf-8', errors='ignore')
            for secret in self.redactor.values:
                start = preview.find(secret, max(0, len(kept)-len(secret)))
                if start >= 0 and start < len(kept) < start + len(secret):
                    kept = kept[:start] + '<redacted>'
                    break
            kept = self.redactor.text(kept)
            for start in range(0, len(kept), 1000):
                self.emit('output', dict(channel=channel, text=kept[start:start + 1000]))

    def stream(self, text, channel):
        if SUPPRESS.get():
            return
        with self.lock:
            # Coalesce print's text/newline writes; do not persist half credentials.
            value = self.pending[channel] + text
            if len(value) > 8192 and '\n' not in value:
                self.pending[channel] = ''
                self.omitted_bytes += len(value.encode('utf-8', errors='replace'))
                self.emit('capture_gap', dict(reason='unframed_stream_limit', channel=channel))
                return
            end = max(value.rfind('\n'), value.rfind('\r')) + 1
            self.pending[channel] = value[end:]
            complete = self.buffered[channel] + value[:end]
            if len(complete.encode('utf-8', errors='replace')) >= 4096:
                self.buffered[channel] = ''
                self.output(complete, channel)
            else:
                self.buffered[channel] = complete

    def flush(self):
        with self.lock:
            for channel, text in self.pending.items():
                self.pending[channel] = ''
                complete = self.buffered[channel] + text
                self.buffered[channel] = ''
                self.output(complete, channel)
            if self.omitted_bytes:
                self.emit('capture_gap', dict(reason='output_limit', omitted_utf8_bytes=self.omitted_bytes))
                self.omitted_bytes = 0
            self.flush_events()

    def close(self, reason='normal'):
        with self.lock:
            if not self.segment:
                return
            self.flush()
            self.emit('session_end', dict(reason=reason))
            self.anchor('SESSION_RECORD_END')
            self.segment = None
            self.path = None


def record(kind, data=None, *, required=False, outcome='success'):
    recorder = ACTIVE.get()
    if recorder and not SUPPRESS.get():
        return recorder.emit(kind, data, required=required, outcome=outcome)


def require():
    recorder = ACTIVE.get()
    if recorder:
        recorder.require()


def output(text, channel='stdout'):
    recorder = ACTIVE.get()
    if recorder:
        recorder.output(text, channel)


def read_response(read, prompt, *, command=False, presentation=None, **kwargs):
    recorder = ACTIVE.get()
    if not command and not SUPPRESS.get():
        from .terminal import question_prompt
        prompt = question_prompt(prompt, presentation)
    if recorder is None or SUPPRESS.get():
        return read(prompt, **kwargs)
    recorder.flush()
    if command:
        recorder.operation_id = uuid.uuid4().hex
        recorder.output_bytes = 0
    recorder.emit('prompt', dict(text=prompt))
    try:
        with suspended():  # Editor redraw and builtins.input echo are not submitted input.
            value = read(prompt, **kwargs)
    except (KeyboardInterrupt, EOFError):
        recorder.emit('input_cancelled', outcome='cancelled')
        recorder.anchor()
        raise
    if SECRET.search(prompt):
        if value:
            recorder.redactor.values.add(value)
        captured = '<redacted>'
    elif command:
        from .interactive.shell import split
        try:
            captured = recorder.redactor.argv(split(value))
        except ValueError:
            captured = '<unparseable command omitted>'
    else:
        captured = recorder.redactor.text(value)
    required = not command and value.strip().casefold() not in ('n', 'no', 'cancel')
    recorder.emit('input', dict(provenance='shell_command' if command else 'interactive_response',
                               value=captured, empty_response=not bool(value),
                               default_resolution='application-owned' if not value else None), required=required)
    recorder.anchor(required=required)
    return value


class ReaderProxy:
    def __init__(self, reader, presentation=None):
        self.reader = reader
        self.presentation = presentation

    def __getattr__(self, name):
        return getattr(self.reader, name)

    def read(self, prompt, **kwargs):
        return read_response(self.reader.read, prompt, command=kwargs.get('remember', False), presentation=self.presentation, **kwargs)


class Stream:
    def __init__(self, original, recorder, channel):
        self.original, self.recorder, self.channel = original, recorder, channel

    def __getattr__(self, name):
        return getattr(self.original, name)

    def write(self, text):
        self.recorder.stream(text, self.channel)
        return self.original.write(text)

    def flush(self):
        self.original.flush()


class DiagnosticHandler(logging.Handler):
    def __init__(self, recorder):
        super().__init__(logging.DEBUG if os.environ.get('LOCARD_AUDIT_LEVEL') == 'DEBUG' else logging.INFO)
        self.recorder = recorder

    def emit(self, entry):
        if not entry.name.startswith('forensic_assistant'):
            return
        data = dict(component=entry.name, severity=entry.levelname, message=entry.getMessage())
        if isinstance(entry.args, dict):
            self.recorder.redactor.clean(entry.args)
        if entry.exc_info:
            data['exception_class'] = entry.exc_info[0].__name__
            data['frames'] = [dict(file=f.filename, line=f.lineno, function=f.name)
                              for f in traceback.extract_tb(entry.exc_info[2])[-20:]]
        self.recorder.emit('diagnostic', data)


@contextmanager
def execution(argv):
    """One app execution; logical hooks plus scoped legacy stream capture."""
    if ACTIVE.get():
        yield ACTIVE.get()
        return
    recorder = Recorder()
    token = ACTIVE.set(recorder)
    oldout, olderr, oldinput = sys.stdout, sys.stderr, builtins.input
    handler = DiagnosticHandler(recorder)
    logger = logging.getLogger('forensic_assistant')
    oldlevel = logger.level
    reason = 'normal'
    try:
        recorder.redactor.argv(argv)
        recorder.open()
        recorder.emit('application_start', dict(argument_count=len(argv)))
        sys.stdout, sys.stderr = Stream(oldout, recorder, 'stdout'), Stream(olderr, recorder, 'stderr')
        from types import SimpleNamespace
        presentation = SimpleNamespace(no_color='--no-color' in argv, json='--json' in argv)
        builtins.input = lambda prompt='': read_response(oldinput, prompt, presentation=presentation)
        logger.addHandler(handler)
        logger.setLevel(handler.level)
        yield recorder
    except BaseException as exc:
        if isinstance(exc, SystemExit) and exc.code in (0, None):
            recorder.emit('application_result', dict(exit_code=0))
        else:
            reason = 'cancelled' if isinstance(exc, (KeyboardInterrupt, EOFError)) else 'abnormal'
            recorder.emit('exception', dict(exception_class=type(exc).__name__, message=str(exc),
                          frames=[dict(file=f.filename, line=f.lineno, function=f.name)
                                  for f in traceback.extract_tb(exc.__traceback__)[-20:]]), outcome=reason)
        raise
    finally:
        sys.stdout, sys.stderr, builtins.input = oldout, olderr, oldinput
        logger.removeHandler(handler)
        logger.setLevel(oldlevel)
        recorder.close(reason)
        ACTIVE.reset(token)


@contextmanager
def operation(args):
    recorder = ACTIVE.get()
    if not recorder:
        yield
        return
    name = getattr(args, 'workflow', None) or args.command
    review = name.startswith('audit-') or args.command == 'activity'
    detached = args.command == 'ai-history' or name in ('findings', 'reason', 'version') or name.startswith('case-') or (
        args.command == 'report' and getattr(args, 'report_command', None) in ('recorded', 'inspect-recorded'))
    if not review:
        target = getattr(args, 'db', None)
        if detached:
            recorder.open()
        elif target and Path(target).is_file():
            recorder.open(target)
    previous = recorder.operation_id
    recorder.operation_id = previous or uuid.uuid4().hex
    recorder.flush()
    recorder.output_bytes = 0
    argv = recorder.redactor.argv(getattr(args, '_argv', [name]))
    raw_debug = args.command == 'ai' and bool(getattr(args, 'raw', False))
    readonly = review or name in ('version', 'status', 'search', 'show', 'around', 'timeline', 'logons', 'session', 'process-tree', 'detections', 'investigate')
    recorder.emit('operation_start', dict(name=name, argv=argv, provenance='scripted_argument'), required=not readonly)
    recorder.anchor(required=not readonly)
    if recorder.broken and readonly:
        recorder.warning()
    start = time.monotonic()
    outcome = 'returned'
    try:
        if review or raw_debug:
            recorder.emit('capture_gap', dict(reason='audit_review_not_recursively_recorded' if review else 'raw_ai_debug_excluded'))
            with suspended():
                yield
        else:
            yield
    except BaseException as exc:
        outcome = 'cancelled' if isinstance(exc, (KeyboardInterrupt, EOFError)) else 'failure'
        recorder.emit('diagnostic', dict(severity='ERROR', component='dispatcher', exception_class=type(exc).__name__, message=str(exc)))
        raise
    finally:
        recorder.flush()
        recorder.emit('operation_end', dict(name=name, duration_ms=round((time.monotonic() - start) * 1000, 3)), outcome=outcome)
        recorder.anchor()
        recorder.operation_id = previous


def imported(path, raw, *, external_editor=False):
    record('document_import', dict(provenance='imported_document', path=str(path), bytes=len(raw),
                                  sha256=hashlib.sha256(raw).hexdigest(),
                                  external_editor_keystrokes_captured=False if external_editor else None))


def verify(case=None):
    """Verify both layers without opening evidence or trusting unanchored filenames."""
    root, authority = locations(case)
    audit = activity.inspect(authority, limit=1)
    anchors = {}
    promised = set()
    anchor_issues = set()
    if audit['valid'] and audit.get('exists'):
        authority_head = None
        authority_count = 0
        with activity.locked(authority) as stream:
            while raw := stream.readline(activity.MAX_ENTRY + 1):
                entry = activity.decode(raw)
                authority_count += 1
                if entry['sequence'] != authority_count or entry['previous_entry_hash'] != authority_head:
                    raise activity.AuditError('Activity changed during session verification; retry')
                authority_head = entry['entry_hash']
                if entry.get('recording_contract') in ('session-record-v1', CONTRACT):
                    key = entry.get('recording_id', '')
                    if not re.fullmatch('[0-9a-f]{32}', key):
                        raise activity.AuditError('Invalid recording identity')
                    if key not in anchors and len(anchors) >= MAX_FILES:
                        raise activity.AuditError('Session verification limit exceeded')
                    if entry.get('recording_contract') == CONTRACT:
                        earlier = anchors.get(key, [None])[-1]
                        if earlier and (earlier['action'] == 'SESSION_RECORD_END' or any(
                                earlier.get(k) != entry.get(k) for k in
                                ('recording_contract', 'chain_id', 'segment_index', 'previous_segment', 'session_id'))):
                            anchor_issues.add(key)
                        following = entry.get('next_segment')
                        if following is not None:
                            if not re.fullmatch('[0-9a-f]{32}', str(following)):
                                raise activity.AuditError('Invalid linked recording identity')
                            promised.add(following)
                    anchors[key] = [entry]  # Latest trusted prefix commits all earlier links.
        if authority_head != audit['head_hash'] or authority_count != audit['entries']:
            raise activity.AuditError('Activity changed during session verification; retry')
    rows = []
    names = set(anchors) | promised
    for refs in anchors.values():
        following = refs[-1].get('next_segment')
        if following is not None:
            if not re.fullmatch('[0-9a-f]{32}', str(following)):
                raise activity.AuditError('Invalid linked recording identity')
            names.add(following)
    if root.exists():
        local_path(root)
        for index, file in enumerate(root.iterdir()):
            if index >= MAX_FILES:
                raise activity.AuditError('Session verification limit exceeded')
            if re.fullmatch(r'[0-9a-f]{32}\.jsonl', file.name):
                names.add(file.stem)
    for identity in sorted(names):
        path = root / (identity + '.jsonl')
        refs = anchors.get(identity, [])
        row = dict(session_id=identity, integrity='unverifiable', completion='unknown', start=None, end=None,
                   application_version=None, limitations=[], records=0)
        try:
            if not path.exists():
                row['integrity'] = 'missing'
            else:
                activity._safe(path)
                if path.stat().st_size > SESSION_BYTES:
                    raise activity.AuditError('Session file exceeds size limit')
                checked = activity.inspect(path, limit=1)
                if not checked['valid']:
                    row['integrity'] = 'corrupt'
                else:
                    entries = {}
                    prefix_bytes = {}
                    consumed = 0
                    binding = None
                    segment_binding = None
                    sealed = False
                    previous_hash = None
                    with activity.locked(path) as stream:
                        while raw := stream.readline(activity.MAX_ENTRY + 1):
                            e = activity.decode(raw)
                            if e['sequence'] != len(entries) + 1 or e['previous_entry_hash'] != previous_hash:
                                raise activity.AuditError('Session event ordering mismatch')
                            previous_hash = e['entry_hash']
                            consumed += len(raw)
                            prefix_bytes[e['sequence']] = consumed
                            entries[e['sequence']] = e
                            if e['session_id'] != identity or e.get('contract') not in ('session-record-v1', CONTRACT):
                                raise activity.AuditError('Session identity or contract mismatch')
                            if e.get('contract') == CONTRACT:
                                if sealed or ((e['sequence'] == 1) != (e['action'] == 'session_start')):
                                    raise activity.AuditError('Invalid segment lifecycle')
                                sealed = e['action'] == 'session_end'
                            metadata = {k: e.get(k) for k in ('contract', 'application_session_id', 'chain_id', 'segment_index', 'previous_segment')}
                            if segment_binding is None:
                                segment_binding = metadata
                            elif metadata != segment_binding:
                                raise activity.AuditError('Session segment binding changed')
                            if e['action'] == 'session_start':
                                binding = e['data'].get('case_binding')
                                row.update(start=e['timestamp_utc'], application_version=e['data'].get('application_version'))
                                row['limitations'].extend(e['data'].get('limitations', []))
                            if e['action'] == 'capture_gap':
                                row['limitations'].append(e['data'])
                    row['records'] = len(entries)
                    if previous_hash != checked['head_hash'] or len(entries) != checked['entries']:
                        raise audit_failure('verification_changed_retry')
                    row.update(segment_binding or {})
                    row['case_binding'] = binding
                    row['recording_bytes'] = consumed
                    row['next_segment'] = entries.get(len(entries), {}).get('data', {}).get('next_segment')
                    row['anchor_sequence'] = refs[-1]['sequence'] if refs else None

                    row['head_hash'] = checked['head_hash']
                    row['anchored_through'] = refs[-1]['recording_sequence'] if refs else 0
                    if refs:
                        for ref in refs:
                            if row.get('contract') == CONTRACT:
                                if ref.get('recording_contract') != CONTRACT or any(
                                        ref.get(k) != row.get(k) for k in ('chain_id', 'segment_index', 'previous_segment')):
                                    raise activity.AuditError('Anchor segment binding mismatch')
                                if ref['session_id'] != row.get('application_session_id'):
                                    raise activity.AuditError('Logical session identity mismatch')
                                if (ref['recording_sequence'] == len(entries) and
                                        ref.get('next_segment') != row.get('next_segment')):
                                    raise activity.AuditError('Anchor successor mismatch')
                            e = entries.get(ref['recording_sequence'])
                            if not e or e['entry_hash'] != ref['recording_hash']:
                                raise activity.AuditError('Anchored session prefix is missing or changed')
                            if prefix_bytes[e['sequence']] != ref['recording_bytes'] or binding != ref.get('case_binding'):
                                raise activity.AuditError('Session byte or case commitment mismatch')
                        last = entries.get(len(entries), {})
                        complete = refs[-1]['action'] == 'SESSION_RECORD_END' and refs[-1]['recording_sequence'] == len(entries) and last.get('action') == 'session_end'
                        row.update(integrity='verified' if complete else 'incomplete',
                                   completion=last.get('data', {}).get('reason', 'incomplete') if complete else 'incomplete',
                                   end=last.get('timestamp_utc') if complete else None)
        except (OSError, ValueError) as exc:
            if getattr(exc, 'reason_code', None) == 'verification_changed_retry':
                raise activity.AuditError('Session changed during verification; retry') from exc
            row['integrity'] = 'corrupt'
        if identity in anchor_issues:
            row['integrity'] = 'corrupt'
            row['limitations'].append('Activity anchors changed segment binding or followed its seal')
        rows.append(row)
    validate_segment_links(rows)
    if audit['valid'] and audit.get('exists'):
        with activity.locked(authority) as stream:
            last = activity.tail(stream)
        if (last['entry_hash'] if last else None) != audit['head_hash']:
            raise activity.AuditError('Activity changed during session verification; retry')
    rows.sort(key=lambda r: (r['start'] or '', r['session_id']))
    return dict(kind='session_audit', valid=audit['valid'] and all(r['integrity'] in ('verified', 'incomplete') for r in rows),
                activity=audit, sessions=rows)


def validate_segment_links(rows):
    """Check reciprocal, anchored links; a valid per-file hash is not enough."""
    by_id = {r['session_id']: r for r in rows}
    chains = {}
    for row in rows:
        if row.get('contract') != CONTRACT:
            continue
        chain = row.get('chain_id')
        if not isinstance(chain, str) or not re.fullmatch('[0-9a-f]{32}', chain):
            row['integrity'] = 'corrupt'
            continue
        chains.setdefault(chain, []).append(row)
    for chain in chains.values():
        good = True
        seen = set()
        for row in chain:
            index = row.get('segment_index')
            if type(index) is not int or index < 0 or index in seen:
                good = False
                continue
            seen.add(index)
            previous = row.get('previous_segment')
            if index == 0:
                if previous is not None:
                    good = False
            else:
                if (not isinstance(previous, dict) or not isinstance(previous.get('recording_id'), str)):
                    good = False
                    continue
                earlier = by_id.get(previous.get('recording_id'))
                if not earlier or previous != dict(recording_id=earlier['session_id'],
                        sequence=earlier['records'], entry_hash=earlier.get('head_hash'),
                        bytes=earlier.get('recording_bytes')):
                    good = False
                    continue
                if (earlier.get('next_segment') != row['session_id'] or
                        earlier.get('segment_index') != index - 1 or
                        any(earlier.get(k) != row.get(k) for k in ('chain_id', 'application_session_id', 'case_binding')) or
                        earlier.get('completion') != 'rotation' or
                        not earlier.get('anchor_sequence') or not row.get('anchor_sequence') or
                        earlier['anchor_sequence'] >= row['anchor_sequence']):
                    good = False
            following = row.get('next_segment')
            if row.get('completion') == 'rotation' and following is None:
                good = False
            if following is not None:
                if not isinstance(following, str):
                    good = False
                    continue
                later = by_id.get(following)
                if (not later or later.get('contract') != CONTRACT or
                        not isinstance(later.get('previous_segment'), dict) or
                        later['previous_segment'].get('recording_id') != row['session_id']):
                    good = False
            if row['integrity'] not in ('verified', 'incomplete'):
                good = False
        if not good:
            for row in chain:
                row['linked_integrity'] = 'invalid'
                if row['integrity'] in ('verified', 'incomplete'):
                    row['integrity'] = 'corrupt'
                row['limitations'].append('Linked segment sequence is missing, inconsistent or unverified')
        else:
            complete = all(r['integrity'] == 'verified' for r in chain)
            for row in chain:
                row['linked_integrity'] = 'verified' if complete else 'incomplete'


def review(case=None, *, selector='latest', limit=100, diagnostics=False, severity=None, operation_id=None, since=None):
    if not 1 <= limit <= 1000:
        raise ValueError('Session review limit must be between 1 and 1000')
    result = verify(case)
    candidates = result['sessions']
    current = ACTIVE.get()
    if case is None and selector == 'latest' and current:
        candidates = [r for r in candidates if r['session_id'] != current.segment] or candidates
    row = candidates[-1] if selector == 'latest' and candidates else next((r for r in candidates if r['session_id'] == selector), None)
    if row is None:
        raise ValueError('No matching session recorded')
    if row['integrity'] not in ('verified', 'incomplete'):
        raise ValueError('Session is not eligible for trusted review: ' + row['integrity'])
    if since:
        from datetime import datetime
        stamp = datetime.fromisoformat(since)
        if stamp.tzinfo is None:
            raise ValueError('--since requires an ISO 8601 timezone')
    records = deque(maxlen=limit)
    total = 0
    previous = None
    sequence = 0
    with activity.locked(locations(case)[0] / (row['session_id'] + '.jsonl')) as stream:
        while raw := stream.readline(activity.MAX_ENTRY + 1):
            entry = activity.decode(raw)
            sequence += 1
            if entry['sequence'] != sequence or entry['previous_entry_hash'] != previous:
                raise activity.AuditError('Session changed during review')
            previous = entry['entry_hash']
            if diagnostics and entry['action'] not in ('diagnostic', 'exception', 'capture_gap'):
                continue
            if severity and entry.get('data', {}).get('severity') != severity:
                continue
            if operation_id and entry.get('operation_id') != operation_id:
                continue
            if since and datetime.fromisoformat(entry['timestamp_utc']) < stamp:
                continue
            total += 1
            records.append(entry)
    if previous != row.get('head_hash') or sequence != row['records']:
        raise activity.AuditError('Session changed during review; retry')
    return dict(kind='session_review', session=row, records=list(records), omitted_records=max(0, total - limit),
                unanchored_records=max(0, sequence-row.get('anchored_through', 0)))


def integrity_summary(value, palette=None):
    """Human projection only; verified JSON and persisted classifications are unchanged."""
    from .terminal import Palette, field
    palette = palette or Palette()
    audit = value['activity']
    status = 'Verified' if audit.get('exists') and audit['valid'] else 'Missing' if audit['valid'] else 'Corrupt'
    rows = value['sessions']
    verified = sum(r['integrity'] == 'verified' for r in rows)
    failures = sum(r['integrity'] in ('corrupt', 'missing', 'unverifiable') for r in rows)
    incomplete = sum(r['integrity'] == 'incomplete' for r in rows)
    current = ACTIVE.get()
    # Only identify this process's live recorder with the exact validated head.
    active = sum(r['integrity'] == 'incomplete' and current is not None and
                 not current.broken and isinstance(current.head, dict) and r['session_id'] == current.segment and
                 r.get('head_hash') == current.head.get('entry_hash') for r in rows)
    lines = [palette('heading', 'AUDIT INTEGRITY'), '',
             field('Activity chain', status, palette, role={'Verified':'success','Missing':'unknown','Corrupt':'error'}[status]),
             field('Completed sessions', verified, palette), field('Verified sessions', verified, palette),
             field('Active sessions (this process)', active, palette),
             field('Incomplete sessions (state unknown)', incomplete-active, palette, role='unknown' if incomplete-active else 'value'),
             field('Integrity failures', failures + int(not audit['valid']), palette, role='error' if failures or not audit['valid'] else 'value')]
    if failures or not audit['valid']:
        lines.append(palette('error', 'Integrity verification failed; inspect audit verify --json for affected records.'))
    if current is not None and current.broken:
        lines.append(palette('error', 'Current session recording failed; integrity of subsequent capture is not established.'))
    if incomplete-active:
        lines.append(palette('forensic_note', 'An incomplete recording may be active elsewhere or interrupted; its state is not established.'))
    return aligned_lines(lines)


def render(value, palette=None):
    from .terminal import Palette, field
    palette = palette or Palette()
    from .retrieval.presentation import safe_text
    if value['kind'] == 'session_review':
        lines = ['Session ' + value['session']['session_id'] + ' — ' + value['session']['integrity']]
        for e in value['records']:
            lines.append(f"{e['sequence']} {e['timestamp_utc']} {e['action']}: " + safe_text(e.get('data', {})))
        lines.append('Earlier matching records omitted: ' + str(value['omitted_records']))
        lines.append('Records beyond the latest authority checkpoint: ' + str(value['unanchored_records']))
        return aligned_lines(lines)
    audit = value['activity']
    status = 'verified' if audit.get('exists') and audit['valid'] else 'missing' if audit['valid'] else 'corrupt'
    lines = [field('Activity chain',status,palette,role={'verified':'success','missing':'unknown','corrupt':'error'}[status])]
    for row in value['sessions']:
        lines.append(f"{row['session_id']}  {row['start']}  {row['integrity']}  {row['completion']}  Locard {row['application_version']}")
        lines.append(palette('forensic_note', '  Capture limitations: ' + safe_text(row['limitations'])))
    if not value['sessions']:
        lines.append('No linked session recordings (historical activity remains independently verifiable).')
    return aligned_lines(lines)

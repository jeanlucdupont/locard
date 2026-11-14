"""Bounded interaction records, anchored in the existing activity audit.

This is derived process history, never evidence or investigation authority.
No recording is installed at import time. Embedders explicitly use execution().
"""
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
EVENT_BYTES = 16 * 1024
OUTPUT_BYTES = 64 * 1024
SESSION_BYTES = 2 * 1024 * 1024
ROOT_BYTES = 100 * 1024 * 1024
MAX_FILES = 1000
RESERVE = 64 * 1024
SECRET = re.compile(r'password|passwd|secret|credential|authorization|api.?key|access.?token|refresh.?token|^token$', re.I)
ANSI = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))')
ASSIGNMENT = re.compile(r'(?i)((?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|credentials|authorization)["\x27]?\s*[:=]\s*)(?:"[^"\r\n]*"|\x27[^\x27\r\n]*\x27|[^\s,;}]+)')
BEARER = re.compile(r'(?i)\bBearer\s+[^\s,;"\x27]+')


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

    def warning(self):
        # Fixed text: filesystem/provider exceptions can contain secrets.
        self.warning_stream.write('Warning: session audit coverage degraded; required actions are blocked. Review audit diagnostics/storage.\n')
        self.warning_stream.flush()

    def fail(self, exc, required=False):
        first = not self.broken
        self.broken = True
        if first and self.authority:
            try:
                # Independent authority can still record loss of its supplemental file.
                self.check_binding()
                with DirectoryGuard(self.authority.parent):
                    activity.append(self.authority, self.id, 'SESSION_CAPTURE_FAILURE', 'failure',
                                    recording_id=self.segment, error_category=type(exc).__name__,
                                    operation_id=self.operation_id)
            except (OSError, ValueError):
                pass  # Fixed visible warning is the remaining channel.
        if first or required:
            self.warning()
        if required:
            raise activity.AuditError('Required session audit could not be persisted; action not authorized') from exc

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
            self.close('case transition')
            self.path = self.segment = self.head = self.authority = None
            self.case = Path(case).absolute() if case else None
            self.binding = None
            self.broken = False
            self.output_bytes = self.omitted_bytes = self.size = 0
            self.events = []
            self.event_bytes = 0
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
                total = count = 0
                for file in root.iterdir():
                    activity._safe(file)
                    total += file.stat().st_size
                    count += 1
                    if count >= MAX_FILES or total > ROOT_BYTES - SESSION_BYTES:
                        raise activity.AuditError('Session storage quota reached')
                if shutil.disk_usage(root).free < SESSION_BYTES + RESERVE:
                    raise activity.AuditError('Insufficient session storage')
                self.authority = authority
                self.segment = uuid.uuid4().hex
                self.path = root / (self.segment + '.jsonl')
                with DirectoryGuard(root):
                    with self.path.open('xb'):
                        pass
                    info = self.path.stat()
                    self.file_identity = (info.st_dev, info.st_ino)
                self.emit('session_start', dict(application_version=self.version, case_binding=self.binding,
                          limitations=['bounded output; no external editor keystrokes',
                                       'parent-visible worker diagnostics only; raw AI debug output excluded']), required=True)
                self.anchor('SESSION_RECORD_START', required=True)
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
                fields = dict(contract='session-record-v1', event_id=uuid.uuid4().hex,
                              observed_utc=datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                              application_session_id=self.id, operation_id=self.operation_id, data=data)
                ceiling = SESSION_BYTES if kind in ('session_end', 'capture_gap') else SESSION_BYTES - RESERVE
                estimate = len(activity.canonical(fields)) + 1024
                if self.size + self.event_bytes + estimate > ceiling:
                    raise activity.AuditError('Session size limit reached')
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
                                recording_contract='session-record-v1', recording_id=self.segment,
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
            encoded = str(text).encode('utf-8', errors='replace')
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


def read_response(read, prompt, *, command=False, **kwargs):
    recorder = ACTIVE.get()
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
    def __init__(self, reader):
        self.reader = reader

    def __getattr__(self, name):
        return getattr(self.reader, name)

    def read(self, prompt, **kwargs):
        return read_response(self.reader.read, prompt, command=kwargs.get('remember', False), **kwargs)


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
        builtins.input = lambda prompt='': read_response(oldinput, prompt)
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
    if audit['valid'] and audit.get('exists'):
        with activity.locked(authority) as stream:
            while raw := stream.readline(activity.MAX_ENTRY + 1):
                entry = activity.decode(raw)
                if entry.get('recording_contract') == 'session-record-v1':
                    key = entry.get('recording_id', '')
                    if not re.fullmatch('[0-9a-f]{32}', key):
                        raise activity.AuditError('Invalid recording identity')
                    if key not in anchors and len(anchors) >= MAX_FILES:
                        raise activity.AuditError('Session verification limit exceeded')
                    anchors[key] = [entry]  # Latest trusted prefix commits all earlier links.
    rows = []
    names = set(anchors)
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
                    with activity.locked(path) as stream:
                        while raw := stream.readline(activity.MAX_ENTRY + 1):
                            e = activity.decode(raw)
                            consumed += len(raw)
                            prefix_bytes[e['sequence']] = consumed
                            entries[e['sequence']] = e
                            if e['session_id'] != identity or e.get('contract') != 'session-record-v1':
                                raise activity.AuditError('Session identity or contract mismatch')
                            if e['action'] == 'session_start':
                                binding = e['data'].get('case_binding')
                                row.update(start=e['timestamp_utc'], application_version=e['data'].get('application_version'))
                                row['limitations'].extend(e['data'].get('limitations', []))
                            if e['action'] == 'capture_gap':
                                row['limitations'].append(e['data'])
                    row['records'] = len(entries)
                    row['head_hash'] = checked['head_hash']
                    row['anchored_through'] = refs[-1]['recording_sequence'] if refs else 0
                    if refs:
                        for ref in refs:
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
        except (OSError, ValueError):
            row['integrity'] = 'corrupt'
        rows.append(row)
    rows.sort(key=lambda r: (r['start'] or '', r['session_id']))
    return dict(kind='session_audit', valid=audit['valid'] and all(r['integrity'] in ('verified', 'incomplete') for r in rows),
                activity=audit, sessions=rows)


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


def render(value):
    from .retrieval.presentation import safe_text
    if value['kind'] == 'session_review':
        lines = ['Session ' + value['session']['session_id'] + ' — ' + value['session']['integrity']]
        for e in value['records']:
            lines.append(f"{e['sequence']} {e['timestamp_utc']} {e['action']}: " + safe_text(e.get('data', {})))
        lines.append('Earlier matching records omitted: ' + str(value['omitted_records']))
        lines.append('Records beyond the latest authority checkpoint: ' + str(value['unanchored_records']))
        return '\n'.join(lines)
    audit = value['activity']
    lines = ['Activity chain: ' + ('verified' if audit.get('exists') and audit['valid'] else 'missing' if audit['valid'] else 'corrupt')]
    for row in value['sessions']:
        lines.append(f"{row['session_id']}  {row['start']}  {row['integrity']}  {row['completion']}  Locard {row['application_version']}")
        lines.append('  Capture limitations: ' + safe_text(row['limitations']))
    if not value['sessions']:
        lines.append('No linked session recordings (historical activity remains independently verifiable).')
    return '\n'.join(lines)

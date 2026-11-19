"""Bounded, ephemeral MFT worker progress; never evidence or publication authority."""
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import os
import stat
from pathlib import Path
import time

PHASES = ('initialization', 'parsing', 'staging', 'reconstruction', 'finalizing', 'complete')
COUNTERS = ('records', 'bytes_read', 'paths')
MAX_FRAME = 1024
INACTIVITY = 900
STARTUP = 60
HARD = 21600
CURRENT = ContextVar('mft_worker_progress', default=None)


def policy(inactivity=INACTIVITY, startup=STARTUP, hard=HARD):
    for value, maximum in ((inactivity, 3600), (startup, 300), (hard, 86400)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError('MFT inactivity must be 1..3600, startup 1..300 and emergency ceiling 1..86400 seconds')
    return dict(inactivity=inactivity, startup=startup, hard=hard)


class ProgressError(ValueError):
    def __init__(self, message, *, operation='validate', failure='invalid_semantics', cause=None):
        super().__init__(message)
        self.diagnostics = dict(progress_operation=operation, progress_failure=failure)
        if isinstance(cause, OSError):
            for key in ('errno', 'winerror'):
                value = getattr(cause, key, None)
                if type(value) is int:
                    self.diagnostics[key] = value


def safe_diagnostics(value):
    """Worker-supplied diagnostics are codes, never arbitrary exception text."""
    if type(value) is not dict:
        return {}
    result = {}
    for key, allowed in (
        ('progress_operation', ('open', 'read', 'write', 'replace', 'decode', 'validate')),
        ('progress_failure', ('io_error', 'invalid_json', 'invalid_semantics', 'counter_regression',
                              'phase_regression', 'frame_limit', 'duplicate_field', 'unsafe_file'))):
        if type(value.get(key)) is str and value[key] in allowed:
            result[key] = value[key]
    for key in ('errno', 'winerror'):
        if type(value.get(key)) is int and -(2**31) <= value[key] < 2**32:
            result[key] = value[key]
    return result


class WorkerFailure(ValueError):
    def __init__(self, category, details):
        self.diagnostics = dict(details, category=category, staged_output='rejected')
        super().__init__('MFT worker ' + category.replace('_', ' ') + (': ' + details['reason'] if 'reason' in details else '') + '; staged output rejected')


def snapshot_path(stage):
    return Path(str(stage) + '.progress')


def replace_snapshot(temporary, path, initial):
    """Publish once, without retries; Windows MoveFileEx cannot replace an open target."""
    if os.name != 'nt':
        os.replace(temporary, path)
        return
    import ctypes as c
    from ctypes import wintypes as w
    import msvcrt
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.SetFileInformationByHandle.argtypes = [w.HANDLE, c.c_int, w.LPVOID, w.DWORD]
    kernel.SetFileInformationByHandle.restype = w.BOOL
    class Rename(c.Structure):
        _fields_ = [('flags', w.DWORD), ('root', w.HANDLE), ('length', w.DWORD), ('name', w.WCHAR * 1)]
    name = str(path.absolute()).encode('utf-16-le')
    buffer = c.create_string_buffer(c.sizeof(Rename) + len(name))
    info = Rename.from_buffer(buffer)
    # FileRenameInfoEx: REPLACE_IF_EXISTS | POSIX_SEMANTICS; no copy/delete gap.
    info.flags, info.length = (0 if initial else 3), len(name)
    c.memmove(c.addressof(buffer) + Rename.name.offset, name, len(name))
    fd = _windows_fd(temporary, delete=True)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ProgressError('MFT progress temporary file aliased', operation='replace', failure='unsafe_file')
        if not kernel.SetFileInformationByHandle(msvcrt.get_osfhandle(fd), 22, buffer, len(buffer)):
            raise c.WinError(c.get_last_error())
    finally:
        os.close(fd)


class Reporter:
    def __init__(self, path, clock=time.monotonic):
        self.path, self.clock = Path(path), clock
        self.last_write = float('-inf')
        self.value = dict(contract='mft-progress-v1', phase='initialization', records=0, bytes_read=0, paths=0)
        self.update(force=True)

    def update(self, *, phase=None, force=False, **counts):
        changed_phase = phase is not None and phase != self.value['phase']
        if phase is not None:
            self.value['phase'] = phase
        self.value.update(counts)
        now = self.clock()
        if not force and not changed_phase and now - self.last_write < 1:
            return
        raw = json.dumps(self.value, separators=(',', ':')).encode('ascii')
        if len(raw) > MAX_FRAME:
            raise ProgressError('MFT progress frame exceeds limit', operation='write', failure='frame_limit')
        temporary = self.path.with_suffix(self.path.suffix + '.tmp')
        operation = 'write'
        try:
            temporary.write_bytes(raw)
            operation = 'replace'
            replace_snapshot(temporary, self.path, self.last_write == float('-inf'))
        except OSError as exc:
            raise ProgressError('MFT progress communication failed', operation=operation,
                                failure='io_error', cause=exc) from exc
        self.last_write = now


def advance(**values):
    reporter = CURRENT.get()
    if reporter is not None:
        reporter.update(**values)


@contextmanager
def reporting(stage):
    reporter = Reporter(snapshot_path(stage))
    token = CURRENT.set(reporter)
    try:
        yield reporter
    finally:
        CURRENT.reset(token)


def _windows_fd(path, *, delete=False):
    """Pin the file, not its pathname; permit atomic replacement while reading."""
    import ctypes as c
    from ctypes import wintypes as w
    import msvcrt
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.GetFileInformationByHandleEx.argtypes = [w.HANDLE, c.c_int, w.LPVOID, w.DWORD]
    class Attributes(c.Structure):
        _fields_ = [('attributes', w.DWORD), ('reparse_tag', w.DWORD)]
    # GENERIC_READ; SHARE_READ|WRITE|DELETE; OPEN_EXISTING; OPEN_REPARSE_POINT.
    handle = kernel.CreateFileW(str(path), 0x80000000 | (0x10000 if delete else 0), 7, None, 3, 0x00200000, None)
    if handle == w.HANDLE(-1).value:
        raise c.WinError(c.get_last_error())
    try:
        info = Attributes()
        if not kernel.GetFileInformationByHandleEx(handle, 9, c.byref(info), c.sizeof(info)):
            raise c.WinError(c.get_last_error())
        if info.attributes & (0x400 | 0x10):
            raise ProgressError('MFT progress file redirected or not regular', operation='open', failure='unsafe_file')
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    return fd  # Ownership transferred to the CRT descriptor.


@contextmanager
def snapshot_reader(path):
    """Read one pinned regular snapshot; replacement may unlink that snapshot."""
    if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
        raise ProgressError('MFT progress path redirected', operation='open', failure='unsafe_file')
    fd = _windows_fd(path) if os.name == 'nt' else os.open(
        path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        info = os.fstat(fd)
        # Zero links means the publisher already replaced this pinned snapshot.
        if not stat.S_ISREG(info.st_mode) or info.st_nlink not in (0, 1):
            raise ProgressError('MFT progress file aliased or not regular', operation='open', failure='unsafe_file')
        stream = os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise
    with stream:
        yield stream


def read_snapshot(path):
    operation = 'open'
    try:
        with snapshot_reader(path) as stream:
            operation = 'read'
            raw = stream.read(MAX_FRAME + 1)
        if len(raw) > MAX_FRAME:
            raise ProgressError('MFT progress frame exceeds limit', operation='read', failure='frame_limit')
        def pairs(items):
            value = {}
            for key, item in items:
                if key in value:
                    raise ProgressError('Duplicate progress field', operation='decode', failure='duplicate_field')
                value[key] = item
            return value
        return json.loads(raw, object_pairs_hook=pairs)
    except ProgressError:
        raise
    except OSError as exc:
        raise ProgressError('MFT progress communication failed', operation=operation,
                            failure='io_error', cause=exc) from exc
    except ValueError as exc:
        raise ProgressError('MFT progress communication failed', operation='decode', failure='invalid_json') from exc


class Deadline:
    def __init__(self, configuration, source_size, clock=time.monotonic):
        self.config = policy(**configuration)
        self.source_size, self.clock = source_size, clock
        self.started = self.last = clock()
        self.ready = False
        self.phase = 'initialization'
        self.completed_phase = None
        self.counts = dict.fromkeys(COUNTERS, 0)
        self.last_utc = None

    def observe(self, value):
        if (type(value) is not dict or set(value) != {'contract', 'phase', *COUNTERS}
                or value['contract'] != 'mft-progress-v1' or value['phase'] not in PHASES):
            raise ProgressError('Invalid MFT progress contract')
        phase = value['phase']
        for key in COUNTERS:
            if type(value[key]) is not int or not 0 <= value[key] <= 2**63 - 1:
                raise ProgressError('Invalid MFT progress counter')
            if value[key] < self.counts[key]:
                raise ProgressError('Invalid MFT progress counter', failure='counter_regression')
        if PHASES.index(phase) < PHASES.index(self.phase):
            raise ProgressError('Invalid MFT progress advancement', failure='phase_regression')
        if value['bytes_read'] > self.source_size:
            raise ProgressError('Invalid MFT progress advancement')
        if phase == 'initialization' and any(value[k] for k in COUNTERS):
            raise ProgressError('Unexpected initialization counters')
        if PHASES.index(phase) < PHASES.index('reconstruction') and value['paths']:
            raise ProgressError('Unexpected reconstruction counters')
        moved = any(value[k] > self.counts[k] for k in COUNTERS)
        if phase == self.phase and phase in ('staging', 'finalizing', 'complete') and moved:
            raise ProgressError('Unexpected fixed-phase counters')
        if phase != self.phase or moved:
            if phase != self.phase:
                self.completed_phase = self.phase
            self.last = self.clock()
            self.last_utc = datetime.now(timezone.utc).isoformat()
        if phase != 'initialization':
            self.ready = True
        self.phase = phase
        self.counts = {k: value[k] for k in COUNTERS}

    def check(self):
        now = self.clock()
        if now - self.started >= self.config['hard']:
            return 'emergency_ceiling'
        if not self.ready and now - self.started >= self.config['startup']:
            return 'startup_timeout'
        if self.ready and now - self.last >= self.config['inactivity']:
            return 'progress_inactivity'
        return None

    def details(self):
        now = self.clock()
        return dict(artifact='mft', policy=self.config, phase=self.phase,
                    last_completed_phase=self.completed_phase, elapsed_seconds=round(now-self.started, 3),
                    progress_idle_seconds=round(now-self.last, 3), last_progress_utc=self.last_utc,
                    **self.counts)


def description(fields):
    phase = fields.get('parser_stage')
    if phase not in PHASES:
        return ''
    count = fields.get('paths_processed' if phase == 'reconstruction' else 'records_processed', 0)
    if type(count) is not int or count < 0:
        return ''
    unit = 'paths' if phase == 'reconstruction' else 'record slots'
    return f'{phase}: {count:,} {unit} processed'


@contextmanager
def display(args):
    from forensic_assistant.ingest.observation import CURRENT as OBSERVER, Observation
    from forensic_assistant.terminal_activity import operation
    if OBSERVER.get() is not None or args.command != 'ingest-mft':
        yield
        return
    started = time.monotonic()
    with operation('MFT: initializing...', args) as indicator:
        def update(fields):
            text = description(fields)
            if text:
                indicator.update(f'MFT {text} | {int(time.monotonic()-started)}s elapsed')
        with Observation('MFT', on_update=update):
            yield

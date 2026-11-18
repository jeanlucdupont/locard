"""Bounded, ephemeral MFT worker progress; never evidence or publication authority."""
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import os
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
    pass


class WorkerFailure(ValueError):
    def __init__(self, category, details):
        self.diagnostics = dict(details, category=category, staged_output='rejected')
        super().__init__('MFT worker ' + category.replace('_', ' ') + (': ' + details['reason'] if 'reason' in details else '') + '; staged output rejected')


def snapshot_path(stage):
    return Path(str(stage) + '.progress')


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
            raise ProgressError('MFT progress frame exceeds limit')
        temporary = self.path.with_suffix(self.path.suffix + '.tmp')
        try:
            temporary.write_bytes(raw)
            os.replace(temporary, self.path)
        except OSError as exc:
            raise ProgressError('MFT progress communication failed') from exc
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


def read_snapshot(path):
    try:
        if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
            raise ProgressError('MFT progress path redirected')
        with path.open('rb') as stream:
            if os.fstat(stream.fileno()).st_nlink != 1:
                raise ProgressError('MFT progress file aliased')
            raw = stream.read(MAX_FRAME + 1)
        if len(raw) > MAX_FRAME:
            raise ProgressError('MFT progress frame exceeds limit')
        def pairs(items):
            value = {}
            for key, item in items:
                if key in value:
                    raise ProgressError('Duplicate progress field')
                value[key] = item
            return value
        return json.loads(raw, object_pairs_hook=pairs)
    except (OSError, ValueError) as exc:
        raise ProgressError('MFT progress communication failed') from exc


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
            if type(value[key]) is not int or not self.counts[key] <= value[key] <= 2**63 - 1:
                raise ProgressError('Invalid MFT progress counter')
        if value['bytes_read'] > self.source_size or PHASES.index(phase) < PHASES.index(self.phase):
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

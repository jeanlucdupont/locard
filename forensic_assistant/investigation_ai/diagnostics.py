"""Content-free, bounded startup diagnostics; no evidence or exception prose."""
from contextlib import contextmanager, nullcontext
import logging
import math
import time

LOG = logging.getLogger('forensic_assistant.investigation_ai')
PHASES = frozenset(('audit_init', 'transcript_init', 'worker_start', 'semantic_setup',
                    'database_open', 'schema_validation', 'fingerprint',
                    'snapshot_creation', 'initial_retrieval', 'inventory', 'source_hydration',
                    'initial_operation', 'exposure', 'pre_model', 'supervisor_start'))


def record(value):
    # Worker messages are untrusted IPC: admit only fixed names and finite numbers.
    if not isinstance(value, dict) or set(value) != {'stage', 'event', 'seconds', 'remaining', 'watchdog_remaining'}:
        raise ValueError('Invalid startup diagnostic')
    if value['stage'] not in PHASES or value['event'] not in ('start', 'complete', 'failure', 'timeout'):
        raise ValueError('Invalid startup diagnostic')
    if any(type(value[k]) not in (int, float) or not math.isfinite(value[k]) or value[k] < 0
           for k in ('seconds', 'remaining', 'watchdog_remaining')):
        raise ValueError('Invalid startup diagnostic')
    LOG.debug('investigate-ai startup stage=%s event=%s elapsed=%.6fs remaining=%.6fs watchdog_remaining=%.6fs',
              value['stage'], value['event'], value['seconds'], value['remaining'], value['watchdog_remaining'])


class Profile:
    def __init__(self, deadline, emit=record, overall_deadline=None):
        self.deadline, self.emit = deadline, emit
        self.overall_deadline = deadline if overall_deadline is None else overall_deadline
        self.started = time.perf_counter()
        self.current = 'worker_start'

    def send(self, stage, event, seconds):
        now = time.monotonic()
        remaining = self.overall_deadline - now
        watchdog = self.deadline - now
        self.emit(dict(stage=stage, event=event, seconds=max(0, seconds),
                       remaining=max(0, remaining) if math.isfinite(remaining) else 0,
                       watchdog_remaining=max(0, watchdog) if math.isfinite(watchdog) else 0))

    @contextmanager
    def phase(self, stage):
        self.current = stage
        start = time.perf_counter()
        self.send(stage, 'start', 0)
        try:
            yield
        except BaseException:
            self.send(stage, 'timeout' if time.monotonic() >= self.deadline else 'failure', time.perf_counter()-start)
            raise
        else:
            self.send(stage, 'complete', time.perf_counter()-start)


def measure(profile, stage):
    return profile.phase(stage) if profile is not None else nullcontext()

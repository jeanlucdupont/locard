"""Dump-only duration accounting; no evidence, paths, SQL or audit payloads."""
from collections import defaultdict
from contextlib import contextmanager
import time


class Timings:
    def __init__(self, clock=None):
        # Monotonic high-resolution counter, including on Windows where
        # time.monotonic() may have only 15.6 ms resolution.
        self.clock = clock or time.perf_counter
        self.phases = defaultdict(lambda: defaultdict(float))
        self.total = 0.0

    @contextmanager
    def measure(self, phase, kind='shared'):
        start = self.clock()
        try:
            yield
        finally:
            self.phases[kind][phase] += self.clock() - start

    def call(self, phase, kind, function, *args, **kwargs):
        with self.measure(phase, kind):
            return function(*args, **kwargs)

    def elapsed(self, kind):
        return sum(self.phases[kind].values())

    def read_elapsed(self, kind):
        return sum(self.phases[kind][p] for p in ('database_read', 'provenance_read'))

    def records(self, db, kind, generator):
        iterator = iter(generator(TimedDatabase(db, self, kind), kind))
        while True:
            before = self.read_elapsed(kind)
            start = self.clock()
            try:
                row = next(iterator)
            except StopIteration:
                return
            finally:
                # Generator work excludes the caller's CSV writing while suspended.
                self.phases[kind]['normalization'] += max(
                    0.0, self.clock() - start - (self.read_elapsed(kind) - before))
            yield row

    def summary(self):
        phases = {k: dict(sorted(v.items())) for k, v in sorted(self.phases.items())}
        measured = sum(sum(v.values()) for v in phases.values())
        return {'total': self.total, 'phases': phases,
                'other': max(0.0, self.total - measured)}


class TimedDatabase:
    """Measure the existing execute/fetch operations without changing queries."""
    def __init__(self, db, timing, kind):
        self.db, self.timing, self.kind = db, timing, kind

    def execute(self, sql, params=()):
        phase = ('provenance_read' if any(name in sql for name in
                 ('source_contexts', 'source_assertions', 'browser_record_occurrences')) else 'database_read')
        cursor = self.timing.call(phase, self.kind, self.db.execute, sql, params)
        return TimedCursor(cursor, self.timing, self.kind, phase)


class TimedCursor:
    def __init__(self, cursor, timing, kind, phase):
        self.cursor, self.timing, self.kind, self.phase = cursor, timing, kind, phase

    def fetchone(self):
        return self.timing.call(self.phase, self.kind, self.cursor.fetchone)

    def __iter__(self):
        return self

    def __next__(self):
        return self.timing.call(self.phase, self.kind, next, self.cursor)

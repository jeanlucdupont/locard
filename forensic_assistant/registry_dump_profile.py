"""Bounded, content-free diagnostics for a single Registry CSV dump."""
from contextlib import contextmanager, nullcontext
import time


PHASES = ('primary_registry_query', 'parent_id_collection',
          'parent_timestamp_query', 'row_normalization', 'csv_write', 'publication')


def measure(profile, phase):
    return profile.measure(phase) if profile is not None else nullcontext()


class RegistryProfile:
    def __init__(self, page_size, clock=None):
        self.clock = clock or time.perf_counter
        self.started = self.clock()
        self.page_size = page_size
        self.phases = {name: {'calls': 0, 'seconds': 0.0, 'max_seconds': 0.0}
                       for name in PHASES}
        self.counts = dict(pages=0, evidence_ids=0, primary_rows=0,
                           parent_ids=0, timestamp_rows=0, csv_rows=0,
                           max_page_rows=0)

    def add(self, phase, seconds):
        metric = self.phases[phase]
        metric['calls'] += 1
        metric['seconds'] += max(0.0, seconds)
        metric['max_seconds'] = max(metric['max_seconds'], seconds)

    @contextmanager
    def measure(self, phase):
        start = self.clock()
        try:
            yield
        finally:
            self.add(phase, self.clock() - start)

    def page(self, rows):
        self.counts['pages'] += 1
        self.counts['evidence_ids'] += rows
        self.counts['max_page_rows'] = max(self.counts['max_page_rows'], rows)

    def summary(self, completed):
        total = self.clock() - self.started
        phases = {name: {**m, 'average_seconds': m['seconds'] / m['calls'] if m['calls'] else 0.0}
                  for name, m in self.phases.items()}
        return dict(completed=completed, total_seconds=total,
                    other_seconds=max(0.0, total - sum(m['seconds'] for m in phases.values())),
                    page_size=self.page_size, **self.counts,
                    average_rows_per_page=self.counts['evidence_ids'] / self.counts['pages'] if self.counts['pages'] else 0.0,
                    phases=phases)

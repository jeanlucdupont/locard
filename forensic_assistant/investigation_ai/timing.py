"""Monotonic execution accounting; only the terminal owner credits analyst waits."""
from contextlib import contextmanager
import math
import time
from .diagnostics import LOG

# Per-prompt abandonment guard, independent of the 300-second execution budget.
APPROVAL_SECONDS = 900.0


class ExecutionClock:
    def __init__(self, started, deadline):
        if not math.isfinite(started) or not math.isfinite(deadline):
            raise ValueError("Invalid execution clock")
        self.started, self.base_deadline = started, deadline
        self.wait = 0.0
        self.depth = 0
        self.pause_started = None

    @property
    def analyst_wait(self):
        total = self.wait
        if self.pause_started is not None:
            total += max(0.0, time.monotonic() - self.pause_started)
        return max(0.0, total)

    @property
    def deadline(self):
        return self.base_deadline + self.analyst_wait

    def remaining(self):
        return max(0.0, self.deadline - time.monotonic())

    def metrics(self):
        elapsed = max(0.0, time.monotonic() - self.started)
        wait = min(elapsed, self.analyst_wait)
        return dict(elapsed_seconds=elapsed, execution_seconds=max(0.0, elapsed-wait),
                    analyst_wait_seconds=wait)

    def credit_wait(self, seconds):
        # Credit comes only from the owning terminal, never a model or tool frame.
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds < 0:
            raise ValueError("Invalid analyst wait")
        if self.wait + seconds > max(0.0, time.monotonic()-self.started):
            raise ValueError("Analyst wait exceeds elapsed time")
        self.wait += seconds

    @contextmanager
    def approval_wait(self):
        if self.depth == 0:
            self.pause_started = time.monotonic()
            LOG.debug('investigate-ai phase=approval_wait event=start remaining_execution_budget=%.6f', self.remaining())
        self.depth += 1
        try:
            yield
        finally:
            self.depth -= 1
            if self.depth == 0:
                elapsed = max(0.0, time.monotonic() - self.pause_started)
                self.credit_wait(elapsed)
                self.pause_started = None
                LOG.debug('investigate-ai phase=approval_wait event=complete elapsed=%.6f remaining_execution_budget=%.6f', elapsed, self.remaining())

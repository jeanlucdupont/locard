"""Transient progress only: no decisions, deadlines, evidence writes or readers."""
from contextvars import ContextVar
import sys
import threading
import time
from forensic_assistant.retrieval.presentation import safe_text
from forensic_assistant.terminal import capable, replace_progress_line

CURRENT = ContextVar('ingestion_observer', default=None)


def emit(**fields):
    observer = CURRENT.get()
    if observer is not None:
        observer.update(**fields)


class Observation:
    def __init__(self, label, *, stream=None, clock=time.monotonic, interval=3, slow_after=10, diagnostics=False):
        self.diagnostics = diagnostics
        self.label = label
        self.stream = sys.stdout if stream is None else stream
        self.clock = clock
        self.interval = interval
        self.slow_after = slow_after
        self.visible = False
        self.last_snapshot = None
        self.started = self.last_progress = clock()
        self.fields = {}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None

    def update(self, **fields):
        with self.lock:
            # Liveness is not evidence of parser progress.
            progress = any(k not in ('worker_pid', 'worker_alive', 'worker_exit_code')
                           and self.fields.get(k) != v for k, v in fields.items())
            self.fields.update(fields)
            if progress:
                self.last_progress = self.clock()

    def render(self):
        with self.lock:
            fields = dict(self.fields)
            elapsed = int(self.clock() - self.started)
            idle = int(self.clock() - self.last_progress)
        lines = [f'{self.label}: {elapsed}s elapsed; last observed progress {idle}s ago']
        for key, value in fields.items():
            lines.append('  ' + key.replace('_', ' ') + ': ' + safe_text(str(value)))
        return '\n'.join(lines)

    def refresh(self):
        """Explicit diagnostic display only; elapsed time never enables it."""
        if not self.diagnostics:
            return
        now = self.clock()
        if now - self.started < self.slow_after:
            return
        try:
            if not self.visible or now - self.last_snapshot >= 30:
                print("\n" + self.render(), file=self.stream, flush=True)
                self.last_snapshot = now
            elif capable(self.stream):
                replace_progress_line(self.render().replace('\n', ' | '), self.stream)
            self.visible = True
        except (OSError, ValueError):
            pass

    def _display(self):
        while not self.stop.wait(self.interval):
            self.refresh()

    def __enter__(self):
        self.token = CURRENT.set(self)
        if self.diagnostics:
            self.thread = threading.Thread(target=self._display, daemon=True, name='Locard observation')
            self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        if self.thread is not None:
            self.thread.join()
        CURRENT.reset(self.token)
        if self.visible:
            try:
                if capable(self.stream):
                    replace_progress_line("", self.stream)
                print(file=self.stream, flush=True)
            except (OSError, ValueError):
                pass

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
    def __init__(self, label, *, stream=None, clock=time.monotonic, interval=3):
        self.label = label
        self.stream = sys.stdout if stream is None else stream
        self.clock = clock
        self.interval = interval
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

    def _display(self):
        # Periodic snapshots retain full paths and cannot overwrite other output.
        # Only the display thread touches the terminal; it never reads stdin/DB.
        last_snapshot = self.clock()
        while not self.stop.wait(self.interval):
            try:
                if capable(self.stream):
                    with self.lock:
                        path = self.fields.get("current_path", "")
                    replace_progress_line(safe_text(f"{self.label}: {int(self.clock()-self.started)}s | {path}"), self.stream)
                if self.clock() - last_snapshot >= 30:
                    print("\n" + self.render(), file=self.stream, flush=True)
                    last_snapshot = self.clock()
            except (OSError, ValueError):
                return

    def __enter__(self):
        self.token = CURRENT.set(self)
        print(self.render(), file=self.stream, flush=True)
        self.thread = threading.Thread(target=self._display, daemon=True, name='Locard observation')
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join()
        CURRENT.reset(self.token)
        print(self.render(), file=self.stream, flush=True)

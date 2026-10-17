"""Parent-side bounded worker lifecycle; no persistent SQLite read locks."""
from collections import deque
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from .diagnostics import record, PHASES, LOG

class WorkerError(ValueError):
    def __init__(self, message, *, stage=None, timed_out=False):
        super().__init__(message)
        self.stage, self.timed_out = stage, timed_out

class ForensicWorker:
    worker_script = Path(__file__).with_name('worker.py')
    def __init__(self, config):
        config = dict(config)
        self.status = config.pop('_status', None)
        self.deadline = config.get('_deadline', float('inf'))
        if time.monotonic() >= self.deadline:
            raise WorkerError('INVESTIGATION_TIMEOUT')
        for key in ('index_root', 'model_path'):
            if config.get(key):
                config[key] = str(Path(config[key]).resolve())
        self.case_path = Path(config['case_path']).resolve(strict=True)
        self.process = None
        self.messages = queue.Queue(maxsize=2)
        self.diagnostics = deque(maxlen=4)
        self.job = None
        self.worker_pid = None
        self.stage = 'worker_start'
        environment = dict(os.environ)
        for name in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONINSPECT'):
            environment.pop(name, None)
        environment.update(HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', HF_HUB_DISABLE_TELEMETRY='1', DO_NOT_TRACK='1')
        self.process = subprocess.Popen(
            [sys.executable, '-I', '-B', str(self.worker_script)],
            cwd=str(Path(__file__).parent),
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        def output():
            try:
                while line := self.process.stdout.readline(512 * 1024 + 2):
                    if len(line) > 512 * 1024 + 1:
                        self.messages.put({'error': 'Worker output size violation'})
                        return
                    self.messages.put(json.loads(line))
            except Exception:
                self.messages.put({'error': 'Malformed worker output'})
        def diagnostic():
            while chunk := self.process.stderr.read(1024):
                self.diagnostics.append(chunk)
        threading.Thread(target=output, daemon=True).start()
        threading.Thread(target=diagnostic, daemon=True).start()
        try:
            ready = self._exchange({'config': {**config, 'case_path': str(self.case_path)}},
                                   max(0, self.deadline - time.monotonic()) if self.deadline != float('inf') else 10)
            self.worker_pid = ready['worker_pid']
            from .lifecycle import WorkerJob
            self.job = WorkerJob(self.worker_pid)
        except BaseException:
            self.close()
            raise

    def _wal_size(self):
        try:
            return Path(str(self.case_path) + '-wal').stat().st_size
        except FileNotFoundError:
            return 0

    def _exchange(self, message, seconds):
        if not self.process or self.process.poll() is not None:
            raise WorkerError('Worker unavailable')
        raw = json.dumps(message, ensure_ascii=True).encode() + b'\n'
        if len(raw) > 512 * 1024:
            raise WorkerError('Worker input size violation')
        baseline = self._wal_size()
        deadline = min(self.deadline, time.monotonic() + seconds)
        try:
            self.process.stdin.write(raw)
            self.process.stdin.flush()
            while True:
                if time.monotonic() >= deadline:
                    LOG.debug('investigate-ai watchdog=operation stage=%s remaining=%.6fs', self.stage, max(0, self.deadline-time.monotonic()))
                    raise WorkerError('TOOL_TIMEOUT', stage=self.stage, timed_out=True)
                if self._wal_size() - baseline > 64 * 1024 * 1024:
                    raise WorkerError('WAL_PRESSURE')
                try:
                    result = self.messages.get(timeout=min(.05, max(.001, deadline - time.monotonic())))
                except queue.Empty:
                    if self.process.poll() is not None:
                        raise WorkerError('Worker terminated abnormally')
                    continue
                if 'startup_diagnostic' in result:
                    record(result['startup_diagnostic'])
                    self.stage = result['startup_diagnostic']['stage']
                    if self.status and result['startup_diagnostic']['event'] == 'start':
                        self.status(self.stage)
                    continue
                if 'error' in result:
                    stage = result.get('stage')
                    stage = stage if stage in PHASES else self.stage
                    timeout = result.get('timed_out') is True
                    LOG.debug('investigate-ai worker failure stage=%s category=%s watchdog=operation remaining=%.6fs',
                              stage, 'timeout' if timeout else 'failure', max(0, deadline-time.monotonic()))
                    raise WorkerError(result['error'], stage=stage, timed_out=timeout)
                return result
        except (BrokenPipeError, OSError) as exc:
            self.close()
            raise WorkerError('Worker communication failed') from exc
        except WorkerError as exc:
            if str(exc) in ('TOOL_TIMEOUT', 'WAL_PRESSURE'):
                self.close()
            raise

    def call(self, operation, arguments=None, *, fingerprint=None, known_ids=(), seconds=45, question=None):
        return self._exchange(
            {
                'operation': operation,
                'arguments': arguments or {},
                'known_ids': list(known_ids),
                'expected_fingerprint': fingerprint,
                'seconds': seconds,
                'question': question
            },
            seconds
        )

    def close(self):
        if self.job:
            self.job.close()
            self.job = None
        if self.process:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=5)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream:
                    try:
                        stream.close()
                    except OSError:
                        pass

    def __enter__(self):
        return self
    def __exit__(self, *exc):
        self.close()

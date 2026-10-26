"""Parent-side bounded worker lifecycle; worker-owned consistent read view."""
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
    def __init__(self, message, *, stage=None, timed_out=False, integrity=None):
        super().__init__(message)
        self.stage, self.timed_out = stage, timed_out
        self.integrity = integrity

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
        self._wal_baseline = self._wal_size() if config.get('_transaction_view') else None
        self.process = None
        self.messages = queue.Queue(maxsize=2)
        self._reader_stop = threading.Event()
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
        def deliver(value):
            while not self._reader_stop.is_set():
                try:
                    self.messages.put(value, timeout=.05)
                    return True
                except queue.Full:
                    pass
            return False
        def output():
            try:
                while line := self.process.stdout.readline(512 * 1024 + 2):
                    if len(line) > 512 * 1024 + 1:
                        deliver({'error': 'Worker output size violation'})
                        return
                    if not deliver(json.loads(line)):
                        return
            except Exception:
                deliver({'error': 'Malformed worker output'})
        def diagnostic():
            while chunk := self.process.stderr.read(1024):
                self.diagnostics.append(chunk)
        self._readers = [threading.Thread(target=target, daemon=True) for target in (output, diagnostic)]
        for reader in self._readers:
            reader.start()
        try:
            ready = self._exchange({'config': {**config, 'case_path': str(self.case_path)}},
                                   max(0, self.deadline - time.monotonic()) if self.deadline != float('inf') else 10)
            self.worker_pid = ready['worker_pid']
            from .lifecycle import WorkerJob
            self.job = WorkerJob(self.worker_pid)
        except BaseException as primary:
            try:
                self.close()
            except RuntimeError as cleanup:
                cleanup.primary = 'TOOL_TIMEOUT' if isinstance(primary, WorkerError) and primary.timed_out else 'WORKER_START_FAILURE'
                raise
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
        baseline = self._wal_size() if self._wal_baseline is None else self._wal_baseline
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
                    raise WorkerError(result['error'], stage=stage, timed_out=timeout,
                                      integrity=result.get('integrity'))
                return result
        except (BrokenPipeError, OSError) as exc:
            try:
                self.close()
            except RuntimeError as cleanup:
                cleanup.primary = 'TOOL_FAILURE'
                raise
            raise WorkerError('Worker communication failed') from exc
        except WorkerError as exc:
            if str(exc) in ('TOOL_TIMEOUT', 'WAL_PRESSURE'):
                try:
                    self.close()
                except RuntimeError as cleanup:
                    cleanup.primary = 'TOOL_TIMEOUT' if exc.timed_out else 'WAL_PRESSURE'
                    raise
            raise

    def call(self, operation, arguments=None, *, fingerprint=None, known_ids=(), seconds=45, question=None):
        return self._exchange(
            {
                'operation': operation,
                '_deadline': self.deadline if self.deadline != float('inf') else None,
                'arguments': arguments or {},
                'known_ids': list(known_ids),
                'expected_fingerprint': fingerprint,
                'seconds': seconds,
                'question': question
            },
            seconds
        )

    def close(self):
        from .lifecycle import CleanupError
        failed = False
        if self.process and self.process.poll() is None:
            try:
                # EOF ends the serve loop and closes the pinned transaction.
                self.process.stdin.close()
                self.process.wait(timeout=.25)
            except (OSError, subprocess.TimeoutExpired):
                pass
        if self.job:
            job, self.job = self.job, None
            try:
                job.close_confirmed(seconds=1)
            except (OSError, RuntimeError):
                failed = True
        if self.process:
            try:
                if self.process.poll() is None:
                    self.process.kill()
                self.process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                failed = True
            self._reader_stop.set()
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream:
                    try:
                        stream.close()
                    except OSError:
                        pass
        for reader in self._readers:
            reader.join(timeout=.2)
            failed = failed or reader.is_alive()
        if failed:
            raise CleanupError('CLEANUP_LIMITATION: investigation worker cleanup unconfirmed')

    def __enter__(self):
        return self
    def __exit__(self, *exc):
        self.close()

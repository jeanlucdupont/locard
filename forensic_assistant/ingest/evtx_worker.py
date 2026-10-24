"""Supervised EVTX decoding with bounded disk IPC; never opens a case database."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import signal
import subprocess
import struct
import sys
import tempfile
import time

from forensic_assistant.investigation_ai.lifecycle import WorkerJob, CleanupError

HARD_TIMEOUT = 6 * 60 * 60
MAX_FRAME = 64 * 1024 * 1024
MAX_STAGE = 8 * 1024 ** 3


class ProgressDeadline:
    def __init__(self, stall=300, hard=HARD_TIMEOUT, clock=time.monotonic):
        if not 1 <= stall <= 3600 or not 1 <= hard <= 86400:
            raise ValueError('EVTX stall timeout must be 1..3600 seconds; hard ceiling 1..86400 seconds')
        self.stall, self.hard, self.clock = stall, hard, clock
        self.started = self.last = clock()
        self.position = -1

    def check(self):
        now = self.clock()
        if now - self.started >= self.hard:
            return f'EVTX parser emergency hard ceiling reached: {self.hard} seconds'
        if now - self.last >= self.stall:
            return f'EVTX parser stalled: no forensic progress for {self.stall} seconds'
        return None

    def advance(self, position):
        if type(position) is not int or position < 0:
            raise ValueError('Invalid EVTX progress position')
        if position > self.position:
            self.position = position
            self.last = self.clock()


def supervise(path, directory, timeout=300, hard_timeout=HARD_TIMEOUT, *, command=None,
              clock=time.monotonic, sleep=time.sleep):
    """Return a precise incomplete reason, or None. Cleanup precedes replay."""
    timer = ProgressDeadline(timeout, hard_timeout, clock)
    source_size = path.stat().st_size
    progress_offset = 0
    spool = directory / 'records.jsonl'
    ready, progress = directory / 'ready', directory / 'progress'
    args = command or [sys.executable, '-m', __name__, str(path), str(directory)]
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                start_new_session=sys.platform != 'win32',
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        job = None
        permitted = False
        try:
            while True:
                reason = timer.check()
                if reason:
                    return reason
                if any(os.fstat(f.fileno()).st_size > 65536 for f in (stdout, stderr)):
                    return 'EVTX worker diagnostic limit exceeded'
                if spool.exists() and spool.stat().st_size > MAX_STAGE:
                    return 'EVTX worker spool exceeds 8 GiB'
                if not permitted and ready.exists():
                    raw = ready.read_bytes()
                    if len(raw) > 128:
                        raise ValueError('Invalid EVTX worker handshake')
                    message = json.loads(raw)
                    if set(message) != {'worker_pid'} or type(message['worker_pid']) is not int:
                        raise ValueError('Invalid EVTX worker handshake')
                    job = WorkerJob(message['worker_pid'])
                    proc.stdin.write(b'go\n'); proc.stdin.flush(); proc.stdin.close()
                    permitted = True
                if permitted and progress.exists():
                    if progress.stat().st_size > 8 * 1024 ** 2:
                        return 'EVTX worker progress limit exceeded'
                    with progress.open('rb') as stream:
                        stream.seek(progress_offset)
                        raw = stream.read(8192)
                    complete_bytes = len(raw) // 8 * 8
                    for (position,) in struct.iter_unpack('<Q', raw[:complete_bytes]):
                        if position > source_size:
                            raise ValueError('Invalid EVTX worker progress position')
                        timer.advance(position)
                    progress_offset += complete_bytes
                if proc.poll() is not None:
                    if not permitted or proc.returncode:
                        return 'EVTX parser worker failed before completing the file'
                    return None
                sleep(.1)
        finally:
            try:
                if job:
                    job.close()
                elif proc.poll() is None:
                    proc.stdin.close()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired as exc:
                        raise CleanupError('Unconfirmed EVTX startup cleanup') from exc
            finally:
                try:
                    if sys.platform != 'win32':
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise CleanupError('EVTX worker cleanup failed') from exc
                finally:
                    if proc.stdin and not proc.stdin.closed:
                        proc.stdin.close()


def replay(spool, reason=None):
    from .evtx import ParsedRecord
    parsed = 0
    last_number = None
    errors, pending = [], []
    complete = False
    try:
        if spool.exists():
            with spool.open('rb') as stream:
                while line := stream.readline(MAX_FRAME + 1):
                    if len(line) > MAX_FRAME or not line.endswith(b'\n'):
                        reason = reason or 'EVTX worker output ended with an incomplete record'
                        break
                    message = json.loads(line)
                    if message == {'complete': True}:
                        complete = True
                        if stream.read(1):
                            reason = 'EVTX worker output contains data after completion'
                        break
                    if set(message) != {'record', 'recoverable'} or type(message['recoverable']) is not bool:
                        raise ValueError('Invalid EVTX worker record envelope')
                    record = ParsedRecord(**message['record'])
                    if (record.xml is None) == (record.error is None):
                        raise ValueError('Invalid EVTX worker record payload')
                    if ((record.xml is not None and not isinstance(record.xml, str))
                            or (record.error is not None and not isinstance(record.error, str))
                            or (record.diagnostics is not None and not isinstance(record.diagnostics, dict))
                            or any(value is not None and (type(value) is not int or value < 0)
                                   for value in (record.offset, record.record_id))):
                        raise ValueError('Invalid EVTX worker record fields')
                    if record.error:
                        if record.diagnostics is not None:
                            errors.append((record.diagnostics, parsed))
                            if message['recoverable']:
                                pending.append(record.diagnostics)
                    else:
                        for diagnostic in pending:
                            diagnostic['resume_offset'] = record.offset
                        pending.clear()
                        parsed += 1
                        last_number = record.record_id
                    yield record
    except (ValueError, TypeError, OSError) as exc:
        reason = f'EVTX worker output invalid: {type(exc).__name__}'
    finally:
        for diagnostic, at_error in errors:
            diagnostic['parsed_records_after_error'] = parsed - at_error
    if reason or not complete:
        yield ParsedRecord(None, error=reason or 'EVTX worker output incomplete',
                           diagnostics=dict(format='evtx', file_offset=None,
                                            chunk_number=None, chunk_offset=None,
                                            record_number=None, last_record_number=last_number,
                                            resume_offset=None, parsed_records_after_error=0))


def records(path, *, timeout=300, hard_timeout=HARD_TIMEOUT):
    path = Path(path).resolve()
    # Validate before creating resources. This directory contains derived XML only.
    ProgressDeadline(timeout, hard_timeout)
    with tempfile.TemporaryDirectory(prefix='locard-evtx-') as temp:
        directory = Path(temp)
        try:
            reason = supervise(path, directory, timeout, hard_timeout)
        except CleanupError:
            raise
        except (OSError, ValueError) as exc:
            reason = f'EVTX supervision failed: {type(exc).__name__}: {exc}'
        yield from replay(directory / 'records.jsonl', reason)


def run(path, directory):
    from forensic_assistant.artifacts.worker import limit_memory
    from .evtx_recovery import read_records
    guard = limit_memory()  # Keep OS memory job alive for the worker lifetime.
    directory = Path(directory)
    ready = directory / 'ready'
    temporary = directory / 'ready.tmp'
    temporary.write_text(json.dumps({'worker_pid': os.getpid()}), encoding='ascii')
    os.replace(temporary, ready)
    if sys.stdin.buffer.readline(16) != b'go\n':
        raise ValueError('EVTX parent containment handshake cancelled')
    last_position = -1
    last_write = 0

    def progress(position):
        nonlocal last_position, last_write
        if position <= last_position:
            return
        now = time.monotonic()
        if now - last_write < .1:
            return
        try:
            progress_stream.write(struct.pack('<Q', position))
            progress_stream.flush()
        except OSError as exc:
            # Infrastructure failure must stop the worker, not masquerade as a
            # malformed source chunk in the framing decoder's exception handler.
            raise SystemExit('EVTX progress IPC failed') from exc
        last_position, last_write = position, now

    with (directory / 'progress').open('wb') as progress_stream, \
            (directory / 'records.jsonl').open('wb') as stream:
        for record in read_records(path, progress=progress):
            frame = json.dumps({'record': asdict(record),
                                'recoverable': getattr(record, '_recoverable', False)},
                               ensure_ascii=True).encode('ascii') + b'\n'
            if len(frame) > MAX_FRAME or stream.tell() + len(frame) > MAX_STAGE:
                raise ValueError('EVTX spool resource limit exceeded')
            stream.write(frame)
            stream.flush()
        stream.write(b'{"complete":true}\n')
        stream.flush()


if __name__ == '__main__':
    run(sys.argv[1], sys.argv[2])

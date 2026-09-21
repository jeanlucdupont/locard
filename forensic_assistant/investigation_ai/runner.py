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

class WorkerError(ValueError):pass

class ForensicWorker:
    def __init__(self,config):
        config=dict(config)
        for key in ('index_root','model_path'):
            if config.get(key):config[key]=str(Path(config[key]).resolve())
        self.case_path=Path(config['case_path']).resolve(strict=True)
        self.process=None;self.messages=queue.Queue(maxsize=2);self.diagnostics=deque(maxlen=4)
        environment=dict(os.environ)
        for name in ('PYTHONPATH','PYTHONHOME','PYTHONSTARTUP','PYTHONINSPECT'):environment.pop(name,None)
        environment.update(HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',HF_HUB_DISABLE_TELEMETRY='1',DO_NOT_TRACK='1')
        self.process=subprocess.Popen([sys.executable,'-I',str(Path(__file__).with_name('worker.py'))],
          cwd=str(Path(__file__).parent),env=environment,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
          creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        def output():
            try:
                while line:=self.process.stdout.readline(512*1024+2):
                    if len(line)>512*1024+1:self.messages.put({'error':'Worker output size violation'});return
                    self.messages.put(json.loads(line))
            except Exception:self.messages.put({'error':'Malformed worker output'})
        def diagnostic():
            while chunk:=self.process.stderr.read(1024):self.diagnostics.append(chunk)
        threading.Thread(target=output,daemon=True).start();threading.Thread(target=diagnostic,daemon=True).start()
        try:self._exchange({'config':{**config,'case_path':str(self.case_path)}},10)
        except BaseException:self.close();raise

    def _wal_size(self):
        try:return Path(str(self.case_path)+'-wal').stat().st_size
        except FileNotFoundError:return 0

    def _exchange(self,message,seconds):
        if not self.process or self.process.poll() is not None:raise WorkerError('Worker unavailable')
        raw=json.dumps(message,ensure_ascii=True).encode()+b'\n'
        if len(raw)>512*1024:raise WorkerError('Worker input size violation')
        baseline=self._wal_size();deadline=time.monotonic()+seconds
        try:
            self.process.stdin.write(raw);self.process.stdin.flush()
            while True:
                if time.monotonic()>=deadline:raise WorkerError('TOOL_TIMEOUT')
                if self._wal_size()-baseline>64*1024*1024:raise WorkerError('WAL_PRESSURE')
                try:result=self.messages.get(timeout=min(.05,max(.001,deadline-time.monotonic())))
                except queue.Empty:
                    if self.process.poll() is not None:raise WorkerError('Worker terminated abnormally')
                    continue
                if 'error' in result:raise WorkerError(result['error'])
                return result
        except (BrokenPipeError,OSError) as exc:
            self.close();raise WorkerError('Worker communication failed') from exc
        except WorkerError as exc:
            if str(exc) in ('TOOL_TIMEOUT','WAL_PRESSURE'):self.close()
            raise

    def call(self,operation,arguments=None,*,fingerprint=None,known_ids=(),seconds=45,question=None):
        return self._exchange({'operation':operation,'arguments':arguments or {},'known_ids':list(known_ids),
          'expected_fingerprint':fingerprint,'seconds':seconds,'question':question},seconds)

    def close(self):
        if self.process:
            if self.process.poll() is None:self.process.kill()
            self.process.wait(timeout=5)
            for stream in (self.process.stdin,self.process.stdout,self.process.stderr):
                if stream:
                    try:stream.close()
                    except OSError:pass

    def __enter__(self):return self
    def __exit__(self,*exc):self.close()

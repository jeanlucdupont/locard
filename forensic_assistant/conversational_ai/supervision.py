"""Conversation-only supervision. Legacy investigation deadlines are unchanged."""
import json
import queue
import threading
import time
import uuid
from pathlib import Path
from forensic_assistant.investigation_ai.runner import ForensicWorker, WorkerError

CODES = frozenset(('ANALYST_CANCELLED','OPERATION_DEADLINE','DATABASE_QUERY_ERROR',
    'WORKER_TERMINATED','WORKER_COMMUNICATION','WORKER_PROTOCOL','AUTHORIZATION_FAILURE',
    'EVIDENCE_INTEGRITY','RESULT_PROJECTION','RESOURCE_PROTECTION','TOOL_REJECTED'))

class ConversationWorkerError(WorkerError):
    def __init__(self, code, *, view=None, recoverable=False, stage='operation', cleanup=None):
        super().__init__(code,stage=stage,timed_out=code=='OPERATION_DEADLINE',
                         integrity=view is not None,diagnostic={'code':code,'stage':stage})
        self.code=code;self.view=view;self.recoverable=recoverable;self.cleanup=cleanup

class ChatWorker(ForensicWorker):
    worker_script=Path(__file__).with_name('worker.py')
    cancellation_grace=5

    def __init__(self,config):
        self.cancel_event=threading.Event()
        self.progress=lambda value:None
        super().__init__(config)

    def cancel(self):
        self.cancel_event.set()

    def _exchange(self,message,seconds):
        if 'config' in message:return super()._exchange(message,seconds)
        identity=uuid.uuid4().hex
        message={**message,'operation_id':identity}
        deadline=min(self.deadline,time.monotonic()+seconds if seconds is not None else float('inf'))
        baseline=self._wal_size() if self._wal_baseline is None else self._wal_baseline
        cancelled=None;stop_at=None
        def lost(code):
            confirmed=True
            try:self.close()
            except (OSError,RuntimeError):confirmed=False
            raise ConversationWorkerError(code,cleanup=confirmed)
        def send(value):
            raw=json.dumps(value,ensure_ascii=True,allow_nan=False).encode()+b'\n'
            if len(raw)>512*1024:raise ConversationWorkerError('WORKER_PROTOCOL')
            self.process.stdin.write(raw);self.process.stdin.flush()
        if not self.process or self.process.poll() is not None:lost('WORKER_TERMINATED')
        try:
            try:send(message)
            except KeyboardInterrupt:self.cancel_event.set()
            while True:
                try:
                    now=time.monotonic()
                    if cancelled is None and (self.cancel_event.is_set() or now>=deadline):
                        cancelled='ANALYST_CANCELLED' if self.cancel_event.is_set() else 'OPERATION_DEADLINE'
                        # Consume only a signal being handled. A cancellation
                        # between exchanges must remain pending for the next call.
                        self.cancel_event.clear()
                        send(dict(operation='cancel',operation_id=identity))
                        stop_at=now+self.cancellation_grace
                    if stop_at is not None and now>=stop_at:lost(cancelled)
                    if self._wal_size()-baseline>64*1024*1024:lost('RESOURCE_PROTECTION')
                    try:result=self.messages.get(timeout=.05)
                    except queue.Empty:
                        if self.process.poll() is not None:lost('WORKER_TERMINATED')
                        continue
                    if not isinstance(result,dict) or result.get('operation_id')!=identity:lost('WORKER_PROTOCOL')
                    if 'progress' in result:
                        value=result['progress']
                        if (set(result)!={'operation_id','progress'} or not isinstance(value,dict) or
                            set(value)!={'processed','groups','phase','elapsed_seconds'} or
                            any(type(value[k]) is not int or value[k]<0 for k in ('processed','groups')) or
                            value['phase'] not in ('analyzing','completed','reused') or type(value['elapsed_seconds']) not in (int,float) or not 0<=value['elapsed_seconds']<1e9):lost('WORKER_PROTOCOL')
                        self.progress(dict(kind='progress',operation='Execution discovery',status=value['phase'],
                            elapsed_seconds=value['elapsed_seconds'],computational_progress=f"{value['processed']} records; {value['groups']} groups",**{k:value[k] for k in ('processed','groups')}))
                        continue  # Never extend the operation deadline.
                    if 'error' in result:
                        code=result['error']
                        if code not in CODES:lost('WORKER_PROTOCOL')
                        view=result.get('evidence_state')
                        healthy=result.get('recoverable') is True and isinstance(view,dict)
                        if not healthy:lost(code)
                        stage=result.get('stage','operation')
                        if stage not in ('operation','authorization','read_view','integrity','query','projection'):lost('WORKER_PROTOCOL')
                        raise ConversationWorkerError(cancelled or code,view=view,recoverable=True,stage=stage)
                    if not isinstance(result.get('result'),dict):lost('WORKER_PROTOCOL')
                    if cancelled:
                        # A completed-result race cannot prove that undelivered
                        # fields were rolled back in the worker exposure store.
                        lost(cancelled)
                    return result
                except KeyboardInterrupt:
                    # Interrupt the current SQLite operation, not the notebook.
                    self.cancel_event.set()
        except (OSError,BrokenPipeError):lost('WORKER_COMMUNICATION')

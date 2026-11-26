"""UI-independent elapsed activity; liveness is not computational progress."""
import threading
import time

class Activity:
    def __init__(self,emit,operation,*,interval=30,clock=time.monotonic):
        if interval<=0:raise ValueError('Activity interval must be positive')
        self.emit=emit;self.operation=operation;self.interval=interval;self.clock=clock
        self.stop=threading.Event();self.thread=None
    def event(self,status):
        self.emit(dict(kind='progress',operation=self.operation,status=status,
                       elapsed_seconds=max(0,self.clock()-self.started),computational_progress='unavailable'))
    def __enter__(self):
        self.started=self.clock();self.event('started')
        def report():
            first=True
            while not self.stop.wait(self.interval):
                self.event('slow' if first else 'waiting');first=False
        self.thread=threading.Thread(target=report,daemon=True);self.thread.start()
        return self
    def __exit__(self,kind,value,tb):
        self.stop.set();self.thread.join()
        self.event('completed' if kind is None else 'interrupted' if kind is KeyboardInterrupt else 'failed')

def description(name,args):
    if name=='discover_execution_behaviors':return 'Analyzing execution behaviors within the approved scope'
    if name=='discover_security_signals':return 'Discovering security signals within the approved scope'
    if name=='activity_overview':return 'Summarizing '+args.get('kind','approved activity').replace('_',' ')
    family=args.get('artifact','approved')
    if name=='search_evidence':return f'Searching {family} evidence within the approved time window'
    if name in ('timeline','around'):return f'Retrieving {family} timestamp observations'
    if name=='show_evidence':return 'Authorizing and inspecting original evidence'
    if name=='verify_observation':return 'Verifying an original evidence field'
    return 'Recording investigative note'

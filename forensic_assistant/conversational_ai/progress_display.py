"""Optional human diagnostic sink; never prints model text or original values."""
import time
from .contracts import SCHEMAS

class ProgressDisplay:
    def __init__(self,stream,clock=time.monotonic,log_path=None):
        self.log=log_path.open('x',encoding='utf-8') if log_path is not None else None
        self.stream=stream;self.clock=clock;self.started=clock();self.request=0;self.last='none';self.counts={k:0 for k in ('successful','failed','records','verifications','nonproductive','checkpoints')}
    def __call__(self,event):
        kind=event.get('kind')
        if kind=='investigative_progress':
            self.counts={k:event.get(k,0) for k in ('successful','failed','records','verifications','nonproductive','checkpoints')}
            self.request=event['request_sequence'];self.last=event['last_operation'] if event['last_operation'] in SCHEMAS else 'unknown'
            phase='operation completed'
        elif kind=='progress':
            phase=event.get('status') if event.get('status') in ('started','waiting','slow','completed','failed','interrupted') else 'active'
            if event.get('operation')=='Waiting for the AI investigator':
                if phase=='started':self.request+=1
                phase='inference '+phase
            else:phase='forensic operation '+phase
        elif kind=='checkpoint':self.counts['checkpoints']=event['count'];phase='automatic checkpoint'
        elif kind=='paused':phase='paused'
        elif kind=='completion_assessment':phase='final response assessed; coverage is not proven complete'
        else:return
        counters=' '.join(f'{k}={v}' for k,v in self.counts.items())
        line=f'{self.clock()-self.started:.1f}s request={self.request} phase={phase} last={self.last} {counters}'
        print(line,file=self.stream,flush=True)
        if self.log:print(line,file=self.log,flush=True)

    def close(self):
        if self.log:self.log.close()

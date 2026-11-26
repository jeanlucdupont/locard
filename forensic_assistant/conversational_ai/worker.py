"""Private read-view worker using the existing parent containment protocol."""
import json,sys,time
from pathlib import Path
if __package__ in (None,''):sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from forensic_assistant.investigation_ai.case import ReadView
from forensic_assistant.artifacts.worker import limit_memory
from forensic_assistant.conversational_ai.contracts import check
from forensic_assistant.conversational_ai.tools import Tools


def serve():
    import os
    memory=limit_memory();view=None;scope=None;adapter=None;calls=0
    try:
        for line in sys.stdin.buffer:
            if len(line)>512*1024:break
            try:
                request=json.loads(line)
                if scope is None:
                    config=request['config'];scope=config['scope'];check(scope,config['case_path'])
                    result=dict(ready=True,worker_pid=os.getpid())
                else:
                    check(scope,config['case_path'])
                    deadline=time.monotonic()+min(request['seconds'],scope['limits']['tool_seconds'])
                    if request['operation']=='chat_init':
                        if view is not None:raise ValueError('View already initialized')
                        view=ReadView(config['case_path'],deadline);adapter=Tools(view.db,scope)
                        result=dict(result={'ready':True},evidence_state=view.state)
                    else:
                        if view is None:raise ValueError('View unavailable')
                        view.check_identity();view.deadline(deadline)
                        if request['operation']=='check':value={'checked':True}
                        else:
                            calls+=1
                            if calls>scope['limits']['operations']:raise ValueError('Operation limit reached')
                            value=adapter.execute(request['operation'],request['arguments'])
                        view.check_identity()
                        result=dict(result=value,evidence_state=view.state)
                raw=json.dumps(result,ensure_ascii=True).encode()
                if len(raw)>scope['limits']['result_bytes']+1024:raise ValueError('Result byte limit reached; narrow query or inspection page')
            except Exception as exc:
                # Never serialize raw exception text from evidence/SQLite.
                allowed=('ValueError','TypeError','KeyError','OperationalError','DatabaseError')
                raw=json.dumps(dict(error='CONVERSATIONAL_TOOL_REJECTED',error_type=type(exc).__name__ if type(exc).__name__ in allowed else 'Other')).encode()
            sys.stdout.buffer.write(raw+b'\n');sys.stdout.buffer.flush()
    finally:
        if view:view.close()

if __name__=='__main__':serve()

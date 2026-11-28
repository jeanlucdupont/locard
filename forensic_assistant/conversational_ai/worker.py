"""Pinned read-view worker with operation-scoped cooperative SQLite cancellation."""
import json,sys,time,threading,queue,sqlite3
from pathlib import Path
if __package__ in (None,''):sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from forensic_assistant.investigation_ai.case import ReadView
from forensic_assistant.artifacts.worker import limit_memory
from forensic_assistant.conversational_ai.contracts import check
from forensic_assistant.conversational_ai.tools import Tools


def serve():
    import os
    limit_memory();view=None;scope=None;adapter=None;calls=0
    requests=queue.Queue(maxsize=2);cancel=threading.Event();lock=threading.Lock()
    current={'id':None};pending=set()
    def reader():
        try:
            while line:=sys.stdin.buffer.readline(512*1024+2):
                if len(line)>512*1024:break
                request=json.loads(line)
                if request.get('operation')=='cancel':
                    with lock:
                        if request.get('operation_id')==current['id']:
                            cancel.set()
                            if view and view.db:view.db.interrupt()
                        elif len(pending)<2:pending.add(request.get('operation_id'))
                else:requests.put(request)
        except (ValueError,OSError):pass
        finally:requests.put(None)
    threading.Thread(target=reader,daemon=True).start()
    try:
        while (request:=requests.get()) is not None:
            identity=request.get('operation_id');stage='authorization';deadline=None
            with lock:
                current['id']=identity;cancel.clear()
                if identity in pending:pending.remove(identity);cancel.set()
            previous=None
            try:
                if scope is None:
                    config=request['config'];scope=config['scope'];check(scope,config['case_path'])
                    result=dict(ready=True,worker_pid=os.getpid())
                else:
                    check(scope,config['case_path'])
                    seconds=request.get('seconds');configured=scope['limits']['tool_seconds']
                    limits=[s for s in (seconds,configured) if s is not None]
                    if any(type(s) not in (int,float) or s<=0 for s in limits):raise ValueError('Invalid deadline')
                    deadline=time.monotonic()+min(limits) if limits else None
                    def interrupted():return cancel.is_set() or (deadline is not None and time.monotonic()>=deadline)
                    if request['operation']=='chat_init':
                        stage='read_view'
                        if view is not None:raise ValueError('View already initialized')
                        view=ReadView(config['case_path'],deadline or float('inf'));adapter=Tools(view.db,scope,profile=[] if config.get('_profile') is True else None,read_view=view)
                        from forensic_assistant.conversational_ai.progress import availability
                        inventory=availability(adapter,min(deadline or float('inf'),time.monotonic()+2),cancel)
                        if cancel.is_set() or (deadline is not None and time.monotonic()>=deadline):raise sqlite3.OperationalError('interrupted')
                        view.check_identity()
                        result=dict(result={'ready':True,'artifact_availability':inventory},evidence_state=view.state)
                    else:
                        stage='integrity'
                        if view is None:raise ValueError('View unavailable')
                        view.check_identity();view.db.set_progress_handler(lambda:int(interrupted()),1000)
                        if interrupted():raise sqlite3.OperationalError('interrupted')
                        if request['operation']=='check':adapter.computation=None;value={'checked':True}
                        else:
                            calls+=1
                            if scope['limits']['operations'] is not None and calls>scope['limits']['operations']:
                                stage='authorization';raise ValueError('Operation limit reached')
                            # Failed/undelivered pages never grant new verification authority.
                            previous=(adapter.known,adapter.disclosed)
                            adapter.known=set(adapter.known)
                            adapter.disclosed={k:dict(v) for k,v in adapter.disclosed.items()}
                            if adapter.profile is not None:adapter.profile.clear()
                            adapter.computation=None
                            def check_processing():
                                if interrupted():raise sqlite3.OperationalError('interrupted')
                            def progress_processing(value):
                                check_processing()
                                raw_progress=json.dumps(dict(operation_id=identity,progress=value)).encode()+b'\n'
                                sys.stdout.buffer.write(raw_progress);sys.stdout.buffer.flush()
                            adapter.cancel_check=check_processing;adapter.progress=progress_processing
                            stage='query'
                            value=adapter.execute(request['operation'],request['arguments'])
                        if interrupted():raise sqlite3.OperationalError('interrupted')
                        stage='integrity';view.check_identity()
                        result=dict(result=value,evidence_state=view.state)
                        if adapter.profile is not None:result['profile']=adapter.profile
                        if adapter.computation is not None:result['computation']=adapter.computation
                    result['operation_id']=identity
                stage='projection'
                raw=json.dumps(result,ensure_ascii=True,allow_nan=False).encode()
                if len(raw)>scope['limits']['result_bytes']+1024:raise ValueError('Result byte limit')
            except Exception as exc:
                if adapter and adapter.population_cache:adapter.population_cache.clear(invalid=stage in ('integrity','read_view','authorization'))
                if previous:adapter.known,adapter.disclosed=previous
                code=('ANALYST_CANCELLED' if cancel.is_set() else
                      'OPERATION_DEADLINE' if deadline is not None and time.monotonic()>=deadline else
                      'RESOURCE_PROTECTION' if isinstance(exc,MemoryError) else
                      'AUTHORIZATION_FAILURE' if stage=='authorization' else
                      'EVIDENCE_INTEGRITY' if stage in ('integrity','read_view') else
                      'DATABASE_QUERY_ERROR' if isinstance(exc,sqlite3.Error) else
                      'RESULT_PROJECTION' if stage=='projection' else 'TOOL_REJECTED')
                healthy=False
                if view:
                    view.db.set_progress_handler(None,0)
                    try:view.check_identity();healthy=True
                    except (ValueError,OSError):pass
                healthy=healthy and code not in ('AUTHORIZATION_FAILURE','EVIDENCE_INTEGRITY','RESOURCE_PROTECTION')
                from forensic_assistant.conversational_ai.operation_diagnostics import failure_detail
                raw=json.dumps(dict(error=code,validation_detail=failure_detail(exc),operation_id=identity,stage=stage,
                                    recoverable=healthy,evidence_state=view.state if healthy else None)).encode()
            finally:
                if view:view.db.set_progress_handler(None,0)
                with lock:current['id']=None
            sys.stdout.buffer.write(raw+b'\n');sys.stdout.buffer.flush()
    finally:
        if adapter and adapter.population_cache:adapter.population_cache.clear()
        if view:view.close()

if __name__=='__main__':serve()

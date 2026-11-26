"""Provider-free read-only retrieval profile; no case writes or initialization."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from forensic_assistant.conversational_ai.activity import Activity
from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
from forensic_assistant.conversational_ai.tools import Tools,exclusive_end
from forensic_assistant.conversational_ai.supervision import ChatWorker
from forensic_assistant.retrieval.evidence import EvidenceQueries


def emit(e):
    print(f"{e['operation']}: {e['status']} {e['elapsed_seconds']:.1f}s; computational progress unavailable",file=sys.stderr,flush=True)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db');p.add_argument('--source');p.add_argument('--start');p.add_argument('--end',help='Exclusive end')
    p.add_argument('--artifact',choices=FAMILIES,default='browser');p.add_argument('--limit',type=int,default=20)
    p.add_argument('--mode',choices=('all','exact','bounded','adapter','worker'),default='all')
    p.add_argument('--tool-seconds',type=int);p.add_argument('--progress-seconds',type=float,default=30)
    p.add_argument('--demo-seconds',type=float,help='Synthetic waiting only; no database or provider access')
    args=p.parse_args()
    if args.demo_seconds is not None:
        try:
            with Activity(emit,'Synthetic operation',interval=args.progress_seconds):time.sleep(args.demo_seconds)
        except KeyboardInterrupt:print('Synthetic operation interrupted; no case was opened.')
        return
    if not all((args.db,args.source,args.start,args.end)):p.error('--db, --source, --start and --end required')
    scope=authorize(args.db,[args.source],args.start,args.end,list(FAMILIES),'openai','provider-free-diagnostic',{'tool_seconds':args.tool_seconds})
    query=dict(artifact=args.artifact,source_scope=args.source,start=scope['start'],end=exclusive_end(scope['end']),limit=args.limit)
    modes=('exact','bounded','adapter','worker') if args.mode=='all' else (args.mode,)
    for mode in modes:
        profile=[];started=time.monotonic();count=[0];worker=None;db=None
        try:
            with Activity(emit,mode+' retrieval',interval=args.progress_seconds):
                if mode=='worker':
                    worker=ChatWorker(dict(case_path=scope['case'],scope=scope,_transaction_view=True,_profile=True))
                    worker.call('chat_init',seconds=60)
                    ready=time.monotonic()
                    response=worker.call('search_evidence',{'artifact':args.artifact,'limit':args.limit},seconds=args.tool_seconds)
                    result=response['result'];profile=response.get('profile',[])
                    profile.append(dict(phase='worker_startup',seconds=ready-started))
                else:
                    db=sqlite3.connect(Path(args.db).resolve().as_uri()+'?mode=ro',uri=True)
                    db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
                    if args.tool_seconds is not None:
                        deadline=time.monotonic()+args.tool_seconds;db.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
                    db.set_trace_callback(lambda sql:count.__setitem__(0,count[0]+1))
                    if mode=='adapter':result=Tools(db,scope,profile=profile).execute('search_evidence',{'artifact':args.artifact,'limit':args.limit})
                    else:result=EvidenceQueries(db,profile=profile).search(**query,exact_count=mode=='exact').as_dict()
            ids=[r.get('evidence_id',r.get('id')) for r in result['records']]
            print(json.dumps(dict(mode=mode,seconds=time.monotonic()-started,records=len(ids),total=result.get('total'),
                has_more=result.get('has_more'),ordered_ids_sha256=hashlib.sha256(json.dumps(ids).encode()).hexdigest(),
                sql_statements=count[0] if db else None,profile=profile),indent=2),flush=True)
        finally:
            if db:db.close()
            if worker:worker.close()

if __name__=='__main__':main()

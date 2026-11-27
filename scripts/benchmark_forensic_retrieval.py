"""Provider-free scoped retrieval benchmark. Never initializes or modifies a case."""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sys
import sqlite3
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES,check
from forensic_assistant.conversational_ai.tools import Tools,leaves,exclusive_end
from forensic_assistant.conversational_ai.activity import Activity
from forensic_assistant.investigation_ai.case import ReadView
from forensic_assistant.retrieval.evidence import EvidenceQueries


def run(a):
 scope=authorize(a.db,[a.source],a.start,a.end,list(FAMILIES),'openai','provider-free-diagnostic',{'tool_seconds':a.seconds})
 reports=[]
 with closing(ReadView(a.db,time.monotonic()+a.seconds if a.seconds else float('inf'))) as view:
  profile=[];tools=Tools(view.db,scope,profile=profile if a.diagnostics else None)
  preparation=0
  if a.operation in ('show','verify'):
   if not a.evidence_id:raise ValueError('--evidence-id required')
   started=time.monotonic();record=tools.original(a.evidence_id,known=False)
   # Explicit analyst inspection establishes original disclosure, not model text.
   if a.operation=='verify':
    if a.field is None or a.value_json is None:raise ValueError('--field and --value-json required')
    index=next((i for i,(p,v) in enumerate(leaves(record)) if p==a.field),None)
    if index is None:raise ValueError('Original field pointer not found')
    tools.page(record,index,1)
   else:tools.page(record,0,1)
   preparation=time.monotonic()-started
  for repetition in range(a.repeat):
   check(scope,a.db);view.check_identity();view.deadline(time.monotonic()+a.seconds if a.seconds else float('inf'));profile.clear()
   query={k:getattr(a,k) for k in ('artifact','registry_key','registry_key_contains','value_name','value_name_contains','path','object_basename','hostname','limit','offset') if getattr(a,k) is not None}
   if 'object_basename' in query and query.get('offset')==0:query.pop('offset')
   started=time.monotonic()
   with Activity(lambda e:print(f"{e['operation']}: {e['status']} {e['elapsed_seconds']:.1f}s; computational progress unavailable",file=sys.stderr),a.operation):
    if a.operation=='show':result=tools.execute('show_evidence',dict(evidence_id=a.evidence_id,limit=min(a.limit,40),offset=a.offset))
    elif a.operation=='verify':result=tools.execute('verify_observation',dict(evidence_id=a.evidence_id,field=a.field,value_json=a.value_json,**({'timestamp_meaning':a.timestamp_meaning} if a.timestamp_meaning else {})))
    elif a.exact_count:
     # Same scope construction and canonical retained-field hydration as Tools.
     result=EvidenceQueries(view.db,hydrate=lambda eid:tools.original(eid,known=False,_scoped=True),profile=profile if a.diagnostics else None).search(source_scope=a.source,start=scope['start'],end=exclusive_end(scope['end']),timeline=a.operation=='timeline',exact_count=True,**query).as_dict()
    else:result=tools.execute('timeline' if a.operation=='timeline' else 'search_evidence',query)
   elapsed=time.monotonic()-started;view.check_identity()
   serial=time.monotonic();encoded=json.dumps(result,sort_keys=True,ensure_ascii=True,allow_nan=False).encode();serialization=time.monotonic()-serial
   rows=result.get('records',[]);ids=[r.get('evidence_id',r.get('id')) for r in rows]
   if result.get('evidence_id'):ids=[result['evidence_id']]
   reports.append(dict(repetition=repetition+1,operation=a.operation,seconds=elapsed,serialization_seconds=serialization,serialized_bytes=len(encoded),
    result_sha256=hashlib.sha256(encoded).hexdigest(),records_returned=len(ids),evidence_ids=ids,verified=result.get('verified'),
    coverage={k:v for k,v in result.items() if k in ('total','total_exact','total_is_exact','total_lower_bound','has_more','truncated','next_offset','content_search','object_search','scope','limitations','field_limit_reached')},
    exact_count_requested=a.exact_count,total_exact=(isinstance(result.get('total'),int) if a.operation in ('search','timeline') else None),read_view=view.state,profile=list(profile) if a.diagnostics else None))
 return dict(contract='forensic-retrieval-benchmark-v1',preparation_seconds=preparation,reports=reports,
   limitations=['Provider-free direct production read view; this script does not measure worker startup or IPC. Production worker safeguards remain unchanged.',
    'First/repeated measurements are not guaranteed cold-cache measurements. No OS cache flushing is performed.',
    'Scope/source/time checks and SQL phases overlap; nested phase durations must not be added together.',
    'No forensic values or SQL parameter values are included in phase diagnostics. Evidence IDs and result digests are sensitive derived metadata.'])


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('db','source','start','end'):p.add_argument('--'+name,required=True)
 p.add_argument('--operation',choices=('search','timeline','show','verify'),required=True)
 p.add_argument('--artifact',choices=FAMILIES,default='registry')
 for name in ('registry-key','registry-key-contains','value-name','value-name-contains','path','object-basename','hostname','evidence-id','field','value-json','timestamp-meaning'):p.add_argument('--'+name)
 p.add_argument('--repeat',type=int,default=1);p.add_argument('--limit',type=int,default=10);p.add_argument('--offset',type=int,default=0)
 p.add_argument('--seconds',type=int);p.add_argument('--exact-count',action='store_true');p.add_argument('--diagnostics',action='store_true');p.add_argument('--json',action='store_true')
 a=p.parse_args()
 if a.repeat<1:p.error('--repeat must be positive')
 if a.exact_count and (a.operation not in ('search','timeline') or a.object_basename):p.error('--exact-count requires an ordinary search or timeline')
 try:r=run(a)
 except (ValueError,OSError,sqlite3.Error,KeyboardInterrupt) as exc:print(json.dumps(dict(complete=False,error=type(exc).__name__)),file=sys.stderr);return 2
 if a.json:print(json.dumps(r,indent=2,ensure_ascii=True))
 else:
  for row in r['reports']:
   print(f"{row['operation']} repeat {row['repetition']}: {row['seconds']:.6f}s; {row['records_returned']} records; verified={row['verified']}")
   print(json.dumps(row,ensure_ascii=True))
  for limitation in r['limitations']:print(limitation)
 return 0
if __name__=='__main__':raise SystemExit(main())

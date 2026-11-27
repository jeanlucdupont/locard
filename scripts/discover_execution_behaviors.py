"""Provider-free production execution discovery in a protected read-view worker."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
from forensic_assistant.conversational_ai.supervision import ChatWorker,ConversationWorkerError
from forensic_assistant.terminal import safe_span_text
from forensic_assistant.detections.execution_features import DEFINITIONS


def render(result):
    lines=['Execution behaviors — investigative leads, not findings']
    for r in result['records']:
        lines.append(f"{r['category']} | {r['kind']} | {r['count']} retained observations | score {r.get('score',r.get('priority',{}).get('score'))}")
        lines.append('  Group: '+r['group_id']);lines.append('  Evidence: '+r['evidence_id'])
        lines.append('  '+r.get('meaning',result.get('shared',{}).get('meanings',{}).get(r['kind'],'')));lines.append('  Features: '+', '.join(r['features']))
        for f in r.get('original_fields',r.get('previews',[])):
            lines.append('  '+f.get('name',f['field'])+': '+str(f['value'])+(' [truncated]' if f['truncated'] else '')+(' [redacted]' if f['redacted'] else ''))
        if r.get('decoding'):lines.append('  Derived static decoding: '+json.dumps(r['decoding'],ensure_ascii=True))
        lines.append('  Frequency: '+json.dumps(r['frequency'],ensure_ascii=True))
    lines+=['Coverage: '+json.dumps(result['coverage'],ensure_ascii=True),'Statistics: '+json.dumps(result['statistics'],ensure_ascii=True),'Next offset: '+str(result['next_offset'])]
    if result.get('shared',{}).get('host_contexts'):lines.append('Host contexts: '+json.dumps(result['shared']['host_contexts'],ensure_ascii=True))
    if result.get('categories'):lines.append('Category inventory: '+json.dumps(result['categories'],ensure_ascii=True))
    lines.extend(str(k)+': '+v for k,v in result.get('shared',{}).items() if isinstance(v,str))
    lines.extend('Limitation: '+s for s in result['limitations'])
    return safe_span_text('\n'.join(lines))


def measure(worker,name,args,seconds):
    started=time.monotonic();reply=worker.call('discover_execution_behaviors',args,seconds=seconds);value=reply['result']
    # Population IDs intentionally bind distinct views; compare the complete remaining payload.
    comparable={k:v for k,v in value.items() if k!='population_id'}
    raw=json.dumps(comparable,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()
    count=len(value['records']);size=len(json.dumps(value,ensure_ascii=True,separators=(',',':')).encode())
    return dict(name=name,arguments=args,elapsed_seconds=time.monotonic()-started,result_digest=hashlib.sha256(raw).hexdigest(),
        computation=reply.get('computation'),candidate_count=count,serialized_bytes=size,bytes_per_candidate=size/count if count else None,
        result=value)


def sequence(worker,args,seconds):
    first=measure(worker,'initial',args,seconds);r=first['result'];operations=[first]
    base={k:v for k,v in args.items() if k not in ('offset','category_filter','feature','group_id')}
    operations.append(measure(worker,'next_page',dict(base,offset=r['next_offset'] if r['next_offset'] is not None else r['coverage']['matching_groups']),seconds))
    categories=r.get('categories',[])
    if categories:operations.append(measure(worker,'category',dict(base,category_filter=min(categories,key=lambda c:(c['groups'],c['category_filter']))['category_filter']),seconds))
    else:operations.append(dict(name='category',skipped='No compact category inventory'))
    features=sorted(r['statistics']['feature_prevalence'])
    if features:operations.append(measure(worker,'feature',dict(base,feature=features[0]),seconds))
    else:operations.append(dict(name='feature',skipped='No supported features'))
    if r['records']:operations.append(measure(worker,'members',dict(base,group_id=r['records'][0]['group_id']),seconds))
    else:operations.append(dict(name='members',skipped='No candidates'))
    operations.append(measure(worker,'repeat',args,seconds))
    operations.append(measure(worker,'detailed',dict(base,presentation='detailed'),seconds))
    return dict(contract='execution-sequence-diagnostic-v1',operations=operations,
        repeat_equal=first['result_digest']==operations[-2]['result_digest'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('db','source','start','end'):p.add_argument('--'+name,required=True)
    p.add_argument('--artifact',choices=('evtx','registry','defender','prefetch'));p.add_argument('--mode',choices=('exact','behavioral'),default='behavioral')
    p.add_argument('--feature',choices=sorted(DEFINITIONS));p.add_argument('--category',dest='category_filter')
    for name in ('executable','parent','hostname','group-id'):p.add_argument('--'+name)
    p.add_argument('--limit',type=int,default=10);p.add_argument('--offset',type=int,default=0);p.add_argument('--tool-seconds',type=int)
    p.add_argument('--presentation',choices=('compact','detailed'),default='compact')
    p.add_argument('--sequence',action='store_true',help='Seven compatible operations in one protected read view')
    p.add_argument('--compare-fresh',action='store_true',help='Recompute sequence without population reuse in a separate protected worker')
    p.add_argument('--json',action='store_true');a=p.parse_args()
    if a.compare_fresh and not a.sequence:p.error('--compare-fresh requires --sequence')
    scope=authorize(a.db,[a.source],a.start,a.end,list(FAMILIES),'openai','provider-free-diagnostic',{'tool_seconds':a.tool_seconds})
    args={k:getattr(a,k) for k in ('artifact','mode','feature','category_filter','executable','parent','hostname','group_id','limit','offset','presentation') if getattr(a,k) is not None}
    started=time.monotonic()
    def progress(event):print(f"{event['status']}: {event['processed']} records; {event['groups']} groups; {event['elapsed_seconds']:.1f}s",file=sys.stderr,flush=True)
    try:
        with ChatWorker(dict(case_path=scope['case'],scope=scope,_transaction_view=True)) as worker:
            worker.progress=progress;worker.call('chat_init',seconds=60)
            result=sequence(worker,args,a.tool_seconds) if a.sequence else worker.call('discover_execution_behaviors',args,seconds=a.tool_seconds)
        if a.compare_fresh:
            checks=[]
            for operation in result['operations']:
                if 'arguments' not in operation:continue
                with ChatWorker(dict(case_path=scope['case'],scope=scope,_transaction_view=True)) as fresh:
                    fresh.call('chat_init',seconds=60)
                    repeated=measure(fresh,operation['name'],operation['arguments'],a.tool_seconds)
                checks.append(dict(operation=operation['name'],equal=operation['result_digest']==repeated['result_digest'],fresh_seconds=repeated['elapsed_seconds']))
            result['fresh_comparisons']=checks
        result['elapsed_seconds']=time.monotonic()-started
        print(json.dumps(result,ensure_ascii=True,indent=2) if a.json else (json.dumps(result,ensure_ascii=True,indent=2) if a.sequence else render(result['result']))+f"\nElapsed: {result['elapsed_seconds']:.3f}s")
        return 0
    except ConversationWorkerError as exc:
        print(json.dumps(dict(error=exc.code,analysis_complete=False,counts_complete=False,read_view_confirmed=exc.integrity,
                             elapsed_seconds=time.monotonic()-started,limitation='No complete population or absence claim; retry with a narrower scope or a larger analyst budget.')))
        return 2

if __name__=='__main__':raise SystemExit(main())

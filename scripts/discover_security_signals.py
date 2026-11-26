"""Read-only security discovery using the protected production worker; no AI calls."""
import argparse
import json
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
from forensic_assistant.conversational_ai.supervision import ChatWorker,ConversationWorkerError
from forensic_assistant.conversational_ai.activity import Activity,description
from forensic_assistant.detections.discovery import OVERVIEWS
from forensic_assistant.terminal import safe_span_text


def render(result):
    lines=['Local security discovery — leads, not findings']
    for item in result['records']:
        lines.append('  '+str(item.get('kind',result.get('overview')))+' | '+str(item.get('category',', '.join(k+'='+str(v['value'])+(' [truncated]' if v['truncated'] else '') for k,v in item.get('group',{}).items()))))
        if item.get('interpretation'):lines.append('    '+item['interpretation']['meaning'])
        for match in item.get('locard_rule_matches',[]):lines.append('    '+match['rule_id']+': '+match['reason'])
        for field in item.get('original_fields',[]):
            lines.append('    '+field.get('name',field['field'])+': '+str(field['value'])+(' [truncated]' if field['truncated'] else '')+(' [redacted]' if field['redacted'] else ''))
        if 'count' in item:lines.append('    Records: '+str(item['count'])+'; evidence ID is a representative only')
        lines.append('    Evidence: '+item['evidence_id'])
    lines.append('Coverage: '+json.dumps(result['coverage'],ensure_ascii=False))
    if result.get('rule_coverage'):lines.append('Rule coverage: '+json.dumps(result['rule_coverage']))
    if result.get('unsupported_semantics'):lines.append('Unsupported semantics: '+', '.join(result['unsupported_semantics']))
    lines.extend('Limitation: '+x for x in result['limitations'])
    return safe_span_text('\n'.join(lines))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('db','source','start','end'):p.add_argument('--'+name,required=True,help='Exclusive end' if name=='end' else None)
    p.add_argument('--category',choices=('all','recorded','observations','heuristics'),default='all')
    p.add_argument('--overview',choices=tuple(OVERVIEWS))
    p.add_argument('--limit',type=int,default=5);p.add_argument('--offset',type=int,default=0)
    p.add_argument('--candidate-limit',type=int,default=200)
    p.add_argument('--tool-seconds',type=int);p.add_argument('--progress-seconds',type=int,default=30)
    p.add_argument('--json',action='store_true')
    args=p.parse_args()
    scope=authorize(args.db,[args.source],args.start,args.end,list(FAMILIES),'openai','provider-free-diagnostic',{'tool_seconds':args.tool_seconds})
    operation='activity_overview' if args.overview else 'discover_security_signals'
    arguments=dict(limit=args.limit,offset=args.offset)
    if args.overview:arguments['kind']=args.overview
    else:arguments.update(category=args.category,candidate_limit=args.candidate_limit)
    def emit(event):
        print(event['operation']+': '+event['status']+f" ({event['elapsed_seconds']:.1f}s); computational progress unavailable; Ctrl+C interrupts",file=sys.stderr,flush=True)
    start=time.monotonic()
    try:
        with ChatWorker(dict(case_path=scope['case'],scope=scope,_transaction_view=True)) as worker:
            worker.call('chat_init',seconds=60)
            with Activity(emit,description(operation,arguments),interval=args.progress_seconds):
                response=worker.call(operation,arguments,seconds=args.tool_seconds)
        if args.json:print(json.dumps({**response,'elapsed_seconds':time.monotonic()-start},ensure_ascii=True,indent=2))
        else:
            print(render(response['result']));print(f'Elapsed: {time.monotonic()-start:.2f} seconds')
        return 0
    except ConversationWorkerError as exc:
        print(json.dumps(dict(error=exc.code,read_view_confirmed=exc.integrity,elapsed_seconds=time.monotonic()-start)) if args.json else 'Discovery unsuccessful: '+exc.code+'; no absence conclusion.',file=sys.stdout)
        return 2

if __name__=='__main__':raise SystemExit(main())

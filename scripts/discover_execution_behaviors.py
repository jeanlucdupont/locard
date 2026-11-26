"""Provider-free production execution discovery in a protected read-view worker."""
import argparse
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
        lines.append(f"{r['category']} | {r['kind']} | {r['count']} retained observations | score {r['priority']['score']}")
        lines.append('  Group: '+r['group_id']);lines.append('  Evidence: '+r['evidence_id'])
        lines.append('  '+r['meaning']);lines.append('  Features: '+', '.join(r['features']))
        for f in r['original_fields']:
            lines.append('  '+f.get('name',f['field'])+': '+str(f['value'])+(' [truncated]' if f['truncated'] else '')+(' [redacted]' if f['redacted'] else ''))
        if r['decoding']:lines.append('  Derived static decoding: '+json.dumps(r['decoding'],ensure_ascii=True))
        lines.append('  Frequency: '+json.dumps(r['frequency'],ensure_ascii=True))
    lines+=['Coverage: '+json.dumps(result['coverage'],ensure_ascii=True),'Statistics: '+json.dumps(result['statistics'],ensure_ascii=True),'Next offset: '+str(result['next_offset'])]
    lines.extend('Limitation: '+s for s in result['limitations'])
    return safe_span_text('\n'.join(lines))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('db','source','start','end'):p.add_argument('--'+name,required=True)
    p.add_argument('--artifact',choices=('evtx','registry','defender','prefetch'));p.add_argument('--mode',choices=('exact','behavioral'),default='behavioral')
    p.add_argument('--feature',choices=sorted(DEFINITIONS));p.add_argument('--category',dest='category_filter')
    for name in ('executable','parent','hostname','group-id'):p.add_argument('--'+name)
    p.add_argument('--limit',type=int,default=5);p.add_argument('--offset',type=int,default=0);p.add_argument('--tool-seconds',type=int)
    p.add_argument('--json',action='store_true');a=p.parse_args()
    scope=authorize(a.db,[a.source],a.start,a.end,list(FAMILIES),'openai','provider-free-diagnostic',{'tool_seconds':a.tool_seconds})
    args={k:getattr(a,k) for k in ('artifact','mode','feature','category_filter','executable','parent','hostname','group_id','limit','offset') if getattr(a,k) is not None}
    started=time.monotonic()
    def progress(event):print(f"{event['status']}: {event['processed']} records; {event['groups']} groups; {event['elapsed_seconds']:.1f}s",file=sys.stderr,flush=True)
    try:
        with ChatWorker(dict(case_path=scope['case'],scope=scope,_transaction_view=True)) as worker:
            worker.progress=progress;worker.call('chat_init',seconds=60)
            result=worker.call('discover_execution_behaviors',args,seconds=a.tool_seconds)
        result['elapsed_seconds']=time.monotonic()-started
        print(json.dumps(result,ensure_ascii=True,indent=2) if a.json else render(result['result'])+f"\nElapsed: {result['elapsed_seconds']:.3f}s")
        return 0
    except ConversationWorkerError as exc:
        print(json.dumps(dict(error=exc.code,analysis_complete=False,counts_complete=False,read_view_confirmed=exc.integrity,
                             elapsed_seconds=time.monotonic()-started,limitation='No complete population or absence claim; retry with a narrower scope or a larger analyst budget.')))
        return 2

if __name__=='__main__':raise SystemExit(main())

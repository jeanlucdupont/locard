"""Provider-free streaming Defender file inventory and parser diagnostic. No writes to inputs."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from forensic_assistant.artifacts.defender import supported,parse
from forensic_assistant.artifacts.sqlite_recovery import regular
from forensic_assistant.ingest.evtx import digest
from forensic_assistant.terminal import safe_span_text


def inspect(path,*,inventory=False,ordinal=None,contains=None,limit=3,time_policy='format-utc'):
    regular(path);sha=digest(path);result=dict(path=str(path),bytes=path.stat().st_size,sha256=sha,supported=supported(path))
    if inventory or not result['supported']:return result
    categories=Counter();statuses=Counter();times=Counter();examples=[];count=0
    for pack in parse(path,sha,defender_time_policy=time_policy):
        detail=pack['detail'];loc=json.loads(pack['record']['locator_json'])
        categories[detail['category']]+=1;statuses[detail['parsing_status']]+=1
        for stamp in pack['timestamps']:times[stamp['normalization_status']]+=1
        if (ordinal is None or ordinal==loc['ordinal']) and (contains is None or contains in detail['text']):
            count+=1
            if len(examples)<limit:
                examples.append(dict(evidence_id=pack['record']['evidence_id'],locator=loc,timestamps=pack['timestamps'],detail=detail))
    result.update(categories=dict(categories),parsing=dict(statuses),timestamp_statuses=dict(times),matched_records=count,examples=examples,
                  source_unchanged=digest(path)==sha)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path');parser.add_argument('--inventory',action='store_true')
    parser.add_argument('--ordinal',type=int);parser.add_argument('--contains');parser.add_argument('--limit',type=int,default=3)
    parser.add_argument('--time-policy',default='format-utc')
    parser.add_argument('--json',action='store_true');args=parser.parse_args()
    if not 0<=args.limit<=20:parser.error('limit must be 0..20')
    from forensic_assistant.investigation_ai.storage import local_path
    root=local_path(Path(args.path).absolute());regular(root) if root.is_file() else None
    paths=[root] if root.is_file() else sorted(root.iterdir());started=time.monotonic();failed=False
    try:
        for path in paths:
            if path.is_dir():continue
            begin=time.monotonic()
            try:result=inspect(path,inventory=args.inventory,ordinal=args.ordinal,contains=args.contains,limit=args.limit,time_policy=args.time_policy)
            except (ValueError,OSError) as exc:result=dict(path=str(path),error=type(exc).__name__+': '+str(exc))
            failed=failed or 'error' in result or result.get('source_unchanged') is False
            result['elapsed_seconds']=round(time.monotonic()-begin,3)
            if args.json:print(json.dumps(result,ensure_ascii=True))
            else:
                print(safe_span_text(str(path)))
                for key in ('bytes','sha256','supported','categories','parsing','timestamp_statuses','matched_records','source_unchanged','error','elapsed_seconds'):
                    if key in result:print(safe_span_text('  '+key+': '+str(result[key])))
                for sample in result.get('examples',[]):
                    print(safe_span_text('  '+sample['evidence_id']+' '+str(sample['locator'])))
                    print(safe_span_text(sample['detail']['text']))
        print(f'Total elapsed: {time.monotonic()-started:.2f}s',file=sys.stderr)
        return 2 if failed else 0
    except KeyboardInterrupt:
        print('Cancelled; file inspection incomplete. Sources were opened read-only.',file=sys.stderr);return 130

if __name__=='__main__':raise SystemExit(main())

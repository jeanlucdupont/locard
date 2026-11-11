"""Explicit post-investigation D2 UI. Importing/previewing never dispatches."""
import argparse
import json
from . import d2, d2_execution as service
from .explanation import _safe


def render(result, prepared):
    packet=prepared.packet['content']
    lines=['Ephemeral D2 result — not saved', 'Established by the evidence']
    for leaf in packet['supports']:
        field=leaf['field']
        lines.append('  Recorded '+_safe(field.get('label',field['pointer']))+': '+_safe(str(field['value'])))
        lines.append('    '+_safe(packet['records'][leaf['record_ref']])+' '+_safe(field['pointer']))
    for entry in packet['interpretations']:
        lines.append('  Registered interpretation: '+_safe(entry['interpretation']['text']))
    lines.extend('  Qualification: '+_safe(q) for q in packet['qualifications'])
    if result['status']=='accepted':
        proposals=result['validated']['proposals'];item=proposals[0]['item']
        lines+=['AI explanation — unverified','  '+_safe(item['statement']),
                'Alternative explanations',*['  '+_safe(v) for v in item['alternatives']],
                'What remains unresolved',*['  '+_safe(v) for v in item['assumptions']+item['gaps']+item['limitations']],
                'Suggested next examination','  '+_safe(proposals[1]['item']['statement'])]
        for support in proposals[0]['dependencies']:
            lines.append('  Support: '+_safe(support['evidence_id'])+' '+_safe(support['field']['pointer']))
    else:
        lines+=['No validated AI explanation.', 'Outcome: '+result['status']+' / '+result.get('reason','unknown')]
    lines+=['Coverage and authority', '  '+_safe(prepared.config['provider']+' / '+prepared.config['model']),
            '  Recorded source run: '+packet['source']['run_id'],
            '  Source frontier: '+str(packet['source']['event_head']),
            '  Original S3: '+prepared.history._original['status'],
            '  Only this packet; omitted evidence is not established irrelevant.',
            '  Attempts: '+('unknown (at most 1)' if result['attempts'] is None else str(result['attempts'])+' / 1')+'; no lookups or automatic continuation.',
            '  Provider response: '+('received' if result.get('provider_response_received') is True else 'not observed' if result.get('provider_response_received') is False else 'unknown')+'.',
            '  Provider-reported usage: '+json.dumps(result.get('usage',{}))+' (missing values are unknown).',
            '  Cleanup: '+result['cleanup']+'; elapsed: '+str(result['elapsed_seconds'])+' seconds.']
    return '\n'.join(lines)


def main():
    parser=argparse.ArgumentParser(description='Provider-free D2 preview or explicitly approved one-shot reasoning')
    parser.add_argument('root');parser.add_argument('run_id')
    parser.add_argument('--issue');parser.add_argument('--exploratory',action='store_true')
    parser.add_argument('--execute',action='store_true',help='Ask to authorize one cloud request; no automatic approval')
    parser.add_argument('--json',action='store_true')
    args=parser.parse_args()
    if not args.issue:
        if args.execute:parser.error('--execute requires an explicit --issue')
        preview=d2.open_history(args.root,args.run_id).preview(exploratory=args.exploratory)
        print(json.dumps(preview,ensure_ascii=True) if args.json else d2.render(preview));return
    from forensic_assistant.ai.settings import load
    prepared=service.prepare(args.root,args.run_id,args.issue,load(),exploratory=args.exploratory)
    preview=prepared.preview()
    if not args.execute:
        print(json.dumps(preview,ensure_ascii=True,indent=2));return
    def approve(value):
        print('Authorize one D2 request: '+_safe(value['provider']+' / '+value['model']))
        print('Source: '+value['source']['run_id']+'; frontier: '+str(value['source']['event_head']))
        print('Issue: '+value['issue']['id']+'; packet: '+value['packet_digest'])
        print('Complete request: '+str(value['body_bytes'])+' / 5600 bytes; 1024 output tokens; 60 seconds including cleanup.')
        print('Recorded evidence will be disclosed to this provider. No retries, lookups, fallback or persistence.')
        return input('Authorize this exact request? [y/N] ').strip().casefold()=='y'
    result=service.execute(service.authorize(prepared,approve))
    print(json.dumps(result,ensure_ascii=True) if args.json else render(result,prepared))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError):
        raise SystemExit('D2 request rejected before a validated result. Check source, selection, provider and budget.') from None

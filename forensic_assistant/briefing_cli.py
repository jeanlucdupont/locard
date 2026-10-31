"""Explicit briefing review and approval; no implicit narrative persistence."""
from pathlib import Path
import json
from forensic_assistant import briefing
from forensic_assistant.interactive.console import safe


def configure(commands):
    from forensic_assistant.command_catalog import COMMANDS
    p=commands.add_parser('briefing',help=COMMANDS['briefing'])
    source=p.add_mutually_exclusive_group(required=True)
    source.add_argument('--file',dest='briefing_file',help='UTF-8 analyst narrative, at most 32 KiB; not evidence')
    source.add_argument('--text',dest='briefing_text',help='Short inline analyst narrative; use --file for paragraphs')
    p.add_argument('--correction',dest='briefing_correction',action='append',default=[],help='Separate analyst correction; original wording remains intact')
    p.add_argument('--ai',action='store_true',help='One bounded narrative interpretation using the configured provider; no tools')
    p.add_argument('--allow-cloud',action='store_true',help='Explicitly authorize disclosure of this original narrative and indicator list to the configured cloud provider')
    p.add_argument('--discover',action='store_true',help='Execute approved lead lookups; requires --approve, --artifact, --start and --end')
    p.add_argument('--approve',action='append',default=[],metavar='LEAD_ID',help='Approve exactly this reviewed lead; repeat for at most six leads')
    p.add_argument('--artifact',choices=briefing.ARTIFACTS,help='Search only this explicitly selected artifact family')
    p.add_argument('--start',help='Authorized search start with UTC/offset; never inferred from narrative')
    p.add_argument('--end',help='Authorized search end with UTC/offset; maximum 24-hour window')
    p.add_argument('--json',action='store_true',help='Include original narrative, spans, leads, packet and plan; sensitive derived output')


def run(args):
    if args.briefing_file:
        path=Path(args.briefing_file)
        if not path.is_file():raise ValueError('Briefing input must be a regular UTF-8 file.')
        with path.open('rb') as stream:raw=stream.read(briefing.MAX_BYTES+1)
        if len(raw)>briefing.MAX_BYTES:raise ValueError('Briefing file exceeds 32768 bytes.')
        text=raw.decode('utf-8')
    else:text=args.briefing_text
    packet=briefing.extract(text,args.briefing_correction)
    if args.ai:
        from forensic_assistant.ai.backend import ModelBackend
        client=ModelBackend(timeout=45)
        briefing.interpret(packet,client,allow_cloud=args.allow_cloud)
    if args.discover:
        if not all((args.approve,args.artifact,args.start,args.end)):
            raise ValueError('Discovery requires reviewed --approve IDs, --artifact, --start and --end.')
        briefing.discover(packet,args.db,args.approve,args.artifact,args.start,args.end)
    elif args.approve or args.artifact or args.start or args.end:
        raise ValueError('Search options require --discover; review with briefing --file or --text first.')
    return packet


def render(packet):
    lines=['Case briefing analysis — unverified analyst input','', 'Explicit indicators and contextual leads']
    if packet.get('ai_status') in ('success','partial','skipped'):
        lines.insert(1,'AI interpretation: '+packet['ai_status']+' ('+str(len(packet['ai_items']))+' accepted items)')
    for lead in packet['leads']:
        span=lead['occurrences'][0]
        lines.append('  '+safe(lead['id'])+'  '+safe(lead['type'])+': '+safe(span['original']))
        lines.append('    '+safe(lead['classification'])+(' / negated: not eligible for search' if lead['negated'] else '')+
                     ' | '+safe(span['source'])+':'+str(span['start'])+'..'+str(span['end']))
    if packet['ai_items']:
        lines.extend(['','AI interpretations — unverified, not findings'])
        for item in packet['ai_items']:
            lines.append('  '+safe(item['category'])+' ('+safe(item['basis'])+'): '+safe(item['text']))
            lines.append('    Uncertainty: '+safe(item['uncertainty']))
    lines.extend(['','Limitations',*('  - '+safe(v) for v in packet['limitations']+packet['conflicts'])])
    if packet.get('ai_error'):
        error=packet['ai_error']
        lines.append('  AI diagnostic: '+safe(error['category'])+' / '+safe(error['stage']))
        detail=([f"HTTP {error['http_status']}"] if 'http_status' in error else [])
        detail.extend(str(error[k]) for k in ('parameter','rule','provider_category') if k in error)
        if detail:lines.append('  '+' | '.join(safe(v) for v in detail))
        for rejection in error.get('rejected_items',[]):
            lines.append('  Item '+str(rejection['item_index'])+': '+safe(rejection['rule']))
        for entry in error.get('validation',{}).get('errors',[]):
            lines.append('  '+safe(entry['canonical_path'])+': '+safe(entry['validator_keyword']))
    discovery=packet.get('discovery')
    if discovery:
        lines.extend(['','Approved deterministic discovery'])
        for q in discovery['queries']:
            result=q['result'];lines.append('  '+safe(q['lead_id'])+': '+str(len(result['records']))+' records returned')
            for record in result['records']:
                lines.append('    Evidence: '+safe(record['id']))
            for note in result.get('limitations',[]):lines.append('    '+safe(note))
            lines.append('    '+safe(result['coverage']['note']))
        for identity in discovery['unmapped']:lines.append('  '+safe(identity)+': no eligible supported mapping for this artifact; not searched')
        lines.extend('  '+safe(v) for v in discovery['limitations'])
        if packet.get('handoff'):
            lines.extend(['','Reviewable investigation plan', '  '+packet['handoff']['instructions'],
                          '  Original objective remains in inputs.original; use --json for the complete packet.'])
    else:
        lines.extend(['','No evidence searches executed. Review IDs, then use --discover with explicit approvals and time bounds.'])
    return '\n'.join(lines)

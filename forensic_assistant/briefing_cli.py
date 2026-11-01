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
    for action in ('interview', 'wizard', 'show', 'edit', 'analyze'):
        source.add_argument('--'+action, action='store_true', help=('Recommended adaptive briefing interview' if action=='interview' else 'Legacy questionnaire' if action=='wizard' else 'Use the selected case briefing: '+action))
    p.add_argument('--save',action='store_true',help='Explicitly import --file/--text as saved narrative after confirmation')
    p.add_argument('--deterministic',action='store_true',help='Analyze saved briefing without AI')
    p.add_argument('--revision',type=int,help='Required current briefing revision for saved-briefing discovery approval')
    p.add_argument('--correction',dest='briefing_correction',action='append',default=[],help='Separate analyst correction; original wording remains intact')
    p.add_argument('--ai',action='store_true',help='One bounded narrative interpretation using the configured provider; no tools')
    p.add_argument('--allow-cloud',action='store_true',help='Legacy disclosure flag; unnecessary after provider configuration acknowledgment')
    p.add_argument('--discover',action='store_true',help='Execute approved lead lookups; requires --approve, --artifact, --start and --end')
    p.add_argument('--approve',action='append',default=[],metavar='LEAD_ID',help='Approve exactly this reviewed lead; repeat for at most six leads')
    p.add_argument('--artifact',choices=briefing.ARTIFACTS,help='Search only this explicitly selected artifact family')
    p.add_argument('--start',help='Authorized search start with UTC/offset; never inferred from narrative')
    p.add_argument('--end',help='Authorized search end with UTC/offset; maximum 24-hour window')
    p.add_argument('--details',action='store_true',help='Show full provenance, search packets and validation diagnostics')
    p.add_argument('--json',action='store_true',help='Include original narrative, spans, leads, packet and plan; sensitive derived output')


def run(args):
    saved = any(getattr(args, name, False) for name in ('interview','wizard','show','edit','analyze'))
    writing = args.interview or args.wizard or args.edit or args.save
    if args.deterministic and (not args.analyze or args.ai):
        raise ValueError('--deterministic requires --analyze and cannot combine with --ai.')
    if args.save and saved:
        raise ValueError('--save imports --file or --text only.')
    if saved and args.briefing_correction:
        raise ValueError('Edit the saved briefing instead of using transient --correction.')
    if args.save and args.briefing_correction:
        raise ValueError('Import narrative first; corrections are not silently persisted.')
    if (args.interview or args.wizard or args.edit or args.show or args.save) and (args.ai or args.discover or args.approve or args.artifact or args.start or args.end or args.revision):
        raise ValueError('Briefing entry/display cannot combine with analysis or search options.')
    if args.revision is not None and not (args.analyze and args.discover):
        raise ValueError('--revision is for approved discovery of saved content.')
    store = state = revision = None
    if saved or args.save:
        from forensic_assistant.briefing_store import Store, FIELDS, content, sources
        from forensic_assistant import briefing_workflow as workflow
        store=Store(args.db);state=store.load()
        revision=state['revisions'][-1] if state else None
        current=revision['content'] if revision else content(dict.fromkeys(FIELDS,''),'')
        if args.show:return workflow.view(state)
        if writing:
            import sys
            read=getattr(args,'_confirm',None) or (input if sys.stdin.isatty() else None)
            if read is None:raise ValueError('Briefing changes require interactive confirmation.')
            if args.interview:
                from forensic_assistant.briefing_interview import interview
                value=interview(current,read,details=args.details)
            elif args.wizard:
                value=workflow.wizard(current,read)
            elif args.edit:
                value=workflow.edit(store,current,read)
            else:
                value=None  # Explicit import handled after bounded input reading below.
            if not args.save:
                if value is None:return {'kind':'saved_briefing','message':'Briefing unchanged; save cancelled.'}
                return workflow.view(store.save(value,revision['digest'] if revision else None))
        if args.analyze:
            if revision is None:raise ValueError('No saved briefing. Use briefing --interview or --edit first.')
            if args.discover and args.revision != revision['revision']:
                raise ValueError('Review current briefing and explicitly supply its --revision for discovery.')
            packet=briefing.extract_inputs(sources(revision))
            packet['saved_briefing']={k:revision[k] for k in ('revision','digest','modified')}
            packet['saved_briefing']['source_identity']=store.identity
            packet['interview_provenance']=revision['content'].get('interviews',[])
            packet['analyst_source_relations']=[
                {'source':f"interview:{session['id']}:{i+1}", 'purpose':session['purpose'],
                 'question_context':turn['question'], 'question_origin':turn['question_origin'],
                 'corrects':f"interview:{session['id']}:{turn['supersedes']}" if turn['supersedes'] is not None else None}
                for session in packet['interview_provenance'] for i,turn in enumerate(session['turns']) if turn['answer_status']=='answered']
    if not args.analyze:
        if args.briefing_file:
            path=Path(args.briefing_file)
            if not path.is_file():raise ValueError('Briefing input must be a regular UTF-8 file.')
            with path.open('rb') as stream:raw=stream.read(briefing.MAX_BYTES+1)
            if len(raw)>briefing.MAX_BYTES:raise ValueError('Briefing file exceeds 32768 bytes.')
            text=raw.decode('utf-8')
        else:text=args.briefing_text
        if args.save:
            value=content(current['answers'],text,current.get('interviews'))
            print('Import replaces the narrative only; structured answers and earlier revisions remain.')
            print(safe(text))
            if workflow.read_answer(read,'Save imported narrative? [y/N]: ').casefold() not in ('y','yes'):
                return {'kind':'saved_briefing','message':'Briefing unchanged; import cancelled.'}
            return workflow.view(store.save(value,revision['digest'] if revision else None))
        packet=briefing.extract(text,args.briefing_correction)
    use_ai=args.ai
    if args.analyze and not args.deterministic:
        from forensic_assistant.ai import settings
        import os
        config=settings.load()  # validates durable cloud acknowledgment before any request
        use_ai=bool(config['model_path'] and config['executable']) if config['provider']=='local' else bool(os.environ.get(settings.PROVIDERS[config['provider']][1], '').strip())
        if not use_ai:
            packet['limitations'].append('Configured AI is unavailable; deterministic analysis only. No provider request made.')
    if use_ai:
        from forensic_assistant.ai.backend import ModelBackend
        client=ModelBackend(timeout=45)
        briefing.interpret(packet,client,allow_cloud=args.allow_cloud)
    if args.discover:
        if not all((args.approve,args.artifact,args.start,args.end)):
            raise ValueError('Discovery requires reviewed --approve IDs, --artifact, --start and --end.')
        briefing.discover(packet,args.db,args.approve,args.artifact,args.start,args.end)
    elif args.approve or args.artifact or args.start or args.end:
        raise ValueError('Search options require --discover; review this briefing first.')
    if args.analyze:
        store.record_analysis(revision,packet)
        packet['limitations'].append('Only analysis revision/status metadata is saved; this result packet is not cached. Export explicitly if needed.')
    return packet


def render_details(packet):
    lines=['Case briefing analysis — unverified analyst input', 'New analysis for this invocation; --details does not load earlier AI responses.', '', 'Explicit indicators and contextual leads']
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
            if 'source_ids' in item:
                inventory={u['id']:u for u in packet.get('source_units',[])}
                refs=[]
                for identity in item['source_ids']:
                    unit=inventory.get(identity)
                    refs.append(identity+(f" ({unit['source']}:{unit['start']}..{unit['end']})" if unit else ''))
                lines.append('    Sources (analyst text, not evidence): '+safe(', '.join(refs)))
            if item.get('basis_note'):lines.append('    '+safe(item['basis_note']))
            lines.append('    Uncertainty: '+safe(item['uncertainty']))
    notes = [('Some AI items were rejected; accepted interpretations remain available.' if packet.get('ai_status') == 'partial' and v.startswith('AI interpretation failed:') else v) for v in packet['limitations']+packet['conflicts']]
    lines.extend(['','Limitations',*('  - '+safe(v) for v in notes)])
    if packet.get('ai_error'):
        error=packet['ai_error']
        lines.append('  AI diagnostic: '+safe(error['category'])+' / '+safe(error['stage']))
        detail=([f"HTTP {error['http_status']}"] if 'http_status' in error else [])
        detail.extend(str(error[k]) for k in ('parameter','rule','provider_category') if k in error)
        if detail:lines.append('  '+' | '.join(safe(v) for v in detail))
        for field,value in error.get('envelope',{}).items():
            lines.append('  '+safe(field)+': '+safe(str(value)))
        for rejection in error.get('rejected_items',[]):
            lines.append('  Item '+str(rejection['item_index'])+': '+safe(rejection['rule']))
            if rejection.get('literal_types'):
                lines.append('    Unsupported literal types: '+safe(', '.join(rejection['literal_types']))+
                             ' ('+str(rejection['unsupported_count'])+')')
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
                          '  Analyst objective remains in named inputs; use --json for the complete packet.'])
    else:
        lines.extend(['','No evidence searches executed. Review IDs, then use --discover with explicit approvals and time bounds.'])
    lines.extend(['', 'Detailed evidence projections'])
    for query in (packet.get('discovery') or {}).get('queries', []):
        lines.extend(safe(line) for line in json.dumps(query['result'], ensure_ascii=False, indent=2).splitlines())
    return '\n'.join(lines)


def render(packet, *, details=False):
    if packet.get('kind') == 'saved_briefing':
        from forensic_assistant.briefing_workflow import render as saved_render
        return saved_render(packet)
    if details:
        return render_details(packet)
    from forensic_assistant.briefing_report import render as human
    return human(packet)

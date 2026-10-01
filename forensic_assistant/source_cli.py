"""Shared CLI surface for analyst provenance actions."""
from forensic_assistant.database import sources


def configure(commands):
    upgrade=commands.add_parser('case-upgrade',help='Explicit transactional schema upgrade with a case backup')
    upgrade.add_argument('--yes',action='store_true',help='Confirm upgrading the selected case')
    upgrade.add_argument('--json',action='store_true')
    parser=commands.add_parser('source',help='Analyst sources, metadata history and retrospective assignments')
    sub=parser.add_subparsers(dest='source_command',required=True)
    for name in ('list','show','create','update','assign'):
        p=sub.add_parser(name)
        p.add_argument('--json',action='store_true')
        if name in ('show','update','assign'):p.add_argument('source_id')
        if name in ('list','show'):
            p.add_argument('--limit',type=int,default=100);p.add_argument('--offset',type=int,default=0)
        if name=='list':p.add_argument('--ids',action='store_true',help='Show full copyable source IDs below the compact table; --json also retains complete values')
        if name in ('create','update'):
            for flag in ('name','hostname','user','volume-root'):p.add_argument('--'+flag)
        if name in ('update','assign'):
            p.add_argument('--yes',action='store_true',help='Apply the explicit analyst action; otherwise preview only')
        if name=='assign':
            p.add_argument('--file-hash',action='append',help='Explicit existing file SHA-256; repeat or combine with --path (deduplicated union)')
            p.add_argument('--path',action='append',help='Recorded absolute Windows file/directory path; repeatable, no filesystem scan or wildcards. Requires --path or --file-hash.')
            p.add_argument('--confirmation-fingerprint',help='Require the case fingerprint returned by a reviewed preview before applying')
            p.add_argument('--reason',required=True,help='Reason for retrospective assignment (does not reconstruct ingestion)')
    for name,p in commands.choices.items():
        if name=='ingest' or name.startswith('ingest-'):
            p.add_argument('--source',help='Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused')
    commands.choices['search'].add_argument('--source',help='Filter Locard source membership, not hostname identity')


def changes(args):
    return {key:getattr(args,flag) for key,flag in
        [('display_name','name'),('hostname','hostname'),('username','user'),('volume_root','volume_root')]
        if getattr(args,flag) is not None}


def render_list(data,palette=None,*,ids=False,width=None):
    from forensic_assistant.retrieval.presentation import safe
    from forensic_assistant.retrieval.layout import table,terminal_width
    import textwrap
    from forensic_assistant.terminal import Palette
    palette=palette or Palette()
    labels={'prefetch':'Prefetch','mft':'MFT','registry':'Registry','evtx':'EVTX'}
    rows=[[r['source_id'],r['display_name'],r['hostname'] or 'unknown',r['batches'],r['files'],
           ', '.join(labels.get(k,k)+': '+str(v) for k,v in sorted(r['artifacts'].items())) or '-'] for r in data['sources']]
    lines=[palette('heading','SOURCES'),'']
    lines+=table(['ID','NAME','HOSTNAME','BATCHES','FILES','ARTIFACTS'],rows,palette,
                 minimums=[12,10,10,7,5,12],maximums=[40,28,24,9,9,40],
                 roles=['evidence_id','string_value','secondary_text','number_value','number_value','secondary_text'],right=(3,4),width=width)
    if ids:
        lines+=['',palette('heading','Full source IDs')]
        lines += [safe(r['source_id'])+'  '+safe(r['display_name']) for r in data['sources']]
    notices=['Display abbreviations (...) are not command IDs. Use source list --ids for full IDs; --json for complete values.',
             f"Showing {len(data['sources'])} of {data['total']}; offset {data['offset']}; more: {data['truncated']}"]
    if data['truncated']:notices.append('Results truncated; use --offset/--limit to review remaining sources.')
    for r in data['sources']:
        if r.get('host_conflict'):notices.append(safe(r['source_id'])+': conflicting host assertions; inspect source show.')
        if r.get('ambiguous_files'):notices.append(safe(r['source_id'])+f": {r['ambiguous_files']} files have multiple source memberships; inspect source show.")
    for notice in notices:lines.extend(textwrap.wrap(notice,terminal_width(width),break_on_hyphens=False))
    return '\n'.join(lines)+'\n'


def dispatch(db,args):
    action=args.source_command
    if action=='list':return sources.listing(db,args.limit,args.offset)
    if action=='show':return sources.detail(db,args.source_id,args.limit,args.offset)
    if action=='create':
        with db:sid=sources.create(db,name=args.name,hostname=args.hostname,username=args.user,volume_root=args.volume_root)
        return sources.summary(db,sid)
    # Hold a write reservation so preview, scope counts and mutation use one state.
    db.execute('BEGIN IMMEDIATE')
    try:
        from forensic_assistant.semantic.documents import fingerprint
        expected=getattr(args,'confirmation_fingerprint',None)
        if expected:
            if fingerprint(db)!=expected:raise ValueError('Case changed after confirmation preview; review and confirm again')
        scope=sources.summary(db,args.source_id)
        if action=='update':
            values=changes(args)
            if not values:raise ValueError('Specify metadata to update')
            preview=dict(source=scope,proposed=values,basis='analyst-supplied; previous revision retained')
            if not args.yes:return dict(preview=preview,applied=False,confirmation='Repeat with --yes to apply',confirmation_fingerprint=fingerprint(db))
            result=sources.update(db,args.source_id,**values)
        else:
            from forensic_assistant.database import source_selection
            selection=source_selection.select(db,args.file_hash,getattr(args,'path',None))
            preview=source_selection.preview(db,args.source_id,selection,args.reason)
            if not args.yes:return dict(preview=preview,applied=False,confirmation='Repeat with --yes to apply',confirmation_fingerprint=fingerprint(db))
            result=dict(assignment_id=sources.assign(db,args.source_id,selection['file_hashes'],reason=args.reason,
                                                    selection_basis=source_selection.assignment_basis(selection)))
        db.commit()
        return dict(applied=True,result=result,scope=preview)
    finally:db.rollback()


def render_assignment(data,palette=None):
    from forensic_assistant.terminal import Palette
    from forensic_assistant.retrieval.presentation import safe
    palette=palette or Palette()
    p=data.get('preview',data.get('scope'));s=p['source']
    lines=[palette('heading','RETROSPECTIVE SOURCE ASSIGNMENT'),
           'Source: '+safe(s['display_name'])+' ['+safe(s['source_id'])+']',
           'Analyst hostname: '+safe(s['hostname'] or 'unknown')]
    for path in p['paths']:lines.append('Recorded path: '+safe(path))
    if p['explicit_hashes']:lines.append('Explicit hash selectors: '+str(len(p['explicit_hashes'])))
    lines += [f"Distinct file hashes: {p['files']}",f"Evidence records: {p['evidence_records']}",
              'Artifact types: '+safe(p['artifact_types']), 'Existing provenance (file hashes):']
    for key,value in p['existing_provenance'].items():lines.append('  '+key.replace('_',' ')+': '+str(value))
    lines += ['Reason: '+safe(p['reason']),'Basis: '+p['basis']]
    lines += [palette('warning',text) for text in p['limitations']]
    if data['applied']:lines.append('Applied assignment: '+data['result']['assignment_id'])
    else:
        lines += ['Preview only. Repeat with --yes to apply; add --confirmation-fingerprint below to require this case state.',
                  data['confirmation_fingerprint']]
    lines.append('Use --json for the full selected hash and matched-location lists; source show exposes bounded assignment history.')
    return '\n'.join(lines)

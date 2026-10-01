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
        if name in ('create','update'):
            for flag in ('name','hostname','user','volume-root'):p.add_argument('--'+flag)
        if name in ('update','assign'):
            p.add_argument('--yes',action='store_true',help='Apply the explicit analyst action; otherwise preview only')
        if name=='assign':
            p.add_argument('--file-hash',action='append',required=True,help='Explicit existing file SHA-256; repeat for each file')
            p.add_argument('--reason',required=True,help='Reason for retrospective assignment (does not reconstruct ingestion)')
    for name,p in commands.choices.items():
        if name=='ingest' or name.startswith('ingest-'):
            p.add_argument('--source',help='Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused')
    commands.choices['search'].add_argument('--source',help='Filter Locard source membership, not hostname identity')


def changes(args):
    return {key:getattr(args,flag) for key,flag in
        [('display_name','name'),('hostname','hostname'),('username','user'),('volume_root','volume_root')]
        if getattr(args,flag) is not None}


def render_list(data):
    from forensic_assistant.retrieval.presentation import safe
    lines=['SOURCES','ID | NAME | ANALYST HOSTNAME | BATCHES | DISTINCT FILES | ARTIFACT RECORDS']
    for row in data['sources']:
        lines.append(' | '.join([row['source_id'],safe(row['display_name']),safe(row['hostname'] or 'unknown'),
            str(row['batches']),str(row['files']),safe(row['artifacts'])]))
    lines.append(f"Showing {len(data['sources'])} of {data['total']}; offset {data['offset']}; more: {data['truncated']}")
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
            hashes=sorted(set(args.file_hash))
            for sha in hashes:
                if not db.execute('SELECT 1 FROM evidence_files WHERE sha256=?',(sha,)).fetchone():raise ValueError('File hash not found: '+sha)
            count=sum(db.execute('SELECT count(*) FROM evidence_records WHERE file_sha256=?',(sha,)).fetchone()[0] for sha in hashes)
            preview=dict(source=scope,file_hashes=hashes,files=len(hashes),evidence_records=count,reason=args.reason,basis='retrospective analyst assignment')
            if not args.yes:return dict(preview=preview,applied=False,confirmation='Repeat with --yes to apply',confirmation_fingerprint=fingerprint(db))
            result=dict(assignment_id=sources.assign(db,args.source_id,hashes,reason=args.reason))
        db.commit()
        return dict(applied=True,result=result,scope=preview)
    finally:db.rollback()

"""Additive V2 CLI. Existing EVTX ingestion and process/session commands remain."""
from forensic_assistant.artifacts.ingest import ingest_artifact,discover
from forensic_assistant.artifacts.context import bind_context
from forensic_assistant.database.db import now
from forensic_assistant.ingest.evtx import ingest_file,digest
from forensic_assistant.retrieval.evidence import EvidenceQueries,get_evidence
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.retrieval.presentation import safe


def configure(commands):
    for name in ('ingest-mft','ingest-prefetch','ingest-registry','ingest-all','ingest-evtx'):
        p=commands.add_parser(name,help='Read-only artifact ingestion with source signature validation')
        p.add_argument('path');p.add_argument('--hostname');p.add_argument('--user');p.add_argument('--volume-root')
        p.add_argument('--parser-timeout',type=int,default=300)
        p.add_argument('--record-size',type=int)
        p.add_argument('--json',action='store_true')
    for name in ('search','timeline'):
        p=commands.choices[name];p.add_argument('--artifact',choices=['evtx','mft','prefetch','registry']);p.add_argument('--path')
    for name in ('search','show','status'):
        commands.choices[name].add_argument('--json',action='store_true')
    commands.choices['around'].add_argument('--timestamp-slot')
    commands.choices['investigate'].add_argument('--timestamp-slot')


def dispatch(db,args):
    command=args.command;q=EvidenceQueries(db)
    if command.startswith('ingest-'):
        requested=command.removeprefix('ingest-');results=[]
        for path,kind in discover(args.path,None if requested=='all' else requested):
            if kind=='evtx':
                result=ingest_file(db,path)
                if result['status'] in ('complete','partial'):
                    sha=db.execute('SELECT file_sha256 FROM ingestion_runs WHERE id=?',(result['run_id'],)).fetchone()[0]
                    with db:bind_context(db,sha,str(path.resolve()),args.hostname,args.user,args.volume_root)
            else:
                result=ingest_artifact(db,path,kind,hostname=args.hostname,username=args.user,volume_root=args.volume_root,
                                       timeout=args.parser_timeout,record_size=args.record_size)
            results.append(result)
        return {'results':results,'status':'complete' if results and all(r['status']=='complete' for r in results) else 'incomplete'},0 if results and all(r['status']=='complete' for r in results) else 1
    if command=='show':return get_evidence(db,args.evidence_id,args.raw),0
    if command=='status':
        result=Queries(db).coverage()
        result.update(schema_version=3,artifact_counts={r[0]:r[1] for r in db.execute('SELECT source_type,count(*) FROM evidence_records GROUP BY source_type')},
                      timeline_observations=db.execute('SELECT count(*) FROM evidence_timestamps WHERE timestamp_utc IS NOT NULL').fetchone()[0])
        return result,0
    if command in ('search','timeline'):
        filters={k:getattr(args,k,None) for k in ('artifact','path','process','hostname','ip','event_id')}
        filters.update(username=args.user,limit=args.limit,offset=args.offset,raw=args.raw)
        if command=='search':
            kinds={'logons':['logon','explicit_credentials','privileged_logon'],'failed-logons':['failed_logon'],
                   'processes':['process'],'scheduled-tasks':['scheduled_task'],'services':['service'],
                   'account-changes':['account_creation','group_membership']}
            if args.kind=='powershell':filters['powershell']=True
            elif args.kind:filters['artifact_types']=kinds[args.kind]
            result=q.search(start=args.start,end=args.end,**filters)
        else:
            if args.timestamp and args.around:raise ValueError('Specify either positional timestamp or --around')
            anchor=args.timestamp or args.around
            if args.artifact_type:filters['artifact_types']=[args.artifact_type]
            if anchor:
                if args.start or args.end:raise ValueError('Do not combine --around with --start/--end')
                result=q.timeline_around(anchor,args.minutes,**filters)
            else:
                if not args.start or not args.end:raise ValueError('Timeline requires --start and --end, or --around')
                result=q.search(start=args.start,end=args.end,timeline=True,**filters)
        output=result.as_dict();output['count_unit']='timestamp_observations' if command=='timeline' else 'evidence_records'
        output['caution']='Timestamp semantics differ by artifact. Correlation is not causation.'
        return output,0
    if command=='around':
        from forensic_assistant.correlation.temporal import shift
        anchor=get_evidence(db,args.evidence_id)
        stamp=anchor_time(anchor,args.timestamp_slot)
        if not anchor['host_key']:raise ValueError('Host context missing or conflicting; cannot select same-host temporal neighbors')
        if not 0<=args.seconds<=604800:raise ValueError('Seconds must be 0..604800')
        result=q.search(start=shift(stamp,-args.seconds) if args.direction!='after' else stamp,
                        end=shift(stamp,args.seconds) if args.direction!='before' else stamp,
                        exclude_time=stamp if args.direction!='around' else None,
                        hostname=anchor['host_key'],strict_host=True,timeline=True,limit=args.limit,offset=args.offset,raw=args.raw)
        return result.as_dict(),0
    return None


def anchor_time(anchor,slot=None):
    candidates=[t for t in anchor['timestamps'] if t['timestamp_utc'] and (slot is None or t['slot']==slot)]
    times={t['timestamp_utc'] for t in candidates}
    if len(times)!=1:raise ValueError('Anchor has missing or multiple timestamps; select --timestamp-slot from show output')
    return next(iter(times))


def render(result):
    if 'records' not in result:return safe(result)
    lines=['UTC | EVIDENCE ID | SOURCE | ARTIFACT TYPE | TIMESTAMP MEANING | OBJECT / OBSERVATION']
    for r in result['records']:
        obj=next((o['original'] for o in r.get('objects',[]) if o['role'] not in ('parent_image',)),None)
        from forensic_assistant.retrieval.presentation import detail
        observation=detail(r) if r['source_type']=='evtx' else obj or r.get('observation')
        lines.append(' | '.join(safe(v) for v in (r.get('timestamp_utc'),r['id'],r['source_type'],r.get('artifact_type'),r.get('timestamp',{}).get('source'),observation)))
    lines.append(f"Displayed {len(result['records'])} / {result['total']}; truncated={result['truncated']}")
    lines.append('CORRELATION != CAUSATION. Timestamp semantics differ by artifact.')
    return '\n'.join(lines)

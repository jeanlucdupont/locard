"""Source-scoped, indexed initial timestamp discovery. No model or case writes."""
import base64
import json
import sqlite3
import threading
import time
from .briefing_store import digest
from .retrieval.queries import required_time
from .retrieval.object_discovery import scope

ROUTES=(('evtx','process_context'),('browser','download'),('browser','visit'),
        ('prefetch','execution_metadata'),('mft','file_metadata'),('registry','registry_metadata'),('evtx','recorded_events'))
CANDIDATES=1000
SECONDS=5


def plans(source,available,start,end):
    if not isinstance(source,str) or not source.startswith('src-') or len(source)>128:
        raise ValueError('Supply an existing source ID using --source')
    leads={};rows=[]
    for family,purpose in ROUTES:
        identity='A-'+digest(['time-scope-v1',source,start,end,family,purpose])[:16]
        label=purpose.replace('_',' ')
        leads[identity]=dict(id=identity,type='time_scope',normalized=label,classification='authorized_scope',
                             negated=False,occurrences=[{'original':label}],fields=[])
        rows.append(dict(lead_id=identity,artifact=family,
            query=dict(time_discovery=True,source_id=source,artifact=family,purpose=purpose,start=start,end=end,limit=10),
            status='not_searched' if family in available else 'unavailable',candidates=0,pages=0,
            candidate_count_known=True,evidence_ids=[],cursor=None,seen_cursors=[],coverage={},limitations=[]))
    return leads,rows


def search(db,args):
    from .briefing import window
    from .database.sources import current
    from .retrieval.evidence import get_evidence
    from .investigation_ai.tools import envelope
    allowed={'time_discovery','source_id','artifact','purpose','start','end','limit','time_after'}
    if (set(args)-allowed or args.get('time_discovery') is not True or args.get('limit')!=10
            or (args.get('artifact'),args.get('purpose')) not in ROUTES):
        raise ValueError('Invalid initial-discovery query')
    window(args['start'],args['end'],source='explicit initial discovery scope')
    current(db,args['source_id'])
    start,end=required_time(args['start']),required_time(args['end'])
    binding=scope(db,[args['source_id'],args['artifact'],args['purpose'],start,end])
    after=None
    if args.get('time_after'):
        try:
            if len(args['time_after'])>2048:raise ValueError()
            token=json.loads(base64.b64decode(args['time_after'],altchars=b'-_',validate=True))
            if len(token)!=2 or token[0]!=binding or not isinstance(token[1],list) or len(token[1])!=3 or any(not isinstance(v,str) or len(v)>512 for v in token[1]):raise ValueError()
            after=token[1]
        except (ValueError,TypeError,UnicodeError):raise ValueError('Invalid continuation for authorized source/window') from None
    # Ordered range scan over the existing timestamp index; no full timeline or COUNT.
    sql='''SELECT t.timestamp_utc,t.evidence_id,t.slot FROM evidence_timestamps t INDEXED BY artifact_time
           CROSS JOIN evidence_records e ON e.evidence_id=t.evidence_id
           WHERE t.timestamp_utc>=? AND t.timestamp_utc<? AND e.source_type=?'''
    params=[start,end,args['artifact']]
    if after:sql+=' AND (t.timestamp_utc,t.evidence_id,t.slot)>(?,?,?)';params+=after
    sql+=' ORDER BY t.timestamp_utc,t.evidence_id,t.slot LIMIT ?';params.append(CANDIDATES+1)
    records=[];matches=[];seen=set();examined=0;last=after;complete=False
    notes=['Timestamp observations are not interchangeable execution evidence; SI/FN, browser, Prefetch and Registry semantics remain distinct.',
           'Only stored normalized timestamps are searched. Missing/ambiguous times and derived-only observations are outside this route.',
           'Source membership is not proof of a common host. Source-host conflicts remain in record provenance.',
           'Time order is a bounded starting sample, not a suspiciousness or rarity ranking.']
    deadline=time.monotonic()+SECONDS
    timer=threading.Timer(SECONDS,db.interrupt);timer.daemon=True;timer.start()
    try:
        candidates=db.execute(sql,params).fetchall()
        for row in candidates[:CANDIDATES]:
            if time.monotonic()>=deadline:break
            stamp,eid,slot=row
            record=get_evidence(db,eid)
            examined+=1;last=[stamp,eid,slot]
            if eid in seen:continue
            seen.add(eid)
            if args['source_id'] not in record.get('context',{}).get('source_ids',[]):continue
            purpose=args['purpose']
            if purpose in ('download','visit') and record.get('artifact_type')!='browser_'+purpose:continue
            if purpose=='process_context' and not (record.get('process_name') or record.get('command_line')):continue
            stamps=[t for t in record.get('timestamps',[]) if t.get('timestamp_utc') and start<=required_time(t['timestamp_utc'])<end]
            if not stamps:continue
            records.append(record)
            matches.append(dict(evidence_id=eid,source_file=str(record.get('source_file') or '')[:512],
                timestamp_utc=stamp,timestamps=stamps[:32],timestamps_truncated=len(stamps)>32,
                matched_fields=[dict(field='timestamp_utc',slot=slot,value=stamp,truncated=False)],limitations=list(notes)))
            if len(records)>=10:break
        complete=examined==len(candidates) and len(candidates)<=CANDIDATES
    except sqlite3.OperationalError as exc:
        if 'interrupt' not in str(exc).lower():raise
        notes.append('Execution-time bound reached; coverage incomplete.')
    finally:
        timer.cancel();timer.join()
    cursor=base64.urlsafe_b64encode(json.dumps([binding,last]).encode()).decode() if not complete and last and last!=after else None
    raw=dict(records=records,total=len(records),limit=10,offset=0,truncated=not complete,limits=notes,total_is_lower_bound=not complete)
    result=envelope(db,'briefing_search',raw,limit=10)
    result.update(matches=matches,limitations=notes,time_search=dict(examined=examined,complete=complete,
        next_cursor=cursor,candidate_limit=CANDIDATES,seconds=SECONDS,sql_scan_count='not_instrumented'),
        coverage=dict(matching_total=len(records),matching_total_is_lower_bound=not complete,returned=len(records)))
    return result

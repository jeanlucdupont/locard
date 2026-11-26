"""Read-only Defender filtering and whole-population grouping over common evidence."""
import hashlib
import json
from forensic_assistant.retrieval.evidence import EvidenceQueries,get_evidence
from forensic_assistant.retrieval.queries import escape_like,required_time
from forensic_assistant.detections.discovery import bounded,field,wire


def filters(artifact,text,category,action,rule,signature,pid,group=None):
    if all(v is None for v in (text,category,action,rule,signature,pid,group)):return [],[]
    if artifact!='defender':raise ValueError('Defender filters require artifact defender')
    clauses=[];params=[]
    if category is not None:clauses.append('e.artifact_type=?');params.append(category)
    if text is not None:
        if not text:raise ValueError('Empty Defender text filter')
        clauses.append("json_extract(e.original_json,'$.text') LIKE ? ESCAPE '!'");params.append('%'+escape_like(text)+'%')
    for role,value in (('action',action),('rule',rule),('signatureid',signature),('processid',pid),('group',group)):
        if value is not None:
            clauses.append("EXISTS (SELECT 1 FROM evidence_objects o WHERE o.evidence_id=e.evidence_id AND o.role=? AND o.normalized=?)")
            params.extend(('defender_'+role,value))
    return clauses,params


PRIORITY={'detection':0,'asr_notification':0,'remediation':1,'injection_monitoring':1,'behavior_telemetry':2,'lowfi':2,
          'signature_observation':2,'file_scan':3,'configuration':3,'signature_throttling':3}


def groups(db,source,start,end,*,limit=5,offset=0,category=None,hydrate=None,byte_limit=12000):
    if not 1<=limit<=10 or type(offset) is not int or offset<0 or byte_limit<4096:raise ValueError('Invalid grouped discovery bounds')
    start,end=required_time(start),required_time(end)
    if start>=end:raise ValueError('Empty time interval')
    where,params=EvidenceQueries(db)._where(artifact='defender',source_scope=source,defender_category=category)
    scope=' AND '.join(where)
    unknown=db.execute('SELECT count(*) FROM evidence_records e WHERE '+scope+" AND NOT EXISTS (SELECT 1 FROM evidence_timestamps t WHERE t.evidence_id=e.evidence_id AND t.timestamp_utc IS NOT NULL)",params).fetchone()[0]
    # Count each record once, regardless of multiple eligible timestamp observations.
    selected=(' FROM evidence_records e WHERE '+scope+' AND EXISTS (SELECT 1 FROM evidence_timestamps t WHERE t.evidence_id=e.evidence_id AND t.timestamp_utc>=? AND t.timestamp_utc<?)')
    params=[*params,start,end]
    priority="CASE e.artifact_type "+' '.join("WHEN '"+k+"' THEN "+str(v) for k,v in PRIORITY.items())+' ELSE 4 END'
    # Qualified min/max times concern in-window retained observations, not execution.
    times="(SELECT %s(t.timestamp_utc) FROM evidence_timestamps t WHERE t.evidence_id=e.evidence_id AND t.timestamp_utc>=? AND t.timestamp_utc<?)"
    sql=("SELECT json_extract(e.original_json,'$.group_key') AS grouping,e.artifact_type,count(*) AS n,min(e.evidence_id) AS example,"
         +'min('+times%'min'+') AS first_time,max('+times%'max'+') AS last_time'+selected+
         " GROUP BY e.artifact_type,json_extract(e.original_json,'$.group_key') ORDER BY "+priority+',grouping LIMIT ? OFFSET ?')
    rows=db.execute(sql,[start,end,start,end,*params,limit+1,offset]).fetchall();output=[]
    hydrate=hydrate or (lambda eid:get_evidence(db,eid))
    for row in rows[:limit]:
        record=hydrate(row['example']);detail=record['detail'];entries=detail['fields']
        originals=[field('/detail/fields/'+str(i)+'/value',f['value'],f['name']) for i,f in enumerate(entries[:8])]
        item=dict(evidence_id=record['id'],artifact='defender',source_ids=[source],representative=True,
                  group_id=hashlib.sha256(row['grouping'].encode()).hexdigest(),category=row['artifact_type'],count=row['n'],
                  first_time=row['first_time'],last_time=row['last_time'],timestamp_meaning='In-window recorded timestamp observations; inspect individual meanings',
                  original_fields=originals,kind='recorded_action' if row['artifact_type'] in ('asr_notification','remediation') else 'recorded_detection' if row['artifact_type']=='detection' else 'diagnostic_observation',
                  field_limitations=detail['limitations']+(['Additional fields omitted; inspect the representative original record'] if len(entries)>8 else []),members_filter=dict(artifact='defender',defender_group=hashlib.sha256(row['grouping'].encode()).hexdigest()),
                  count_meaning='Retained original records in this scoped group; not unique incidents, process instances or EVTX-equivalent actions')
        if len(wire(output+[item]))>byte_limit-2000:break
        output.append(item)
    more=len(rows)>len(output)
    if more and not output:raise ValueError('Group summary exceeds response capacity; inspect original records')
    result=dict(contract='defender-groups-v1',records=output,next_offset=offset+len(output) if more else None,truncated=more or offset>0,
                coverage=dict(complete=not more and offset==0 and unknown==0,remaining_complete=not more,counts_complete=True,
                              timed_population_complete=not more and offset==0,
                              time_unassignable_records=unknown,groups_returned=len(output)),
                limitations=['Group counts cover the entire eligible population; returned group pages can be incomplete.',
                             'Timezone-unknown/untimed records are excluded from timed authorization; no absence conclusion.',
                             'Different files may repeat observations; counts are not unique incidents or distinct processes.',
                             'Defender diagnostic telemetry and numeric flags do not independently establish maliciousness.'])
    if len(wire(result))>byte_limit:raise ValueError('Grouped discovery envelope exceeds response capacity')
    return result

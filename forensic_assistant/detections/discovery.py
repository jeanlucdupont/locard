"""Provider-free, scope-first discovery. Derived leads are not forensic findings.

No rule with secondary evidence queries is admitted here. Legacy detections()
retains its independent contract. All SQL fragments below are application-owned.
"""
import hashlib
import json
from forensic_assistant.retrieval.evidence import EvidenceQueries,get_evidence
from forensic_assistant.retrieval.event_data import payload, BLOCK_NOTE
from forensic_assistant.retrieval.queries import required_time
from forensic_assistant.detections.rules.events import RULES as EVENT_RULES
from forensic_assistant.detections.rules.powershell import RULES as PS_RULES
from forensic_assistant.detections.rules.office import RULES as OFFICE_RULES

DEFENDER='Microsoft-Windows-Windows Defender'
DEFENDER_CHANNEL=DEFENDER+'/Operational'
SECURITY='Microsoft-Windows-Security-Auditing'
# Verified Microsoft event definitions; actions remain separate original fields.
DEFENDER_EVENTS={
    1116:('malware_detection','Recorded malware or potentially unwanted software detection',0),
    1117:('remediation_action','Recorded threat action; inspect the original action and status',0),
    1118:('remediation_failure','Recorded failure of a threat action',0),
    1119:('remediation_critical_failure','Recorded critical failure of a threat action',0),
    1121:('asr_block',BLOCK_NOTE,0),
    1122:('asr_audit','Recorded ASR audit; this is not a blocking action',0),
    5001:('protection_disabled','Recorded real-time protection disablement',0),
    5004:('protection_configuration','Recorded real-time protection configuration change',1),
    5007:('configuration_change','Recorded antimalware configuration change',1),
}
ORDINARY={
    (SECURITY,'Security',4698):('task_creation','LOCARD-TASK-001'),
    (SECURITY,'Security',4697):('service_installation','LOCARD-SVC-001'),
    ('Service Control Manager','System',7045):('service_installation','LOCARD-SVC-001'),
    ('Microsoft-Windows-Eventlog','Security',1102):('audit_cleared','LOCARD-AUDIT-001'),
    (SECURITY,'Security',4720):('account_creation','LOCARD-ACCOUNT-001'),
    (SECURITY,'Security',4648):('explicit_credentials','LOCARD-CRED-001'),
    (SECURITY,'Security',4719):('audit_policy_change',None),
}
HEURISTIC_EVENTS=((SECURITY,'Security',4688),
    ('Microsoft-Windows-Sysmon','Microsoft-Windows-Sysmon/Operational',1),
    ('Microsoft-Windows-PowerShell','Microsoft-Windows-PowerShell/Operational',4103),
    ('Microsoft-Windows-PowerShell','Microsoft-Windows-PowerShell/Operational',4104))
DEFERRED=('LOCARD-AUTH-001','LOCARD-X-001','LOCARD-X-002','LOCARD-X-003','LOCARD-X-004')
OVERVIEWS={'event_distribution':'evtx','process_images':'evtx','browser_downloads':'browser','prefetch_executables':'prefetch','defender_groups':'defender'}
LIMITATIONS=['Discovery is not proof of compromise or absence of an incident.',
    'Coverage concerns retained authorized records, not completeness of endpoint logging or ingestion.',
    'Recorded alerts, ordinary observations and Locard heuristics have different meanings.',
    'Source metadata may be analyst supplied. Inspect original records to corroborate leads.']
FIELD_NAMES=('Path','Process Name','Target Commandline','Parent Commandline','Threat Name','Action Name',
    'Error Code','Error Description','Status','Severity Name','Detection User','User','ID','Old Value','New Value',
    'Old value','New value','Action','Severity','Name','ImagePath','ServiceFileName','ServiceName','TaskName','TaskContent','NewProcessName','ParentProcessName','CommandLine','SubjectUserName','TargetUserName','AuditPolicyChanges')


def wire(value):return json.dumps(value,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode()

def bounded(value,maximum=192):
    from forensic_assistant.ai.backend import redact
    if not isinstance(value,str):return dict(value=value,truncated=False,redacted=False)
    clean=redact(value);short=clean.encode()[:maximum].decode('utf-8','ignore')
    while len(wire(short))>maximum:short=short[:-1]
    return dict(value=short,truncated=short!=clean,redacted=clean!=value)

def field(pointer,value,name=None):
    item=dict(field=pointer,**bounded(value))
    if name is not None:item['name']=bounded(name,80)['value']
    return item

def tuple_filter(values):
    parts=[];params=[]
    for provider,channel,event_id in values:
        parts.append('(v.event_id=? AND v.provider=? AND v.channel=?)');params.extend((event_id,provider,channel))
    return '('+' OR '.join(parts)+')',params


class Discovery:
    def __init__(self,db,source_id,start,end,*,hydrate=None):
        self.db=db;self.source=source_id;self.start=required_time(start);self.end=required_time(end)
        if not source_id or self.start>=self.end:raise ValueError('Explicit source and nonempty time scope required')
        self.hydrate=hydrate or (lambda eid:get_evidence(db,eid))

    def scoped(self,family):
        if self.db.execute('PRAGMA user_version').fetchone()[0] not in (4,5):raise ValueError('Source-aware discovery requires schema 4 or 5')
        clauses,params=EvidenceQueries(self.db)._where(artifact=family,source_scope=self.source)
        return ' AND '.join(clauses),params

    def event_base(self):
        where,params=self.scoped('evtx')
        return (' FROM events v JOIN evidence_records e ON e.evidence_id=v.id WHERE '+where+
                ' AND v.timestamp_utc>=? AND v.timestamp_utc<?'),[*params,self.start,self.end]

    def base_result(self):
        return dict(contract='security-discovery-v1',scope=dict(source_id=self.source,start=self.start,end_exclusive=self.end),
                    records=[],limitations=list(LIMITATIONS))

    def signals(self,*,category='all',limit=5,offset=0,candidate_limit=200,byte_limit=12000):
        if category not in ('all','recorded','observations','heuristics') or not 1<=limit<=10 or not 1<=candidate_limit<=1000 or type(offset) is not int or offset<0:
            raise ValueError('Invalid discovery bounds')
        if byte_limit<4096:raise ValueError('Discovery response capacity too small')
        base,params=self.event_base()
        supported=[(DEFENDER,DEFENDER_CHANNEL,i) for i in DEFENDER_EVENTS]
        if category in ('all','observations'):supported+=list(ORDINARY)
        if category in ('all','heuristics'):supported+=list(HEURISTIC_EVENTS)
        if category=='observations':supported=list(ORDINARY)
        if category=='heuristics':supported=list(HEURISTIC_EVENTS)
        predicate,selected_params=tuple_filter(supported)
        # Indexed Event ID predicate narrows candidates before any original hydration.
        # Static ranking is review priority, not probability; every lower rank is pageable.
        ranking="CASE WHEN v.provider=? AND v.channel=? THEN CASE WHEN v.event_id IN (5004,5007) THEN 1 ELSE 0 END WHEN v.event_id IN (4688,1,4103,4104,1102,4719) THEN 1 ELSE 2 END"
        sql='SELECT v.id'+base+' AND '+predicate+' ORDER BY '+ranking+',v.timestamp_utc,v.id LIMIT ? OFFSET ?'
        ids=self.db.execute(sql,[*params,*selected_params,DEFENDER,DEFENDER_CHANNEL,candidate_limit+1,offset]).fetchall()
        result=self.base_result();evaluated=0;examined=0;output=[]
        rule_counts={r.rule_id:dict(evaluated_candidates=0,returned_matches=0) for r in (*EVENT_RULES,*PS_RULES,*OFFICE_RULES)}
        for row in ids[:candidate_limit]:
            if len(output)>=limit:break
            record=self.hydrate(row[0]);signal=self.signal(record);examined+=1
            key=(record.get('provider'),record.get('channel'),record.get('event_id'))
            attempted=([ORDINARY[key][1]] if key in ORDINARY and ORDINARY[key][1] else
                [r.rule_id for r in (*PS_RULES,*OFFICE_RULES) if record.get('kind') in r.kinds] if key in HEURISTIC_EVENTS else [])
            for rule_id in attempted:rule_counts[rule_id]['evaluated_candidates']+=1
            if signal is None:evaluated+=1;continue
            # Reserve bounded envelope/coverage room. Never truncate an evidence ID.
            if len(wire(output+[signal]))>byte_limit-3500:break
            output.append(signal);evaluated+=1
            for match in signal['locard_rule_matches']:rule_counts[match['rule_id']]['returned_matches']+=1
        more=evaluated<len(ids)
        available=bool(self.db.execute('SELECT 1'+base+' AND v.provider=? AND v.channel=? LIMIT 1',
                                      [*params,DEFENDER,DEFENDER_CHANNEL]).fetchone())
        coverage=dict(candidate_population=None,candidate_limit=candidate_limit,candidates_evaluated=examined,candidates_consumed=evaluated,returned_matches=len(output),
            offset=offset,complete=not more and offset==0,remaining_complete=not more,
            truncated=more or offset>0,next_offset=offset+evaluated if more else None,
            ordering='static review priority, recorded timestamp, evidence ID',
            defender_records_available=available,
            state='signals_found' if output else 'coverage_incomplete' if more or offset else 'no_matching_signals_in_supported_coverage' if available else 'defender_source_unavailable_in_scope')
        selected_rules=({r.rule_id for r in EVENT_RULES} if category=='observations' else {r.rule_id for r in (*PS_RULES,*OFFICE_RULES)} if category=='heuristics' else set(rule_counts) if category=='all' else set())
        for rule_id,counts in rule_counts.items():
            counts['selected']=rule_id in selected_rules
            counts['coverage_complete']=coverage['complete'] if counts['selected'] else None
        result.update(records=output,coverage=coverage,truncated=coverage['truncated'],next_offset=coverage['next_offset'],
            evaluated_categories=category,rule_coverage=dict(single_record_rules=rule_counts,scope_of_counts='This page only; an evaluated but unreturned candidate is revisited by continuation',
                deferred_rules=list(DEFERRED),deferred_reason='Secondary queries or supporting evidence need additional scoped integration; not evaluated'),
            unsupported_semantics=['Unlisted Defender event IDs','AppLocker','Code Integrity','Other security-product providers'])
        if more and evaluated==0:raise ValueError('Complete signal cannot fit response capacity')
        if len(wire(result))>byte_limit:raise ValueError('Discovery envelope exceeds response capacity')
        return result

    def signal(self,record):
        key=(record.get('provider'),record.get('channel'),record.get('event_id'))
        interpretation=None;matches=[]
        if key[:2]==(DEFENDER,DEFENDER_CHANNEL) and key[2] in DEFENDER_EVENTS:
            category,reason,priority=DEFENDER_EVENTS[key[2]]
            kind='recorded_security_alert' if key[2]<5000 else 'security_relevant_observation'
            interpretation=dict(category=category,meaning=reason,basis='provider/channel/Event ID',version='defender-signals-v1')
        elif key in ORDINARY:
            category,rule_id=ORDINARY[key];priority=1 if key[2] in (1102,4719) else 2;kind='security_relevant_observation'
            if rule_id:
                rule=next(r for r in EVENT_RULES if r.rule_id==rule_id)
                match=rule.evaluate(None,record,{})
                if match:matches=[match]
                else:return None
                reason=match['reason']
            else:reason='Recorded audit policy change; authorization and intent are not established'
            interpretation=dict(category=category,meaning=reason,basis='provider/channel/Event ID',version='security-observations-v1')
        elif key in HEURISTIC_EVENTS:
            matches=[value for rule in (*PS_RULES,*OFFICE_RULES) if record.get('kind') in rule.kinds
                     if (value:=rule.evaluate(None,record,{}))]
            if not matches:return None
            category='heuristic_match';kind='locard_heuristic';priority=1
        else:return None
        fields=[field('/'+k,record[k]) for k in ('process_name','command_line','parent_process_name','service_name','task_name','user_sid','level') if record.get(k) is not None]
        entries,notes=payload(record)
        chosen=[(i,e) for i,e in enumerate(entries) if e['name'] in FIELD_NAMES]
        chosen.sort(key=lambda pair:(FIELD_NAMES.index(pair[1]['name']),pair[0]))
        for i,entry in chosen[:8]:fields.append(field('/original_event_data/'+str(i)+'/value',entry['value'],entry['name']))
        if len(chosen)>8:notes.append('Additional relevant original fields omitted; inspect the record')
        signal=dict(signal_id='SIGNAL:'+hashlib.sha256(wire(['signals-v1',record['id'],category])).hexdigest(),
            evidence_id=record['id'],artifact='evtx',provider=record['provider'],channel=record['channel'],event_id=record['event_id'],
            timestamp=record.get('timestamp_utc'),timestamp_meaning='EVTX SystemTime',kind=kind,category=category,
            review_priority=priority,priority_origin='Locard static review order; not confidence',original_fields=fields,
            source_ids=[self.source],interpretation=interpretation,
            locard_rule_matches=[{k:m[k] for k in ('rule_id','rule_version','reason','limitations')} for m in matches],
            field_limitations=notes)
        return signal

    def overview(self,*,kind,limit=5,offset=0,byte_limit=12000):
        if kind not in OVERVIEWS or not 1<=limit<=10 or type(offset) is not int or offset<0:raise ValueError('Invalid overview')
        if byte_limit<4096:raise ValueError('Discovery response capacity too small')
        if kind=='defender_groups':
            from forensic_assistant.artifacts.defender_query import groups
            return groups(self.db,self.source,self.start,self.end,limit=limit,offset=offset,byte_limit=byte_limit,hydrate=self.hydrate)
        result=self.base_result();result.update(contract='activity-overview-v1',overview=kind)
        if kind=='browser_downloads':
            from forensic_assistant.conversational_ai.tools import exclusive_end
            page=EvidenceQueries(self.db,hydrate=self.hydrate).search(artifact='browser',browser_kind='download',source_scope=self.source,
                start=self.start,end=exclusive_end(self.end),limit=limit,offset=offset,exact_count=False)
            items=[]
            for r in page.records:
                detail=r.get('detail',{})
                fields=[field('/detail/'+k,detail[k]) for k in ('target_path','current_path','url','referrer','state','received_bytes','total_bytes') if detail.get(k) is not None]
                for i,link in enumerate(detail.get('url_chain',[])[:2]):
                    if isinstance(link,dict) and link.get('url') is not None:fields.append(field('/detail/url_chain/'+str(i)+'/url',link['url']))
                items.append(dict(evidence_id=r['id'],artifact='browser',source_ids=[self.source],original_fields=fields,
                    timestamp=r.get('timestamp_utc'),timestamp_meaning='Browser summary time; inspect start/end observations',kind='download_inventory'))
            extra=page.has_more
        else:
            family=OVERVIEWS[kind]
            if family=='evtx':
                base,params=self.event_base()
                keys=('v.provider','v.channel','v.event_id') if kind=='event_distribution' else ('v.process_name',)
                reference='v.id'
                if kind=='process_images':base+=' AND v.process_name IS NOT NULL'
            else:
                where,params=self.scoped(family)
                base=(' FROM prefetch_records p JOIN evidence_records e USING(evidence_id) WHERE '+where+
                      ' AND EXISTS (SELECT 1 FROM evidence_timestamps t WHERE t.evidence_id=e.evidence_id AND t.timestamp_utc>=? AND t.timestamp_utc<?)')
                params += [self.start,self.end];keys=('p.executable',);reference='e.evidence_id'
            columns=','.join(k+' AS k'+str(i) for i,k in enumerate(keys))
            sql='SELECT '+columns+',count(*) AS n,min('+reference+') AS example'+base+' GROUP BY '+','.join(keys)+' ORDER BY n DESC,'+','.join(keys)+' LIMIT ? OFFSET ?'
            rows=self.db.execute(sql,[*params,limit+1,offset]).fetchall();extra=len(rows)>limit;items=[]
            for row in rows[:limit]:
                eid=row['example'];self.hydrate(eid) # Validate representative before exposing its identity.
                values=[row['k'+str(i)] for i in range(len(keys))]
                items.append(dict(evidence_id=eid,artifact=family,source_ids=[self.source],representative=True,
                    group_id='GROUP:'+hashlib.sha256(wire([kind,values])).hexdigest(),
                    group={keys[i].split('.')[-1]:bounded(v,160) for i,v in enumerate(values)},count=row['n'],count_meaning='Retained evidence records in this exact scoped group; not executions or distinct real-world events'))
        output=[]
        for item in items:
            if len(wire(output+[item]))>byte_limit-2000:break
            output.append(item)
        more=extra or len(output)<len(items)
        if items and not output:raise ValueError('Complete overview item cannot fit response capacity')
        result.update(records=output,truncated=more or offset>0,next_offset=offset+len(output) if more else None,
            coverage=dict(complete=not more and offset==0,remaining_complete=not more,groups_returned=len(output),
                          total_groups=None,group_counts_exact=kind!='browser_downloads'),
            limitations=LIMITATIONS+['Frequency is not an organizational baseline; rarity or recency is not maliciousness.',
                'Examples represent groups, not every member. Use original inspection and scoped search for additional records.'])
        if len(wire(result))>byte_limit:raise ValueError('Discovery envelope exceeds response capacity')
        return result

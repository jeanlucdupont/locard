"""Versioned, scope-first execution observations from slim retained projections."""
from functools import lru_cache
import json
from forensic_assistant.artifacts.context import effective_context
from forensic_assistant.artifacts.registry_extractors import EXTRACTORS
from forensic_assistant.database import sources
from forensic_assistant.retrieval.evidence import EvidenceQueries
from forensic_assistant.retrieval.event_data import payload
from .discovery import SECURITY,tuple_filter

FAMILIES=('evtx','registry','defender','prefetch')
EVENTS=((SECURITY,'Security',4688),('Microsoft-Windows-Sysmon','Microsoft-Windows-Sysmon/Operational',1),
 ('Microsoft-Windows-PowerShell','Microsoft-Windows-PowerShell/Operational',4103),
 ('Microsoft-Windows-PowerShell','Microsoft-Windows-PowerShell/Operational',4104),
 ('PowerShell','Windows PowerShell',400),('PowerShell','Windows PowerShell',403),('PowerShell','Windows PowerShell',600))
DEFENDER=('lowfi','behavior_telemetry','injection_monitoring','asr_notification')
MEANINGS={
 'process_creation':'Recorded process creation; parent fields are assertions, not independently matched instances',
 'script_content':'Recorded PowerShell content/context, not proof every statement completed',
 'user_entered_command':'RunMRU user-entered command; not proof of successful execution',
 'configured_execution':'Registry configured execution value; not verified execution or malicious persistence',
 'command_line_observation':'Selected Defender LowFi command-line observation, not complete execution telemetry',
 'security_engine_telemetry':'Selected Defender behavioral/monitoring telemetry, not a malware verdict',
 'recorded_control_action':'Recorded ASR action; BLOCK does not establish successful target execution or complete prevention',
 'historical_execution_indicator':'Prefetch execution indicator; referenced files are not executed images and retained runs are incomplete'}


class Population:
    def __init__(self,db,source,start,end,*,hostname=None,check=lambda:None):
        sources.current(db,source)
        self.db,self.source,self.start,self.end,self.hostname,self.check=db,source,start,end,hostname,check
        self.coverage={}
        self.context=lru_cache(maxsize=512)(lambda sha,host,user:effective_context(db,dict(file_sha256=sha,hostname=host,username=user)))

    def rows(self,family):
        db=self.db;self.check()
        where,params=EvidenceQueries(db)._where(artifact=family,source_scope=self.source)
        scoped=' AND '.join(where)
        allwhere,allparams=EvidenceQueries(db)._where(artifact=family,source_id=self.source)
        allcount=db.execute('SELECT count(*) FROM evidence_records e WHERE '+' AND '.join(allwhere),allparams).fetchone()[0]
        strictcount=db.execute('SELECT count(*) FROM evidence_records e WHERE '+scoped,params).fetchone()[0]
        extra=[];supported='1';timekey='e.evidence_id'
        if family=='evtx':
            join=' JOIN events v ON v.id=e.evidence_id'
            supported,extra=tuple_filter(EVENTS)
            columns='v.provider,v.channel,v.event_id,v.process_name,v.command_line,v.script_block,v.parent_process_name,v.process_id,v.parent_process_id,v.user_sid,v.event_data_json'
        elif family=='registry':
            join=' JOIN registry_values v USING(evidence_id) JOIN registry_keys k ON k.evidence_id=v.key_id'
            columns='v.key_id,k.key_path,v.value_name,v.decoded_json'
            # Reuse the registered extractors; exact RunMRU is a subset of recent_text.
            supported="(EXISTS (SELECT 1 FROM registry_views r WHERE r.evidence_id=e.evidence_id AND r.extractor IN ('run','services','winlogon')) OR (lower(k.key_path) LIKE '%\\runmru' AND v.value_name<>'MRUList'))"
            timekey='v.key_id'
        elif family=='defender':
            join='';supported="e.artifact_type IN ("+','.join('?' for _ in DEFENDER)+')';extra=list(DEFENDER)
            columns="json_extract(e.original_json,'$.fields') AS fields_json,json_extract(e.original_json,'$.category') AS category"
        else:
            join=' JOIN prefetch_records p USING(evidence_id)';columns='p.executable'
        base=' FROM evidence_records e'+join+' WHERE '+scoped+' AND '+supported
        values=[*params,*extra]
        supported_count=db.execute('SELECT count(*)'+base,values).fetchone()[0]
        timebase=' FROM evidence_timestamps t WHERE t.evidence_id='+timekey
        unknown=db.execute('SELECT count(*)'+base+' AND NOT EXISTS (SELECT 1'+timebase+' AND t.timestamp_utc IS NOT NULL)',values).fetchone()[0]
        timefilter=' AND t.timestamp_utc>=? AND t.timestamp_utc<?'
        first='(SELECT min(t.timestamp_utc)'+timebase+timefilter+')'
        last='(SELECT max(t.timestamp_utc)'+timebase+timefilter+')'
        fields='e.evidence_id,e.file_sha256,e.hostname,e.username,e.artifact_type,'+columns
        sql='SELECT '+fields+','+first+' AS first_time,'+last+' AS last_time'+base+' AND EXISTS (SELECT 1'+timebase+timefilter+') ORDER BY e.evidence_id'
        stats=dict(source_records=allcount,excluded_ambiguous_source=allcount-strictcount,unsupported_record_types=strictcount-supported_count,
                   supported_source_records=supported_count,excluded_unknown_time=unknown,in_window=0,excluded_host_conflict=0,excluded_host_filter=0,excluded_invalid_projection=0,eligible=0)
        self.coverage[family]=stats
        for row in db.execute(sql,[self.start,self.end,self.start,self.end,*values,self.start,self.end]):
            self.check();stats['in_window']+=1
            context=self.context(row['file_sha256'],row['hostname'],row['username'])
            if 'hostname' in context['conflicts'] or context.get('source_ids')!=[self.source]:stats['excluded_host_conflict']+=1;continue
            if self.hostname and (context['hostname'] or '').casefold()!=self.hostname.casefold():stats['excluded_host_filter']+=1;continue
            observation=self.project(family,dict(row),context)
            if observation is None:stats['excluded_invalid_projection']+=1;continue
            stats['eligible']+=1
            yield observation
        stats['excluded_outside_window']=supported_count-unknown-stats['in_window']

    def project(self,family,row,context):
        originals={};notes=[];image=parent=command=pid=ppid=None;semantic='';additional={}
        def take(name,value,pointer):
            if value is not None:originals[name]=dict(field=pointer,value=value)
            return value
        if family=='evtx':
            semantic='process_creation' if row['event_id'] in (4688,1) else 'script_content'
            image=take('image',row['process_name'],'/process_name');parent=take('parent',row['parent_process_name'],'/parent_process_name')
            command=take('command',row['command_line'],'/command_line')
            if not command:command=take('command',row['script_block'],'/script_block')
            pid=take('pid',row['process_id'],'/process_id');ppid=take('parent_pid',row['parent_process_id'],'/parent_process_id')
            entries,limitations=payload(row);notes.extend(limitations)
            for name in ('SubjectUserName','TargetUserName','User','LogonId','SubjectLogonId','IntegrityLevel','TokenElevationType','HostApplication'):
                found=[(i,e) for i,e in enumerate(entries) if e['name']==name]
                if len(found)==1:
                    i,e=found[0];additional[name]=take(name,e['value'],f'/original_event_data/{i}/value')
                elif len(found)>1:notes.append('Duplicate '+name+' fields remain unresolved')
            if not command and additional.get('HostApplication'):
                command=additional['HostApplication'];originals['command']=originals['HostApplication']
            additional.update(provider=row['provider'],channel=row['channel'],event_id=row['event_id'])
        elif family=='registry':
            semantic='user_entered_command' if row['key_path'].casefold().endswith('\\runmru') else 'configured_execution'
            # Defensive matching prevents a stale/forged view from granting semantics.
            matches=[x for x in EXTRACTORS if x.name in ('run','services','winlogon','recent') and x.matches(row['key_path'],row['value_name'])]
            if not matches:return None
            decoded=json.loads(row['decoded_json'])
            if isinstance(decoded,str):command=take('command',decoded,'/detail/value_data')
            else:notes.append('Non-string Registry value has no command-line interpretation')
            take('registry_path',row['key_path'],'/detail/key_path');take('value_name',row['value_name'],'/detail/value_name')
            notes.append('Timestamp is containing-key last-write, not individual value creation or execution')
        elif family=='defender':
            semantic={'lowfi':'command_line_observation','asr_notification':'recorded_control_action'}.get(row['category'],'security_engine_telemetry')
            entries=json.loads(row['fields_json']);mapping={}
            for name in ('ImagePath','Process','CommandLine','command','ProcessID','SessionID','CreationTime','ProcessCreationTime','Taint Parents','Taint Info','Operations','Target','Action','Rule','MonitoringReason'):
                found=[(i,e) for i,e in enumerate(entries) if e['name']==name]
                if len(found)==1:
                    i,e=found[0];mapping[name]=take(name,e['value'],f'/detail/fields/{i}/value')
                elif len(found)>1:notes.append('Duplicate '+name+' fields remain unresolved')
            image=mapping.get('ImagePath') or mapping.get('Process');command=mapping.get('CommandLine') or mapping.get('command');pid=mapping.get('ProcessID')
            for alias,names in (('image',('ImagePath','Process')),('command',('CommandLine','command')),('pid',('ProcessID',))):
                for name in names:
                    if name in originals:originals[alias]=originals[name];break
            additional['defender_category']=row['category']
            notes.append('Taint/monitoring and parent references do not establish malware or process-instance ancestry')
        else:
            semantic='historical_execution_indicator';image=take('image',row['executable'],'/detail/executable')
        return dict(contract='execution-observation-v1',evidence_id=row['evidence_id'],artifact=family,source_ids=[self.source],artifact_host=row['hostname'],
                    context_host=context['hostname'],host_basis=context['basis'],first_time=row['first_time'],last_time=row['last_time'],
                    timestamp_meaning='Containing Registry key last-write' if family=='registry' else 'EVTX SystemTime' if family=='evtx' else 'Artifact timestamp observations; inspect original slots and meanings',
                    kind=semantic,meaning=MEANINGS[semantic],image=image,parent=parent,command=command,pid=pid,parent_pid=ppid,
                    user=row['username'],original_fields=originals,context=additional,limitations=notes)

"""Streaming Defender diagnostic observations; no command execution or cloud access.

Original byte chunks are retained even when decoding or record interpretation fails.
Format recognition is deliberately separate from claims about maliciousness.
"""
import base64
import hashlib
import codecs
import re
from pathlib import Path
from forensic_assistant.database.artifacts import dump
from forensic_assistant.retrieval.queries import required_time
from .times import filetime
from .progress import advance

VERSION='2'
MAX_CHUNK=1024*1024
STAMP=re.compile(r'^\s*(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)')
MARKERS=('[Mini-filter]','DETECTION_ADD','Process scan','Signature updated','Engine:','ASR Notification:','BEGIN BM telemetry','END BM telemetry','RTP:','RTP ','MpService','Service Start','RTP minifilter','RTP minfil','Microsoft Antimalware','Microsoft Defender','Service started','Service startup','Engine Version','AV Signature Version','Detection add:','Threat detected:','Remediation:')
LIMITATION='Defender diagnostic observation; selected telemetry is not complete endpoint activity or proof of maliciousness.'
CAUTIONS={
 'asr_notification':'Recorded action applies to this notification only: BLOCK does not prove successful execution or complete incident prevention; abbreviated Rule values are not expanded to GUIDs.',
 'lowfi':'LowFi is selected command-line telemetry, not a confirmed detection or a complete execution history.',
 'behavior_telemetry':'Signature hashes are not executable-content hashes; module/parent references and numeric flags are not verified execution, ancestry or confidence.',
 'injection_monitoring':'Monitoring notification is not a verified malicious injection or prevention; PID reuse prevents uncorroborated process-instance identity.',
 'file_scan':'A scan failure is not proof of malware or bypass; file access is not file creation or modification.',
 'remediation':'Inspect the original action and status; an attempt does not establish successful remediation.'}



def encoding(head):
    if head.startswith(codecs.BOM_UTF16_LE):return 'utf-16-le'
    if head.startswith(codecs.BOM_UTF16_BE):return 'utf-16-be'
    if b'\x00' in head[:200]:
        if head[1:100:2].count(0)>20:return 'utf-16-le'
        if head[:100:2].count(0)>20:return 'utf-16-be'
    return 'utf-8'


def supported(path):
    from .sqlite_recovery import regular
    regular(path)
    with open(path,'rb') as handle:head=handle.read(65536)
    text=head.decode(encoding(head),errors='replace').lstrip('\ufeff')
    return any(marker in text for marker in MARKERS)


def chunks(handle,enc):
    """Byte-aligned physical lines, bounded fragments for excessive lines."""
    newline='\n'.encode(enc);pending=b'';offset=0;line=1;unit=2 if enc.startswith('utf-16') else 1
    while True:
        block=handle.read(65536)
        pending+=block
        while pending:
            end=pending.find(newline)
            while end>=0 and end%unit:end=pending.find(newline,end+1)
            if end>=0 and end+len(newline)<=MAX_CHUNK:
                end+=len(newline);terminated=True
            elif len(pending)>=MAX_CHUNK:end=MAX_CHUNK;terminated=False
            elif not block:end=len(pending);terminated=False
            else:break
            raw=pending[:end];pending=pending[end:]
            yield raw,offset,line,terminated
            offset+=end
            if terminated:line+=1
        if not block:break


def validate_policy(policy):
    if policy not in ('format-utc','unknown','UTC') and not re.fullmatch(r'[+-](?:0\d|1[0-3]):[0-5]\d|[+-]14:00',policy):
        raise ValueError('Defender time policy must be format-utc, unknown, UTC or an explicit +/-HH:MM offset')
    return policy


def timestamp(value,slot,meaning,policy='format-utc',convention=None):
    validate_policy(policy)
    iso=re.fullmatch(r'(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(\.\d{1,9})?(Z|[+-]\d\d:\d\d)?',value)
    bm=re.fullmatch(r'(\d\d)-(\d\d)-(\d{4}) (\d\d:\d\d:\d\d)(\.\d{1,9})?(Z|[+-]\d\d:\d\d)?',value)
    result=dict(slot=slot,original_value=value,encoding='recorded text',source='Defender diagnostic log',meaning=meaning,
                precision_ns=None,timestamp_utc=None,normalization_status='unsupported_format',
                original_format='unsupported',interpretation_basis='none',parser_version=VERSION,policy=policy,uncertainty=[])
    if not value:result['normalization_status']='missing';return result
    if not iso and not bm:return result
    if iso:
        date,clock,fraction,zone=iso.groups();result['original_format']='ISO8601'
    else:
        month,day,year,clock,fraction,zone=bm.groups();date=f'{year}-{month}-{day}';result['original_format']='MM-DD-YYYY HH:MM:SS'
    text=date+'T'+clock+(fraction or '')
    result['precision_ns']=10**(9-len(fraction[1:])) if fraction else 1000000000
    # Validate even unresolved local times, without consulting the host timezone.
    try:required_time(text+(zone or 'Z'))
    except ValueError:result['normalization_status']='invalid';return result
    if zone:basis='explicit recorded offset'
    elif policy=='unknown':basis='analyst selected unknown timezone'
    elif policy!='format-utc':zone='Z' if policy=='UTC' else policy;basis='explicit analyst-assigned timezone'
    elif (convention=='mplog-leading' and iso) or (convention=='bm-creation' and bm):
        zone='Z';basis='Defender format UTC convention: '+convention
        result['uncertainty']=['Format-based UTC interpretation corroborated by forensic parsers; not an explicit offset in the original.']
    else:basis='No validated timezone convention for this field/format'
    result['interpretation_basis']=basis
    if zone:result.update(timestamp_utc=required_time(text+zone),normalization_status='normalized')
    else:result['normalization_status']='timezone_unknown'
    return result


def interpret(text,incomplete=False,*,policy='format-utc',log_kind='mplog'):
    fields=[];warnings=[];category='unknown';values={};stamps=[]
    m=STAMP.match(text)
    if m:
        value=m[1]
        if m.end()<len(text) and not text[m.end()].isspace():
            value+=text[m.end():].split(None,1)[0]  # Never normalize a valid prefix of an unsupported suffix.
        stamps.append(timestamp(value,'observation','Log observation time; not process start',policy,'mplog-leading' if log_kind=='mplog' else None))
    body=text[m.end():].strip() if m else text.strip()
    def add(name,value):
        fields.append(dict(name=name,value=value));values.setdefault(name,value)
    if 'BEGIN BM telemetry' in body:
        category='behavior_telemetry'
        for line in body.splitlines():
            match=re.match(r'\s*([^:\r\n]+):\s*(.*)',line)
            if match:add(match[1].strip(),match[2])
        if 'END BM telemetry' not in body:incomplete=True
        for i,entry in enumerate(fields):
            if entry['name'] in ('CreationTime','ProcessCreationTime'):
                value=entry['value'];meaning='Telemetry creation time' if entry['name']=='CreationTime' else 'Process creation time'
                if entry['name']=='ProcessCreationTime' and re.fullmatch(r'(?:0x[0-9a-fA-F]+|\d{17,18})',value):
                    converted=filetime(int(value,16 if value.startswith('0x') else 10),f'field:{i}',entry['name'],meaning+'; ProcessCreationTime FILETIME variant')
                    converted.update(original_value=value,original_format='FILETIME',interpretation_basis='Windows FILETIME UTC epoch',parser_version=VERSION,policy=policy,uncertainty=[]);stamps.append(converted)
                else:stamps.append(timestamp(value,f'field:{i}',meaning,policy,'bm-creation' if entry['name']=='CreationTime' else None))
        if 'Taint Info' in values:
            for match in re.finditer(r'(Friendly|Reason|Modules|Parents):\s*(.*?)(?=\s+(?:Friendly|Reason|Modules|Parents):|$)',values['Taint Info']):
                add('Taint '+match[1],match[2])
            warnings.append('Taint suffixes, Friendly and ThreatLevel are not independently validated verdicts; parent references are not a process tree.')
    elif 'Engine:command line reported as lowfi:' in body:
        category='lowfi';command=body.split('Engine:command line reported as lowfi:',1)[1].lstrip();add('command',command)
        # Only a unique .exe( boundary and closing delimiter permit lossless splitting.
        boundaries=list(re.finditer(r'\.exe\(',command,re.I))
        if len(boundaries)==1 and command.endswith(')'):
            at=boundaries[0].end()-1;add('ImagePath',command[:at]);add('CommandLine',command[at+1:-1])
        else:warnings.append('Image/command boundary ambiguous; complete command retained.')
    elif 'ASR Notification:' in body:
        category='asr_notification';value=body.split('ASR Notification:',1)[1]
        names=('Process','Action','Target','Reason','Persisted','Rule')
        matches=list(re.finditer(r'(?:^|,\s*)('+ '|'.join(names)+r'):\s*',value))
        for i,match in enumerate(matches):add(match[1],value[match.end():matches[i+1].start() if i+1<len(matches) else len(value)].strip())
        if [f['name'] for f in fields]!=list(names):
            warnings.append('ASR field boundaries incomplete or ambiguous; inspect original text.');incomplete=True;fields=[]
    elif (match:=re.search(r'Engine:Process (\d+) will be fully monitored because of injection from (.+)',body)):
        category='injection_monitoring';add('ProcessID',match[1]);add('ImagePath',match[2]);add('MonitoringReason',match[0])
    elif '[Mini-filter]' in body or 'RTP' in body and ('minifilter' in body.lower() or 'minfil' in body.lower()):
        category='file_scan'
        scan_body=body
        if '[Mini-filter]' in body:
            intro,separator,tail=body.split('[Mini-filter]',1)[1].partition(' Process:')
            label,colon,path=intro.partition(':')
            if separator and colon:
                add('ScanObservation',label.strip());add('Path',path.strip());scan_body='Process:'+tail
        labels=list(re.finditer(r'(?:^|[,;]\s*|\s)(Path|Process|Status|ScanRequest|FileId|Reason|State|FileAttributes|ScanAttributes|AccessStateFlags|IoStatusBlockForNewFile|DesiredAccess|BackingFileInfo)(?::\s*|\s+)',scan_body))
        for i,match in enumerate(labels):
            add(match[1],scan_body[match.end():labels[i+1].start() if i+1<len(labels) else len(scan_body)].rstrip(',; '))
    else:
        for marker,kind in (('DETECTION_ADD','detection'),('Detection add:','detection'),('Threat detected:','detection'),('Remediation:','remediation'),
            ('signature thrott','signature_throttling'),('dynamic signature','signature_update'),('Signature updated','signature_update'),('signature match','signature_observation'),
            ('lowfi signature','signature_observation'),('behavior signature','signature_observation'),('cloud','cloud_diagnostic'),
            ('configuration','configuration'),('version','version'),('service start','service_start')):
            if marker.lower() in body.lower():category=kind;break
        # Preserve opaque field names and statuses; never infer outcomes from keywords.
        labels=list(re.finditer(r'\b(SignatureID|SigSha|Resource|ThreatID|Action|Status|Outcome|ImagePath|Target|Version)\s*[:=]\s*',body))
        for i,match in enumerate(labels):
            value=body[match.end():labels[i+1].start() if i+1<len(labels) else len(body)].rstrip(',; ')
            add(match[1],value)
    if any(t['normalization_status']=='invalid' for t in stamps):
        warnings.append('Invalid timestamp retained without inventing a normalized time.')
    if any(t['normalization_status'] in ('unsupported_format','timezone_unknown') for t in stamps):
        warnings.append('Timestamp interpretation unresolved; original record completeness is assessed independently.')
    if incomplete:warnings.append('Incomplete or size-fragmented original record; do not infer completeness.')
    return category,fields,stamps,warnings


def parse(path,sha,**options):
    policy=validate_policy(options.get('defender_time_policy','format-utc'))
    log_kind='mplog' if Path(options.get('_source_path',path)).name.lower().startswith('mplog-') else 'other'
    if not supported(path):raise ValueError('No recognized Defender text markers in initial 64 KiB; unsupported input, not ingested')
    with open(path,'rb') as handle:
        head=handle.read(256);enc=encoding(head);handle.seek(0)
        block=[];size=0;ordinal=0;continuation=False
        def pack(parts,fragment=False,structural_reason='size_fragmented'):
            nonlocal ordinal
            raw=b''.join(p[0] for p in parts);decode_error=False
            try:text=raw.decode(enc)
            except UnicodeDecodeError:text=raw.decode(enc,errors='backslashreplace');decode_error=True
            category,fields,stamps,warnings=interpret(text.lstrip('\ufeff'),fragment,policy=policy,log_kind=log_kind)
            if decode_error:warnings.append('Undecodable bytes escaped in text; exact original bytes retained as base64.')
            if category=='unknown':warnings.append('Unknown record semantics; original preserved.')
            locator=dict(ordinal=ordinal,line_start=parts[0][2],line_end=parts[-1][2],offset=parts[0][1],end_offset=parts[-1][1]+len(parts[-1][0]))
            eid=f'DEFENDER:{sha}:Offset:{locator["offset"]}'
            detail=dict(category=category,fields=fields,text=text,raw_base64=base64.b64encode(raw).decode(),encoding=enc,
                        parsing_status='partial' if fragment or decode_error or any('Incomplete' in w for w in warnings) else 'unknown' if category=='unknown' else 'parsed',
                        limitations=[LIMITATION,*([CAUTIONS[category]] if category in CAUTIONS else []),*warnings])
            group_text=text.lstrip('\ufeff');observed=STAMP.match(group_text)
            if observed:group_text=group_text[observed.end():]
            grouping=dump([category,group_text.strip()])
            detail.update(timestamp_interpretations=stamps,parser_version=VERSION,time_policy=policy,
                          structural_status=structural_reason if fragment else 'incomplete' if any('Incomplete' in w for w in warnings) else 'complete',
                          decoding_status='limited' if decode_error else 'complete',group_key=grouping,group_id=hashlib.sha256(grouping.encode()).hexdigest())
            objects=[dict(slot='group',role='defender_group',original=detail['group_id'])]
            roles={'ImagePath':'process_image','Process':'process_image','Path':'file_path','Target':'file_path'}
            for i,f in enumerate(fields):
                if f['name'] in roles:objects.append(dict(slot=str(i),role=roles[f['name']],original=f['value']))
                elif f['name'] in ('ProcessID','Rule','SignatureID','Action','CommandLine','command'):
                    objects.append(dict(slot=str(i),role='defender_'+f['name'].lower(),original=f['value']))
            ordinal+=1
            advance(phase='parsing',records=ordinal,bytes_read=locator['end_offset'])
            return dict(record=dict(evidence_id=eid,source_type='defender',artifact_type=category,locator_json=dump(locator),
                                   warnings_json=dump(warnings),original_json=dump(detail)),detail=detail,objects=objects,timestamps=stamps)
        for item in chunks(handle,enc):
            text=item[0].decode(enc,errors='replace')
            if block and ('BEGIN BM telemetry' in text or size+len(item[0])>MAX_CHUNK):
                yield pack(block,True,'incomplete' if 'BEGIN BM telemetry' in text else 'size_fragmented');block=[];size=0
            if block or 'BEGIN BM telemetry' in text:
                block.append(item);size+=len(item[0])
                if 'END BM telemetry' in text:yield pack(block);block=[];size=0
            else:yield pack([item],continuation or len(item[0])>=MAX_CHUNK)
            continuation=not item[3] and len(item[0])>=MAX_CHUNK
        if block:yield pack(block,True,'incomplete')

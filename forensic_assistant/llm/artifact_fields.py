"""Semantic minimum for small local-model contexts; originals remain queryable."""
import json


def compact_artifact(record):
    truncated=[]
    def short(value,field):
        if not isinstance(value,str):return value
        result=value[:220]
        while len(json.dumps(result,ensure_ascii=True))>450:result=result[:-1]
        if result!=value:truncated.append(field)
        return result
    result={'id':record['id'],'source_type':record['source_type'],'artifact_type':record['artifact_type']}
    if record.get('hostname'):result['hostname']=record['hostname'];result['host_context_basis']=record['context']['basis']
    if record.get('username'):result['username']=record['username']
    stamps=[t for t in record.get('timestamps',[]) if t['timestamp_utc']]
    if record['source_type']=='mft':stamps.sort(key=lambda t:({'MFT SI Created':0,'MFT FN Created':1}.get(t['source'],2),t['slot']))
    result['timestamps']=[{'utc':t['timestamp_utc'],'type':t['source'],'meaning':t['meaning'],'precision_ns':t['precision_ns']} for t in stamps[:2]]
    if len(stamps)>2:truncated.append(f'timestamps: {len(stamps)-2} omitted')
    objects=[o['original'] for o in record.get('objects',[]) if o['role'] in ('file_path','filename','persistence_target','executable_name')]
    if objects:result['objects']=[short(p,'objects') for p in objects[:2]]
    if len(objects)>2 or record.get('objects_truncated'):truncated.append('objects')
    detail=record.get('detail',{})
    if record['source_type']=='mft':
        result.update(record_number=detail['record_number'],sequence=detail['sequence_number'],allocated=bool(detail['allocated']))
    elif record['source_type']=='prefetch':
        result.update(executable=short(detail['executable'],'executable'),run_count=detail['run_count'],format_version=detail['format_version'])
        if detail['reference_count']:truncated.append('referenced files: inspect show --raw')
    elif record['source_type']=='registry':
        result.update(hive=detail['hive']['hive_type'],key=short(detail['key_path'],'key'))
        if 'value_name' in detail:
            result.update(value_name=short(detail['value_name'],'value_name'),value_type=detail['value_type'],key_evidence_id=detail['key_id'])
            value=detail['value_data']
            result['value_data']=short(value,'value_data') if isinstance(value,str) else value if isinstance(value,(int,float,type(None))) else 'Binary/list data omitted; inspect show --raw'
            if isinstance(value,(dict,list)):truncated.append('value_data')
    if record.get('warnings'):result['warnings']=[short(w,'warnings') for w in record['warnings'][:2]]
    if len(record.get('warnings',[]))>2:truncated.append('warnings')
    if truncated:result['truncated_fields']=truncated
    return result

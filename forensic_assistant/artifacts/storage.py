"""Validated adapter output to typed tables; source identities never overwritten."""
import base64
from forensic_assistant.database.artifacts import register,add_timestamp,add_object,dump


def store(db, pack, sha, path, parser, version):
    record=pack['record'];eid=record['evidence_id']
    inserted=register(db,dict(**record,file_sha256=sha,source_file=path,parser_name=parser,parser_version=version))
    if not inserted:return 0
    for t in pack.get('timestamps',[]):add_timestamp(db,eid,t)
    for o in pack.get('objects',[]):add_object(db,eid,o['slot'],o['role'],o['original'])
    d=pack['detail'];kind=record['source_type']
    if kind=='mft':
        db.execute('INSERT INTO mft_records VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                   (eid,d['record_number'],d['sequence_number'],d['allocated'],d['directory'],d.get('file_size'),
                    d['base_record'],d['base_sequence'],d['record_size'],dump(d['attributes']),base64.b64decode(d['raw'])))
        for n in d['names']:
            db.execute('INSERT INTO mft_names VALUES (?,?,?,?,?,?,?,?)',(eid,n['slot'],n['filename'],n['namespace'],
                       n['parent_record'],n['parent_sequence'],None,'unresolved'))
    elif kind=='prefetch':
        db.execute('INSERT INTO prefetch_records VALUES (?,?,?,?,?,?,?)',(eid,d['executable'],d['prefetch_identifier'],d['run_count'],d['format_version'],base64.b64decode(d['raw']),dump(d['metrics'])))
        db.executemany('INSERT INTO prefetch_references VALUES (?,?,?)',[(eid,i,p) for i,p in enumerate(d['references'])])
        db.executemany('INSERT INTO prefetch_volumes VALUES (?,?,?,?,?)',[(eid,i,v['device_path'],v['serial_number'],v['creation_filetime']) for i,v in enumerate(d['volumes'])])
    elif kind=='registry':
        h=d['hive']
        db.execute('INSERT INTO registry_hives VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING',(sha,h['type'],h['basis'],h['dirty'],dump(h['warnings'])))
        if record['artifact_type']=='registry_key':
            db.execute('INSERT INTO registry_keys VALUES (?,?,?,?)',(eid,d['key_path'],d['parent_id'],d['offset']))
        else:
            db.execute('INSERT INTO registry_values VALUES (?,?,?,?,?,?,?)',(eid,d['key_id'],d['value_name'],d['value_type'],
                       base64.b64decode(d['raw_data']),dump(d['decoded']),d['offset']))
    return inserted


def base_record(eid,kind,subtype,locator,warnings=None,original=None):
    return dict(evidence_id=eid,source_type=kind,artifact_type=subtype,locator_json=dump(locator),
                warnings_json=dump(warnings or []),original_json=dump(original or {}))

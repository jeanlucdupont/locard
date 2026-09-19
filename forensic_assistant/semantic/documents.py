"""Versioned bounded projections; no parser or embedding imports."""
import hashlib
import json
from contextlib import contextmanager

VERSION = '1'
MAX_FIELD = 16384
MAX_CHUNKS = 16
MAX_CHARS = 65536


@contextmanager
def snapshot(db):
    # One snapshot for validation, SQL filtering and hydration, including WAL DBs.
    db.execute('SAVEPOINT semantic_read')
    try:
        yield
    finally:
        db.execute('ROLLBACK TO semantic_read')
        db.execute('RELEASE semantic_read')


def fingerprint(db):
    """Hash every authoritative table/cell in bounded pieces, including raw bytes.

    Deliberately conservative: run/provenance-only changes also invalidate an index.
    Physical row ordering changes may invalidate it even with equivalent content.
    Caller holds a consistent SQLite snapshot. No file-stat/WAL assumptions.
    """
    h = hashlib.sha256()
    def feed(value):
        value = value if isinstance(value, bytes) else str(value).encode('utf-8')
        h.update(len(value).to_bytes(8, 'little')); h.update(value)
    def quoted(name):
        return '"' + name.replace('"', '""') + '"'
    feed(db.execute('PRAGMA user_version').fetchone()[0])
    tables = db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    for name, ddl in tables:
        feed(name); feed(ddl)
        cols = [r[1] for r in db.execute('PRAGMA table_info('+quoted(name)+')')]
        expressions = []
        for col in cols:
            col = quoted(col)
            expressions += [f'typeof({col})', f'length(CAST({col} AS BLOB))', f'substr(CAST({col} AS BLOB),1,65536)']
        for row in db.execute('SELECT rowid,'+','.join(expressions)+' FROM '+quoted(name)+' ORDER BY rowid'):
            feed('row')
            for i, col in enumerate(cols):
                kind, size, value = row[1+i*3:4+i*3]
                feed(kind); feed(size); feed(value or b'')
                for offset in range(65536, size or 0, 65536):
                    value = db.execute('SELECT substr(CAST('+quoted(col)+' AS BLOB),?,65536) FROM '+quoted(name)+' WHERE rowid=?', (offset+1,row[0])).fetchone()[0]
                    feed(value)
    return h.hexdigest()


def _fields(db, table, key, eid, columns, limit=1):
    # Identifiers are code-owned constants. Bounds apply before Python hydration.
    expr = ','.join('substr(CAST('+c+' AS TEXT),1,?) AS '+c for c in columns)
    rows = db.execute('SELECT '+expr+' FROM '+table+' WHERE '+key+'=? ORDER BY rowid LIMIT ?', [MAX_FIELD+1]*len(columns)+[eid,limit+1]).fetchall()
    result=[]; clipped=len(rows)>limit
    for row in rows[:limit]:
        obj={}
        for col,value in zip(columns,row):
            if value is not None:
                clipped |= len(value)>MAX_FIELD
                obj[col]=value[:MAX_FIELD]
        result.append(obj)
    return result,clipped


def representation(db, eid):
    base, clipped = _fields(db,'evidence_records','evidence_id',eid,
        ['evidence_id','source_type','artifact_type','file_sha256','source_file','hostname','username','warnings_json'])
    if not base:raise ValueError('Evidence ID not found')
    record=base[0]; kind=record['source_type']
    def add(label,table,key,columns,limit=1,target=eid):
        nonlocal clipped
        rows,cut=_fields(db,table,key,target,columns,limit)
        record[label]=rows;clipped |= cut
    add('timestamp_observations','evidence_timestamps','evidence_id',
        ['slot','timestamp_utc','original_value','encoding','source','meaning','normalization_status'],32)
    add('object_observations','evidence_objects','evidence_id',['role','original','path_kind','warnings_json'],64)
    add('analyst_assertions','source_contexts','file_sha256',['hostname','username','volume_root','basis'],8,record['file_sha256'])
    if kind=='evtx':
        add('reported_event','events','id',['event_id','provider','channel','username','process_name','parent_process_name','command_line','script_block','source_ip','destination_ip','logon_type','service_name','task_name'])
        record['semantics']='Reported event fields; parent fields alone do not establish a parent record relationship.'
    elif kind=='mft':
        add('filesystem_metadata','mft_records','evidence_id',['record_number','sequence_number','allocated','directory','file_size'])
        add('names','mft_names','evidence_id',['filename','namespace','reconstructed_path','path_status'],32)
        record['semantics']='SI and FN timestamps are filesystem metadata, not proof of download or execution.'
    elif kind=='prefetch':
        add('execution_observations','prefetch_records','evidence_id',['executable','run_count','format_version'])
        add('referenced_paths','prefetch_references','evidence_id',['path'],64)
        record['semantics']='Retained execution times are incomplete. Referenced paths do not prove execution of those files.'
    elif kind=='registry':
        if record['artifact_type']=='registry_value':
            add('value_snapshot','registry_values','evidence_id',['key_id','value_name','value_type','decoded_json'])
            key=record['value_snapshot'][0]['key_id']
            value=record['value_snapshot'][0]
            if value.get('value_type') not in ('1','2','6','7','4','5','11') or value.get('decoded_json','').lstrip().startswith('{'):
                value.pop('decoded_json',None)
                value['omitted_data']='Binary/undecodable value; inspect original evidence'
            add('containing_key','registry_keys','evidence_id',['key_path'],target=key)
            add('containing_key_last_write','evidence_timestamps','evidence_id',['slot','timestamp_utc','meaning'],8,key)
        else:add('key_snapshot','registry_keys','evidence_id',['key_path'])
        record['semantics']='Registry snapshot. Last-write belongs to the containing key, not individual value creation.'
    else:raise ValueError('Unsupported evidence source')
    # Identity/provenance remain in the mapping and original registry; long hashes
    # and acquisition paths are not useful language-model retrieval features.
    projection={k:v for k,v in record.items() if k not in ('evidence_id','file_sha256','source_file')}
    text=json.dumps(projection,ensure_ascii=True,sort_keys=True,separators=(',',':'))
    clipped |= len(text)>MAX_CHARS
    return record,text[:MAX_CHARS],bool(clipped)


def chunks(db,eid,tokenizer):
    record,text,clipped=representation(db,eid)
    header='Artifact: '+record['source_type']+'; subtype: '+record['artifact_type']+'; '+record['semantics']+'\n'
    # Character windows preserve exact substrings; token limits are measured with
    # the pinned tokenizer. No decode/re-encode reconstruction of forensic text.
    position=0; output=[]
    while position<len(text) and len(output)<MAX_CHUNKS:
        end=min(position+1600,len(text))
        while end>position and tokenizer.count(header+text[position:end])>tokenizer.document_limit:
            end=position+(end-position)//2
        if end==position:raise ValueError('Representation header exceeds model token limit')
        value=header+text[position:end]
        output.append({'evidence_id':eid,'source_type':record['source_type'],
          'artifact_type':record['artifact_type'],'chunk_id':f'{VERSION}:{position}:{end}',
          'text':value,'digest':hashlib.sha256(value.encode()).hexdigest()})
        position=end
    clipped |= position<len(text)
    return output,bool(clipped)

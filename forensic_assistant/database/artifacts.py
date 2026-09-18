"""Schema-3 common registry. Original EVTX rows remain authoritative and immutable."""
import json
from forensic_assistant.database.context import host_key

VERSION = "1"
DDL = (
    """CREATE TABLE evidence_records (
      evidence_id TEXT PRIMARY KEY, source_type TEXT NOT NULL, artifact_type TEXT NOT NULL,
      file_sha256 TEXT NOT NULL REFERENCES evidence_files(sha256), source_file TEXT NOT NULL,
      locator_json TEXT NOT NULL, hostname TEXT, username TEXT,
      parser_name TEXT, parser_version TEXT, extractor_version TEXT NOT NULL,
      warnings_json TEXT NOT NULL, original_json TEXT NOT NULL)""",
    "CREATE INDEX evidence_source ON evidence_records(file_sha256,source_type,evidence_id)",
    "CREATE INDEX evidence_type ON evidence_records(source_type,artifact_type,evidence_id)",
    """CREATE TABLE evidence_timestamps (
      evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id), slot TEXT NOT NULL,
      timestamp_utc TEXT, original_value TEXT, encoding TEXT, source TEXT NOT NULL,
      meaning TEXT NOT NULL, precision_ns INTEGER, normalization_status TEXT NOT NULL,
      PRIMARY KEY(evidence_id,slot))""",
    "CREATE INDEX artifact_time ON evidence_timestamps(timestamp_utc,evidence_id,slot)",
    """CREATE TABLE evidence_objects (
      evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id), slot TEXT NOT NULL,
      role TEXT NOT NULL, original TEXT NOT NULL, normalized TEXT, basename TEXT,
      path_kind TEXT NOT NULL, warnings_json TEXT NOT NULL,
      PRIMARY KEY(evidence_id,slot))""",
    "CREATE INDEX object_path ON evidence_objects(normalized,evidence_id)",
    "CREATE INDEX object_basename ON evidence_objects(basename,evidence_id)",
    """CREATE TABLE source_contexts (
      context_id TEXT PRIMARY KEY, file_sha256 TEXT NOT NULL REFERENCES evidence_files(sha256),
      hostname TEXT, username TEXT, volume_root TEXT, basis TEXT NOT NULL,
      source_file TEXT NOT NULL, recorded_utc TEXT NOT NULL)""",
    "CREATE INDEX context_source ON source_contexts(file_sha256)",
    "CREATE INDEX context_host ON source_contexts(hostname,file_sha256)",
    """CREATE TABLE artifact_runs (run_id INTEGER PRIMARY KEY REFERENCES ingestion_runs(id),
      source_type TEXT NOT NULL, parser_name TEXT NOT NULL, parser_version TEXT,
      extractor_version TEXT NOT NULL, source_sha256 TEXT, parameters_json TEXT NOT NULL)""",
    """CREATE TABLE artifact_errors (error_id INTEGER PRIMARY KEY REFERENCES ingestion_errors(id),
      locator_json TEXT NOT NULL)""",
    """CREATE TABLE mft_records (evidence_id TEXT PRIMARY KEY REFERENCES evidence_records(evidence_id),
      record_number INTEGER NOT NULL, sequence_number INTEGER NOT NULL, allocated INTEGER NOT NULL,
      directory INTEGER NOT NULL, file_size INTEGER, base_record INTEGER, base_sequence INTEGER,
      record_size INTEGER NOT NULL, attributes_json TEXT NOT NULL, raw_record BLOB NOT NULL)""",
    """CREATE TABLE mft_names (evidence_id TEXT NOT NULL REFERENCES mft_records(evidence_id),
      slot TEXT NOT NULL, filename TEXT NOT NULL, namespace INTEGER, parent_record INTEGER,
      parent_sequence INTEGER, reconstructed_path TEXT, path_status TEXT NOT NULL,
      PRIMARY KEY(evidence_id,slot))""",
    "CREATE INDEX mft_parent ON mft_names(parent_record,parent_sequence)",
    """CREATE TABLE prefetch_records (evidence_id TEXT PRIMARY KEY REFERENCES evidence_records(evidence_id),
      executable TEXT, prefetch_identifier INTEGER, run_count INTEGER, format_version INTEGER NOT NULL,
      raw_file BLOB NOT NULL, metrics_json TEXT NOT NULL)""",
    """CREATE TABLE prefetch_references (evidence_id TEXT NOT NULL REFERENCES prefetch_records(evidence_id),
      ordinal INTEGER NOT NULL, path TEXT NOT NULL, PRIMARY KEY(evidence_id,ordinal))""",
    """CREATE TABLE prefetch_volumes (evidence_id TEXT NOT NULL REFERENCES prefetch_records(evidence_id),
      ordinal INTEGER NOT NULL, device_path TEXT, serial_number INTEGER, creation_filetime TEXT,
      PRIMARY KEY(evidence_id,ordinal))""",
    """CREATE TABLE registry_hives (file_sha256 TEXT PRIMARY KEY REFERENCES evidence_files(sha256),
      hive_type TEXT NOT NULL, identity_basis TEXT NOT NULL, dirty INTEGER NOT NULL,
      warnings_json TEXT NOT NULL)""",
    """CREATE TABLE registry_keys (evidence_id TEXT PRIMARY KEY REFERENCES evidence_records(evidence_id),
      key_path TEXT NOT NULL, parent_id TEXT REFERENCES registry_keys(evidence_id), cell_offset INTEGER NOT NULL)""",
    """CREATE TABLE registry_values (evidence_id TEXT PRIMARY KEY REFERENCES evidence_records(evidence_id),
      key_id TEXT NOT NULL REFERENCES registry_keys(evidence_id), value_name TEXT NOT NULL,
      value_type INTEGER NOT NULL, raw_data BLOB NOT NULL, decoded_json TEXT, cell_offset INTEGER NOT NULL)""",
    "CREATE INDEX registry_key_values ON registry_values(key_id,evidence_id)",
    "CREATE INDEX registry_path ON registry_keys(key_path COLLATE NOCASE)",
    """CREATE TABLE registry_views (evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id),
      extractor TEXT NOT NULL, version TEXT NOT NULL, category TEXT NOT NULL,
      details_json TEXT NOT NULL, PRIMARY KEY(evidence_id,extractor))""",
    "CREATE INDEX registry_category ON registry_views(category,evidence_id)",
)


def dump(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def register(db, record):
    names = ('evidence_id','source_type','artifact_type','file_sha256','source_file','locator_json',
             'hostname','username','parser_name','parser_version','extractor_version','warnings_json','original_json')
    data = {**dict(hostname=None, username=None, parser_name=None, parser_version=None,
                  extractor_version=VERSION, warnings_json='[]', original_json='{}'), **record}
    return db.execute('INSERT INTO evidence_records ('+','.join(names)+') VALUES ('+
                      ','.join('?' for _ in names)+') ON CONFLICT DO NOTHING',
                      [data[k] for k in names]).rowcount


def add_timestamp(db, eid, stamp):
    keys = ('slot','timestamp_utc','original_value','encoding','source','meaning','precision_ns','normalization_status')
    db.execute('INSERT INTO evidence_timestamps VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING',
               [eid, *(stamp.get(k) for k in keys)])


def add_object(db, eid, slot, role, original):
    from forensic_assistant.artifacts.paths import normalize_path
    p = normalize_path(original)
    db.execute('INSERT INTO evidence_objects VALUES (?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING',
               (eid,slot,role,original,p['normalized'],p['basename'],p['kind'],dump(p['warnings'])))


def project_events(db, rows,parser_name=None,parser_version=None):
    for row in rows:
        e = dict(row)
        if not register(db, dict(evidence_id=e['id'], source_type='evtx',artifact_type=e['artifact_type'] or 'event',
                                file_sha256=e['file_sha256'],source_file=e['source_file'],
                                locator_json=dump({'offset':e['record_offset'],'record_id':e['record_id']}),
                                hostname=host_key(e['hostname']),username=e['username'],
                                parser_name=parser_name,parser_version=parser_version,
                                extractor_version=e['normalizer_version'],warnings_json=e['normalization_warnings_json'])):
            continue
        add_timestamp(db,e['id'],dict(slot='SystemTime',timestamp_utc=e['timestamp_utc'],original_value=e['timestamp_original'],
                      encoding='parser-rendered ISO8601',source='EVTX SystemTime',meaning='Event timestamp',precision_ns=None,
                      normalization_status=e['timestamp_status']))
        for field,role in (('process_name','process_image'),('parent_process_name','parent_image')):
            if e[field]: add_object(db,e['id'],field,role,e[field])


def upgrade3(db):
    for sql in DDL: db.execute(sql)
    cursor = db.execute('SELECT * FROM events ORDER BY id')
    while rows := cursor.fetchmany(500): project_events(db,rows)
    db.execute('PRAGMA user_version=3')

"""Source assertions and occurrences; never rewrites artifact-derived evidence."""
import uuid
from forensic_assistant.database.db import now
from forensic_assistant.database.context import host_key
from forensic_assistant.artifacts.context import normalize_volume_root


DDL = (
    """CREATE TABLE sources (source_id TEXT PRIMARY KEY, created_utc TEXT NOT NULL,
        creation_basis TEXT NOT NULL CHECK(creation_basis IN ('analyst','automatic')))""",
    """CREATE TABLE source_assertions (
        assertion_id INTEGER PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(source_id),
        display_name TEXT NOT NULL, hostname TEXT, username TEXT, volume_root TEXT,
        recorded_utc TEXT NOT NULL, basis TEXT NOT NULL,
        supersedes INTEGER UNIQUE REFERENCES source_assertions(assertion_id))""",
    "CREATE INDEX source_assertion_history ON source_assertions(source_id,assertion_id)",
    """CREATE TABLE ingestion_batches (batch_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL REFERENCES sources(source_id), started_utc TEXT NOT NULL,
        finished_utc TEXT, requested_path TEXT NOT NULL, command TEXT NOT NULL,
        status TEXT NOT NULL)""",
    "ALTER TABLE ingestion_runs ADD COLUMN batch_id TEXT REFERENCES ingestion_batches(batch_id)",
    "CREATE INDEX ingestion_batch_runs ON ingestion_runs(batch_id,file_sha256)",
    """CREATE TABLE source_assignments (assignment_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL REFERENCES sources(source_id), recorded_utc TEXT NOT NULL,
        basis TEXT NOT NULL, reason TEXT NOT NULL)""",
    """CREATE TABLE source_assignment_files (
        assignment_id TEXT NOT NULL REFERENCES source_assignments(assignment_id),
        file_sha256 TEXT NOT NULL REFERENCES evidence_files(sha256),
        PRIMARY KEY(assignment_id,file_sha256))""",
)


def upgrade4(db):
    """Caller owns the migration transaction. No historical memberships inferred."""
    if db.execute('PRAGMA user_version').fetchone()[0] != 3:
        raise ValueError('Source migration requires schema 3')
    for sql in DDL:
        db.execute(sql)
    db.execute('PRAGMA user_version=4')


def require4(db):
    if db.execute('PRAGMA user_version').fetchone()[0] != 4:
        raise ValueError('Source operations require schema 4; explicitly upgrade this case first')


def identifier(prefix):
    return prefix+'-'+uuid.uuid4().hex


def current(db, source_id):
    require4(db)
    row=db.execute('''SELECT s.*,a.* FROM sources s JOIN source_assertions a USING(source_id)
        WHERE s.source_id=? ORDER BY a.assertion_id DESC LIMIT 1''',(source_id,)).fetchone()
    if row is None:raise ValueError('Source ID not found')
    data=dict(row);data['updated_utc']=data['recorded_utc']
    return data


def metadata(name,hostname,username,volume_root):
    for value in (name,hostname,username,volume_root):
        if value is not None and (not isinstance(value,str) or len(value)>4096 or '\x00' in value):
            raise ValueError('Invalid source metadata')
    return (name,host_key(hostname) if hostname else None,username or None,normalize_volume_root(volume_root))


def create(db, *, name=None, hostname=None, username=None, volume_root=None, automatic=False):
    require4(db)
    sid=identifier('src')
    values=metadata(name or 'Source '+sid[4:16],hostname,username,volume_root)
    stamp=now()
    # Caller owns the transaction, including any associated batch creation.
    db.execute('INSERT INTO sources VALUES (?,?,?)',(sid,stamp,'automatic' if automatic else 'analyst'))
    db.execute('''INSERT INTO source_assertions
        (source_id,display_name,hostname,username,volume_root,recorded_utc,basis,supersedes)
        VALUES (?,?,?,?,?,?,?,NULL)''',(sid,*values,stamp,'analyst-supplied; generated label' if not name else 'analyst-supplied'))
    return sid


def update(db, source_id, **changes):
    old=current(db,source_id)
    if not changes or set(changes)-{'display_name','hostname','username','volume_root'}:
        raise ValueError('Specify source metadata to update')
    data={**old,**changes}
    if not data['display_name']:raise ValueError('Source display name must not be empty')
    values=metadata(*(data[k] for k in ('display_name','hostname','username','volume_root')))
    db.execute('''INSERT INTO source_assertions
        (source_id,display_name,hostname,username,volume_root,recorded_utc,basis,supersedes)
        VALUES (?,?,?,?,?,?,?,?)''',(source_id,*values,now(),'analyst-supplied',old['assertion_id']))
    return current(db,source_id)


MEMBERSHIP = '''SELECT b.source_id,r.file_sha256 FROM ingestion_batches b
    JOIN ingestion_runs r USING(batch_id) WHERE r.file_sha256 IS NOT NULL
    UNION SELECT a.source_id,f.file_sha256 FROM source_assignments a
    JOIN source_assignment_files f USING(assignment_id)'''


def memberships(db, sha):
    if db.execute('PRAGMA user_version').fetchone()[0] != 4:return []
    ids=[r[0] for r in db.execute('SELECT source_id FROM ('+MEMBERSHIP+') WHERE file_sha256=? ORDER BY source_id LIMIT 101',(sha,))]
    if len(ids)>100:raise ValueError('Source membership exceeds retrieval bound; inspect source-specific provenance')
    return [current(db,sid) for sid in ids]


def assign(db, source_id, hashes, *, reason, selection_basis=None):
    current(db,source_id)
    hashes=sorted(set(hashes))
    if not hashes or len(hashes)>1000 or not reason.strip() or len(reason)>4096:raise ValueError('Select 1..1000 explicit file hashes and a reason of 1..4096 characters')
    for sha in hashes:
        if not db.execute('SELECT 1 FROM evidence_files WHERE sha256=?',(sha,)).fetchone():
            raise ValueError('Selected file hash not found: '+sha)
    aid=identifier('assign')
    basis='retrospective analyst assignment'+('; '+selection_basis if selection_basis else '')
    db.execute('INSERT INTO source_assignments VALUES (?,?,?,?,?)',(aid,source_id,now(),basis,reason))
    db.executemany('INSERT INTO source_assignment_files VALUES (?,?)',[(aid,sha) for sha in hashes])
    return aid


def summary(db, source_id):
    data=current(db,source_id)
    data['batches']=db.execute('SELECT count(*) FROM ingestion_batches WHERE source_id=?',(source_id,)).fetchone()[0]
    data['files']=db.execute('SELECT count(*) FROM ('+MEMBERSHIP+') WHERE source_id=?',(source_id,)).fetchone()[0]
    data['artifacts']={r[0]:r[1] for r in db.execute('''SELECT e.source_type,count(*) FROM evidence_records e
        JOIN ('''+MEMBERSHIP+''') m USING(file_sha256) WHERE m.source_id=? GROUP BY e.source_type''',(source_id,))}
    data['evidence_count']=sum(data['artifacts'].values())
    data['artifact_hostnames']=[r[0] for r in db.execute('''SELECT DISTINCT e.hostname FROM evidence_records e
        JOIN ('''+MEMBERSHIP+''') m USING(file_sha256) WHERE m.source_id=? AND e.hostname IS NOT NULL ORDER BY e.hostname LIMIT 101''',(source_id,))]
    data['artifact_hostnames_truncated']=len(data['artifact_hostnames'])>100
    hosts={host_key(h) for h in data['artifact_hostnames'] if h}
    if data['hostname']:hosts.add(data['hostname'])
    data['host_conflict']=len(hosts)>1
    data['artifact_hostnames']=data['artifact_hostnames'][:100]
    data['limitations']=[]
    if not data['hostname']:data['limitations'].append('Analyst hostname unknown; source membership alone does not establish a host')
    if data['host_conflict']:data['limitations'].append('Conflicting source/artifact hostname assertions')
    data['ambiguous_files']=db.execute('''SELECT count(*) FROM ('''+MEMBERSHIP+''') m WHERE source_id=?
        AND EXISTS (SELECT 1 FROM ('''+MEMBERSHIP+''') other WHERE other.file_sha256=m.file_sha256 AND other.source_id<>m.source_id)''',(source_id,)).fetchone()[0]
    if data['ambiguous_files']:data['limitations'].append('Some content identities occur in multiple sources')
    return data


def listing(db, limit=100, offset=0):
    require4(db)
    if not 1<=limit<=1000 or offset<0:raise ValueError('Invalid pagination bounds')
    total=db.execute('SELECT count(*) FROM sources').fetchone()[0]
    ids=[r[0] for r in db.execute('SELECT source_id FROM sources ORDER BY created_utc,source_id LIMIT ? OFFSET ?',(limit,offset))]
    return dict(sources=[summary(db,s) for s in ids],total=total,limit=limit,offset=offset,truncated=offset+len(ids)<total)


def detail(db, source_id, limit=100, offset=0):
    if not 1<=limit<=1000 or offset<0:raise ValueError('Invalid pagination bounds')
    data=summary(db,source_id)
    for key,table,column,order in (
        ('assertion_history','source_assertions','source_id','assertion_id'),
        ('batch_history','ingestion_batches','source_id','started_utc,batch_id'),
        ('retrospective_assignments','source_assignments','source_id','recorded_utc,assignment_id')):
        total=db.execute('SELECT count(*) FROM '+table+' WHERE '+column+'=?',(source_id,)).fetchone()[0]
        rows=[dict(r) for r in db.execute('SELECT * FROM '+table+' WHERE '+column+'=? ORDER BY '+order+' LIMIT ? OFFSET ?',(source_id,limit,offset))]
        if table=='source_assertions':
            for row in rows:
                row['active']=row['assertion_id']==data['assertion_id']
                next_row=db.execute('SELECT assertion_id FROM source_assertions WHERE supersedes=?',(row['assertion_id'],)).fetchone()
                row['superseded_by']=next_row[0] if next_row else None
        data[key]=dict(records=rows,total=total,limit=limit,offset=offset,truncated=offset+len(rows)<total)
    total=db.execute('SELECT count(*) FROM ingestion_runs r JOIN ingestion_batches b USING(batch_id) WHERE b.source_id=?',(source_id,)).fetchone()[0]
    rows=[dict(r) for r in db.execute('''SELECT r.* FROM ingestion_runs r JOIN ingestion_batches b USING(batch_id)
        WHERE b.source_id=? ORDER BY r.id LIMIT ? OFFSET ?''',(source_id,limit,offset))]
    data['file_occurrences']=dict(records=rows,total=total,limit=limit,offset=offset,truncated=offset+len(rows)<total)
    total=db.execute('SELECT count(*) FROM source_assignment_files f JOIN source_assignments a USING(assignment_id) WHERE a.source_id=?',(source_id,)).fetchone()[0]
    rows=[dict(r) for r in db.execute('''SELECT f.* FROM source_assignment_files f JOIN source_assignments a USING(assignment_id)
        WHERE a.source_id=? ORDER BY f.assignment_id,f.file_sha256 LIMIT ? OFFSET ?''',(source_id,limit,offset))]
    data['retrospective_files']=dict(records=rows,total=total,limit=limit,offset=offset,truncated=offset+len(rows)<total)
    return data


def coverage(db):
    if db.execute('PRAGMA user_version').fetchone()[0]!=4:
        return dict(schema=3,limitations=['Legacy source and batch membership unknown; no historical batches inferred'])
    result=listing(db)
    result['unassigned_files']=db.execute('SELECT count(*) FROM evidence_files f WHERE NOT EXISTS (SELECT 1 FROM ('+MEMBERSHIP+') m WHERE m.file_sha256=f.sha256)').fetchone()[0]
    result['unfinished_batches']=db.execute("SELECT count(*) FROM ingestion_batches WHERE finished_utc IS NULL").fetchone()[0]
    result['cleanup_unconfirmed_batches']=db.execute("SELECT count(*) FROM ingestion_batches WHERE status='cleanup_unconfirmed'").fetchone()[0]
    result['unknown_hostname_sources']=db.execute('''SELECT count(*) FROM source_assertions a WHERE hostname IS NULL
        AND NOT EXISTS (SELECT 1 FROM source_assertions n WHERE n.supersedes=a.assertion_id)''').fetchone()[0]
    result['limitations']=['Unfinished batches may reflect an active or abnormally terminated operation; completion is not inferred'] if result['unfinished_batches'] else []
    if result['cleanup_unconfirmed_batches']:result['limitations'].append('Worker cleanup was not confirmed for some batches; inspect operational state before further ingestion')
    return result

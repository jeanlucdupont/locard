"""Schema-5 browser contexts and explicit run-specific record provenance."""
import hashlib
from .artifacts import dump

DDL = (
    """CREATE TABLE browser_contexts (
        context_id TEXT PRIMARY KEY, main_file_sha256 TEXT NOT NULL REFERENCES evidence_files(sha256),
        browser_product TEXT NOT NULL CHECK(browser_product IN ('chrome','edge')),
        profile TEXT NOT NULL, snapshot_sha256 TEXT NOT NULL, manifest_json TEXT NOT NULL)""",
    """CREATE TABLE browser_record_occurrences (
        evidence_id TEXT NOT NULL REFERENCES evidence_records(evidence_id),
        context_id TEXT NOT NULL REFERENCES browser_contexts(context_id),
        run_id INTEGER NOT NULL REFERENCES ingestion_runs(id),
        PRIMARY KEY(evidence_id,run_id))""",
    'CREATE INDEX browser_occurrence_context ON browser_record_occurrences(context_id,run_id,evidence_id)',
    'CREATE INDEX browser_occurrence_run ON browser_record_occurrences(run_id,evidence_id)',
)


def upgrade5(db):
    if db.execute('PRAGMA user_version').fetchone()[0] != 4:
        raise ValueError('Browser migration requires schema 4')
    for statement in DDL:
        db.execute(statement)
    db.execute('PRAGMA user_version=5')


def require5(db):
    if db.execute('PRAGMA user_version').fetchone()[0] != 5:
        raise ValueError('Browser ingestion requires schema 5; explicitly run case-upgrade --yes (creates a backup)')


def context_id(sha, product, profile):
    return 'BROWSERCTX:' + hashlib.sha256(dump([sha, product, profile]).encode()).hexdigest()


MEMBERSHIP = '''SELECT DISTINCT o.evidence_id,b.source_id FROM browser_record_occurrences o
 JOIN ingestion_runs r ON r.id=o.run_id JOIN ingestion_batches b USING(batch_id)'''


def provenance(db, evidence_id):
    """One bounded join for source assertions and run occurrences, never per-run queries."""
    rows = db.execute('''SELECT s.*,a.*,r.id AS ingestion_run_id,r.batch_id,
        r.source_file AS ingestion_path,r.status AS ingestion_status,
        c.context_id AS browser_context_id,c.browser_product,c.profile,c.snapshot_sha256,
        ar.parameters_json AS ingestion_parameters
        FROM browser_record_occurrences o JOIN browser_contexts c USING(context_id)
        JOIN ingestion_runs r ON r.id=o.run_id JOIN ingestion_batches b USING(batch_id)
        JOIN sources s ON s.source_id=b.source_id JOIN source_assertions a ON a.source_id=s.source_id
        LEFT JOIN artifact_runs ar ON ar.run_id=r.id
        WHERE o.evidence_id=? AND NOT EXISTS
          (SELECT 1 FROM source_assertions newer WHERE newer.supersedes=a.assertion_id)
        ORDER BY r.id LIMIT 10001''', (evidence_id,)).fetchall()
    if len(rows) > 10000:
        raise ValueError('Browser occurrence retrieval exceeds 10000-run bound')
    members, occurrences = {}, []
    source_keys = ('source_id', 'created_utc', 'creation_basis', 'assertion_id', 'display_name',
                   'hostname', 'username', 'volume_root', 'recorded_utc', 'basis', 'supersedes')
    import json
    for row in rows:
        source = {key: row[key] for key in source_keys}
        source['updated_utc'] = source['recorded_utc']
        members[source['source_id']] = source
        occurrences.append(dict(run_id=row['ingestion_run_id'], batch_id=row['batch_id'],
                                source_id=source['source_id'], source_file=row['ingestion_path'],
                                status=row['ingestion_status'], context_id=row['browser_context_id'],
                                browser_product=row['browser_product'], profile=row['profile'],
                                snapshot_sha256=row['snapshot_sha256'],
                                parameters=json.loads(row['ingestion_parameters'] or '{}')))
    if len(members) > 100:
        raise ValueError('Browser source membership exceeds retrieval bound')
    return [members[key] for key in sorted(members)], occurrences

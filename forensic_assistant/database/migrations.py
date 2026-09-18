"""Explicit additive schema upgrade with an exclusive-name local backup."""
from pathlib import Path
import sqlite3
import uuid
from forensic_assistant.database.context import insert_context

SCHEMA_VERSION = 3
STATEMENTS = (
    """CREATE TABLE event_context (
    evidence_id TEXT PRIMARY KEY REFERENCES events(id), host_key TEXT, timestamp_utc TEXT,
    kind TEXT, pid INTEGER, ppid INTEGER, process_guid TEXT, parent_process_guid TEXT,
    subject_logon_key TEXT, target_logon_key TEXT, process_logon_key TEXT,
    subject_account TEXT, target_account TEXT, subject_sid TEXT, target_sid TEXT,
    source_ip_key TEXT, version TEXT NOT NULL, warnings_json TEXT NOT NULL)""",
    "CREATE INDEX ctx_host_time ON event_context(host_key,timestamp_utc,evidence_id)",
    "CREATE INDEX ctx_pid ON event_context(host_key,pid,timestamp_utc)",
    "CREATE INDEX ctx_ppid ON event_context(host_key,ppid,timestamp_utc)",
    "CREATE INDEX ctx_guid ON event_context(host_key,process_guid,timestamp_utc)",
    "CREATE INDEX ctx_parent_guid ON event_context(host_key,parent_process_guid,timestamp_utc)",
    "CREATE INDEX ctx_subject_logon ON event_context(host_key,subject_logon_key,timestamp_utc)",
    "CREATE INDEX ctx_target_logon ON event_context(host_key,target_logon_key,timestamp_utc)",
    "CREATE INDEX ctx_process_logon ON event_context(host_key,process_logon_key,timestamp_utc)",
    "CREATE INDEX ctx_kind_time ON event_context(kind,timestamp_utc,evidence_id)",
    "CREATE INDEX ctx_auth ON event_context(host_key,target_account,source_ip_key,timestamp_utc)",
)


def upgrade(db):
    for statement in STATEMENTS:
        db.execute(statement)
    cursor = db.execute("SELECT * FROM events ORDER BY id")
    while rows := cursor.fetchmany(500):
        insert_context(db, rows)
    if db.execute("PRAGMA foreign_key_check").fetchone():
        raise ValueError("Foreign key validation failed")
    if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        raise ValueError("Database integrity validation failed")
    db.execute("PRAGMA user_version=2")


def migrate(path):
    source = Path(path).resolve(strict=True)
    db = sqlite3.connect(source)
    db.row_factory = sqlite3.Row
    backup = None
    try:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("BEGIN IMMEDIATE")
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version == SCHEMA_VERSION:
            db.rollback()
            return {"status": "current", "schema_version": version, "backup": None}
        if version not in (1, 2):
            raise ValueError(f"Cannot migrate schema version {version}; expected schema 1 or 2")
        backup = source.with_name(source.name + f".schema{version}-backup-" + uuid.uuid4().hex + ".sqlite")
        # Exclusive creation prevents overwriting anything, including another backup.
        with backup.open("xb"):
            pass
        reader = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
        destination = sqlite3.connect(backup)
        try:
            reader.backup(destination)
        finally:
            destination.close()
            reader.close()
        if version == 1:
            upgrade(db)
        from forensic_assistant.database.artifacts import upgrade3
        upgrade3(db)
        if db.execute('PRAGMA foreign_key_check').fetchone() or db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise ValueError('Schema-3 integrity validation failed')
        db.commit()
        return {"status": "migrated", "schema_version": 3, "backup": str(backup)}
    except Exception as exc:
        db.rollback()
        raise ValueError(f"Migration rolled back: {exc}. Backup: {backup or 'not created'}") from exc
    finally:
        db.close()

from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from forensic_assistant.model import NormalizedEvent
from forensic_assistant.database.context import insert_context
from forensic_assistant.database.migrations import upgrade


def now():
    return datetime.now(timezone.utc).isoformat()


def connect(path):
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    version = db.execute("PRAGMA user_version").fetchone()[0]
    if version in (1, 2):
        db.close()
        raise ValueError("Unsupported legacy database schema; an existing schema-3 case is required")
    if version not in (0, 3):
        db.close()
        raise ValueError(f"Unsupported database schema version: {version}")
    db.execute("PRAGMA foreign_keys=ON")
    if version == 0:
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table'").fetchone():
            db.close()
            raise ValueError("Unversioned nonempty database; refusing to modify it")
        db.executescript(Path(__file__).with_name("schema.sql").read_text())
        with db:
            upgrade(db)
            from forensic_assistant.database.artifacts import upgrade3
            upgrade3(db)
    return db


def register_source(db, sha, size, path):
    db.execute("INSERT INTO evidence_files VALUES (?, ?, ?) ON CONFLICT DO NOTHING", (sha, size, now()))
    db.execute("INSERT INTO source_locations VALUES (?, ?) ON CONFLICT DO NOTHING", (sha, str(path)))


def insert_events(db, events,*,parser_name=None,parser_version=None):
    events = list(events)
    # Identifiers come exclusively from the fixed dataclass, never user input.
    names = [f.name for f in fields(NormalizedEvent)]
    sql = "INSERT INTO events (" + ",".join(names) + ") VALUES (" + ",".join("?" for _ in names) + ") ON CONFLICT(id) DO NOTHING"
    before = db.total_changes
    db.executemany(sql, [tuple(getattr(e, name) for name in names) for e in events])
    inserted = db.total_changes - before
    # On duplicate ingestion derive context from the preserved row, not a later input.
    if events:
        preserved = [db.execute("SELECT * FROM events WHERE id=?", (e.id,)).fetchone() for e in events]
        insert_context(db, preserved)
        from forensic_assistant.database.artifacts import project_events
        project_events(db, preserved,parser_name,parser_version)
    return inserted

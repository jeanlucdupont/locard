from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from forensic_assistant.model import NormalizedEvent


def now():
    return datetime.now(timezone.utc).isoformat()


def connect(path):
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    version = db.execute("PRAGMA user_version").fetchone()[0]
    if version not in (0, 1):
        db.close()
        raise ValueError(f"Unsupported database schema version: {version}")
    db.executescript(Path(__file__).with_name("schema.sql").read_text())
    return db


def register_source(db, sha, size, path):
    db.execute("INSERT INTO evidence_files VALUES (?, ?, ?) ON CONFLICT DO NOTHING", (sha, size, now()))
    db.execute("INSERT INTO source_locations VALUES (?, ?) ON CONFLICT DO NOTHING", (sha, str(path)))


def insert_events(db, events):
    # Identifiers come exclusively from the fixed dataclass, never user input.
    names = [f.name for f in fields(NormalizedEvent)]
    sql = "INSERT INTO events (" + ",".join(names) + ") VALUES (" + ",".join("?" for _ in names) + ") ON CONFLICT(id) DO NOTHING"
    before = db.total_changes
    db.executemany(sql, [tuple(getattr(e, name) for name in names) for e in events])
    return db.total_changes - before

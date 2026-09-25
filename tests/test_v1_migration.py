from pathlib import Path
import sqlite3
import pytest
from forensic_assistant.database.db import connect, insert_events, register_source
from forensic_assistant.database import migrations
from forensic_assistant.database.context import extract, canonical_id
from forensic_assistant.ingest.normalize import normalize
from test_ingest import xml, SHA


def old_database(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript((Path(__file__).parents[1] / "forensic_assistant/database/schema.sql").read_text())
    with db:
        register_source(db, SHA, 1, "original.evtx")
        event = normalize(xml(), SHA, "original.evtx", 512).as_dict()
        db.execute("INSERT INTO events (" + ",".join(event) + ") VALUES (" + ",".join("?" for _ in event) + ")", list(event.values()))
    original = dict(db.execute("SELECT * FROM events").fetchone())
    db.close()
    return original


def test_explicit_migration_preserves_every_field(tmp_path):
    path = tmp_path / "old.db"
    original = old_database(path)
    with pytest.raises(ValueError, match="Unsupported legacy database schema"):
        connect(path)
    result = migrations.migrate(path)
    db = connect(path)
    assert dict(db.execute("SELECT * FROM events").fetchone()) == original
    assert db.execute("SELECT count(*) FROM event_context").fetchone()[0] == 1
    assert db.execute("PRAGMA user_version").fetchone()[0] == 3
    backup = sqlite3.connect(result["backup"])
    assert backup.execute("PRAGMA user_version").fetchone()[0] == 1
    assert migrations.migrate(path)["status"] == "current"
    backup.close(); db.close()


def test_migration_failure_rolls_back(tmp_path, monkeypatch):
    path = tmp_path / "old.db"
    original = old_database(path)
    def fail(db):
        db.execute("CREATE TABLE should_rollback(x)")
        raise RuntimeError("simulated failure")
    monkeypatch.setattr(migrations, "upgrade", fail)
    with pytest.raises(ValueError, match="rolled back"):
        migrations.migrate(path)
    db = sqlite3.connect(path)
    assert db.execute("PRAGMA user_version").fetchone()[0] == 1
    assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='should_rollback'").fetchone()
    assert list(tmp_path.glob("*.sqlite"))
    db.close()


def test_context_roles_and_unknown_fields():
    event = normalize(xml(data='<Data Name="SubjectLogonId">0x42</Data><Data Name="TargetLogonId">0x43</Data>'), SHA, "x", 1)
    context = extract(event.as_dict())
    assert context["subject_logon_key"] == "66"
    assert context["process_logon_key"] == "67"
    assert canonical_id("0x0") is None
    assert canonical_id("invalid") is None
    raw = xml(4647, data='<Data Name="SubjectLogonId">0x42</Data>')
    assert extract(normalize(raw, SHA, "x", 1).as_dict())["kind"] == "logoff_request"


def test_new_database_and_duplicate_context():
    db = connect(":memory:")
    with db:
        register_source(db, SHA, 1, "original")
        event = normalize(xml(), SHA, "original", 512)
        assert insert_events(db, [event]) == 1
        event.hostname = "other-host"
        assert insert_events(db, [event]) == 0
    assert db.execute("SELECT host_key FROM event_context").fetchone()[0] == "pc.example"
    assert db.execute("SELECT source_file FROM events").fetchone()[0] == "original"
    db.close()

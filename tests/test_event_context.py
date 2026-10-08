import sqlite3
import pytest
from forensic_assistant.database.db import connect, insert_events, register_source
from forensic_assistant.database.context import extract, canonical_id
from forensic_assistant.ingest.normalize import normalize
from test_ingest import xml, SHA


def test_context_roles_and_unknown_fields():
    event = normalize(
        xml(data='<Data Name="SubjectLogonId">0x42</Data><Data Name="TargetLogonId">0x43</Data>'),
        SHA,
        "x",
        1
    )
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


@pytest.mark.parametrize('version', [1, 2])
def test_unsupported_legacy_schema_is_rejected_without_changes(tmp_path, version):
    path = tmp_path / 'legacy.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE sentinel(value TEXT)')
        db.execute("INSERT INTO sentinel VALUES ('preserved')")
        db.execute(f'PRAGMA user_version={version}')
    db.close()
    before = path.read_bytes()
    with pytest.raises(ValueError, match='Unsupported legacy database schema'):
        connect(path)
    assert path.read_bytes() == before

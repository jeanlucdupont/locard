import json
import pytest
from forensic_assistant.database.db import connect, insert_events, register_source
from forensic_assistant.ingest.normalize import normalize
from forensic_assistant.correlation.temporal import events_before, events_after, events_around, shift
from forensic_assistant.cli import main
from test_ingest import xml, SHA


def fixture_db(path=":memory:"):
    db = connect(path)
    with db:
        register_source(db, SHA, 1, "synthetic.evtx")
        for index, time in enumerate(["14:30:00", "14:31:00", "14:32:00", "14:31:00"]):
            raw = xml(record_id=index).replace("14:30:55.1234567", time)
            if index == 3:
                raw = raw.replace("PC.example", "OTHER")
            insert_events(db, [normalize(raw, SHA, "synthetic.evtx", 512 + index)])
    return db


def test_temporal_boundaries_and_host():
    db = fixture_db()
    anchor = db.execute("SELECT id FROM events WHERE record_offset=513").fetchone()[0]
    assert events_before(db, anchor, 60).total == 1
    assert events_after(db, anchor, 60).total == 1
    assert events_around(db, anchor, 60).total == 3
    assert events_around(db, anchor, 0).total == 1
    assert shift("2026-09-15T14:31:00.123456789Z", 1).endswith("01.123456789Z")
    with pytest.raises(ValueError, match="not found"):
        events_around(db, "unknown", 1)
    db.close()


def test_timeline_cli_compatibility_filters_and_text(tmp_path, capsys):
    path = tmp_path / "case.db"
    fixture_db(path).close()
    prefix = ["--db", str(path), "timeline"]
    assert main(prefix + ["2026-09-15T14:31:00Z", "--minutes", "1"]) == 0
    old = json.loads(capsys.readouterr().out)
    assert old["total"] == 4
    assert main(prefix + ["--start", "2026-09-15T14:30:00Z", "--end", "2026-09-15T14:32:00Z", "--hostname", "PC.example", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["total"] == 3
    assert [e["timestamp_utc"] for e in data["records"]] == sorted(e["timestamp_utc"] for e in data["records"])
    assert main(prefix + ["--around", "2026-09-15T14:31:00Z", "--text"]) == 0
    assert "EVIDENCE ID" in capsys.readouterr().out
    assert main(prefix + ["--start", "2026-09-15T14:30:00Z"]) == 2

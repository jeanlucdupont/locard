import pytest
from forensic_assistant.model import NormalizedEvent, evidence_id, utc_timestamp
from forensic_assistant.database.db import connect, register_source, insert_events

SHA = "a" * 64


def test_timestamp():
    assert utc_timestamp("2026-09-15T16:30:55.1234567+02:00") == ("2026-09-15T14:30:55.123456700Z", "normalized")
    assert utc_timestamp("2016-07-08 18:12:51.681641+00:00") == ("2016-07-08T18:12:51.681641000Z", "normalized")
    assert utc_timestamp("2026-09-15T14:30:55")[1] == "ambiguous"
    assert utc_timestamp("bad")[1] == "invalid"
    assert utc_timestamp(None)[1] == "missing"
    assert utc_timestamp("2026-02-30T00:00:00Z")[1] == "invalid"


def test_ids():
    assert evidence_id(SHA, 512) == evidence_id(SHA, 512)
    assert evidence_id(SHA, 512) != evidence_id("b" * 64, 512)
    with pytest.raises(ValueError):
        evidence_id("bad", 1)


def test_duplicate_path_provenance():
    db = connect(":memory:")
    with db:
        register_source(db, SHA, 1234, "original.evtx")
        event = NormalizedEvent(evidence_id(SHA, 512), SHA, "original.evtx", 512, "<Event/>")
        assert insert_events(db, [event]) == 1
        register_source(db, SHA, 1234, "copy.evtx")
        event.source_file = "copy.evtx"
        assert insert_events(db, [event]) == 0
    assert db.execute("SELECT source_file FROM events").fetchone()[0] == "original.evtx"
    assert db.execute("SELECT count(*) FROM source_locations").fetchone()[0] == 2


def test_transaction_rollback():
    db = connect(":memory:")
    with pytest.raises(RuntimeError), db:
        register_source(db, SHA, 1, "a")
        raise RuntimeError()
    assert db.execute("SELECT count(*) FROM evidence_files").fetchone()[0] == 0

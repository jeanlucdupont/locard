import pytest
from forensic_assistant.detections.engine import detections, available_rules
from forensic_assistant.database.db import insert_events
from forensic_assistant.model import NormalizedEvent
from v1_fixtures import database, add, process


def ids(db, **kwargs):
    return {d["rule_id"] for d in detections(db, **kwargs)["detections"]}


def test_office_and_powershell():
    db = database()
    event = process(db, 1, 20, 10, data={"CommandLine": "powershell -enc AAA; IEX; DownloadString; FromBase64String"})
    assert ids(db) == {"LOCARD-PROC-001", "LOCARD-PS-001"}
    for detection in detections(db)["detections"]:
        assert detection["evidence_ids"] == [event["id"]]
        assert detection["limitations"] and detection["rule_version"]


@pytest.mark.parametrize("event_id,rule", [(4698, "LOCARD-TASK-001"), (4697, "LOCARD-SVC-001"), (4720, "LOCARD-ACCOUNT-001"), (4648, "LOCARD-CRED-001")])
def test_event_rules(event_id, rule):
    db = database()
    add(db, 1, event_id)
    assert rule in ids(db)


def test_audit_rule_and_provider_collision():
    from test_ingest import xml, SHA
    from forensic_assistant.ingest.normalize import normalize
    db = database()
    with db:
        insert_events(db, [normalize(xml(1102, "Microsoft-Windows-Eventlog"), SHA, "x", 1)])
        insert_events(db, [normalize(xml(4698, "Unrelated"), SHA, "x", 2)])
    assert ids(db) == {"LOCARD-AUDIT-001"}


def test_lexical_false_positive_boundaries():
    db = database()
    process(db, 1, 20, parent="notwinword.exe", data={"CommandLine": "powershell -encoding utf8; IExplorer"})
    assert not ids(db)
    add(db, 2, 4702)
    assert "LOCARD-TASK-001" not in ids(db)


def test_failed_then_success_threshold_window_and_source():
    db = database()
    fields = {"TargetUserName": "bob", "TargetDomainName": "DOMAIN", "IpAddress": "192.0.2.1"}
    for n in range(4):
        add(db, n + 1, 4625, time=f"14:30:0{n}", data=fields)
    success = add(db, 10, 4624, time="14:31:00", data=fields)
    assert "LOCARD-AUTH-001" not in ids(db)
    add(db, 5, 4625, time="14:30:05", data=fields)
    assert "LOCARD-AUTH-001" in ids(db)
    result = detections(db, rule_id="LOCARD-AUTH-001")
    assert len(result["detections"][0]["evidence_ids"]) == 6
    assert not detections(db, rule_id="LOCARD-AUTH-001", failure_window_seconds=10)["detections"]
    add(db, 11, 4624, time="14:31:01", data={**fields, "IpAddress": "192.0.2.2"})
    assert len(detections(db, rule_id="LOCARD-AUTH-001")["detections"]) == 1


def test_duplicate_observations_do_not_inflate_failures():
    db = database()
    fields = {"TargetUserName": "bob", "IpAddress": "192.0.2.1"}
    event = add(db, 1, 4625, data=fields)
    original = dict(db.execute("SELECT * FROM events WHERE id=?", (event["id"],)).fetchone())
    for n in range(2, 8):
        copied = NormalizedEvent(**{**original, "id": event["id"].replace("Offset:1", "Offset:" + str(n)), "record_offset": n})
        with db:
            insert_events(db, [copied])
    add(db, 20, 4624, time="14:31:00", data=fields)
    assert "LOCARD-AUTH-001" not in ids(db)


def test_limits_and_rule_metadata():
    db = database()
    for n in range(3):
        add(db, n + 1, 4698)
    result = detections(db, candidate_limit=1)
    assert result["truncated"]
    assert len(available_rules()) == 8
    assert not ids(db, severity="high")
    with pytest.raises(ValueError):
        detections(db, rule_id="unknown")

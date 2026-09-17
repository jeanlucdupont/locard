import json
import sqlite3
import pytest
from forensic_assistant.cli import main
from forensic_assistant.database.context import extract
from forensic_assistant.correlation.models import get_event
from forensic_assistant.correlation.processes import process_tree
from forensic_assistant.correlation.investigation import investigate
from forensic_assistant.llm.context import context_bundle
from forensic_assistant.retrieval.queries import Queries
from v1_fixtures import database, add, process


@pytest.mark.parametrize("command", ["timeline", "process-tree", "logons", "session", "detections", "around", "investigate", "analyze-timeline"])
def test_all_investigative_cli_json(tmp_path, capsys, command):
    db = database()
    add(db, 1, 4624, data={"TargetLogonId": "0x10", "TargetUserName": "bob"})
    event = process(db, 2, 20, time="14:30:05", data={"SubjectLogonId": "0x10"})
    args = {
        "timeline": ["--around", "2026-09-15T14:30:00Z"],
        "process-tree": ["--evidence", event["id"]], "logons": ["--user", "bob"],
        "session": ["--logon-id", "0x10", "--hostname", "PC.example"],
        "detections": [], "around": [event["id"]], "investigate": [event["id"]],
        "analyze-timeline": ["--start", "2026-09-15T14:29:00Z", "--end", "2026-09-15T14:31:00Z", "--dry-run"],
    }
    path = tmp_path / "case.db"
    dest = sqlite3.connect(path)
    db.backup(dest); dest.close(); db.close()
    assert main(["--db", str(path), command, *args[command], "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert isinstance(result, dict)


def test_context_indexes_used():
    db = database()
    process(db, 1, 10)
    for predicate, args, index in [
        ("host_key=? AND pid=? AND timestamp_utc>=?", ("pc.example", 10, "2026"), "ctx_pid"),
        ("host_key=? AND process_guid=?", ("pc.example", "guid"), "ctx_guid"),
        ("host_key=? AND target_logon_key=? AND timestamp_utc>=?", ("pc.example", "10", "2026"), "ctx_target_logon"),
    ]:
        plan = db.execute("EXPLAIN QUERY PLAN SELECT evidence_id FROM event_context WHERE " + predicate, args).fetchall()
        assert index in " ".join(str(row[3]) for row in plan)


def test_nearest_neighbors_and_atomic_projection():
    db = database()
    for n in range(1, 20):
        add(db, n, 9999, time=f"14:29:{n:02}")
    anchor = add(db, 30, 9999, time="14:30:00")
    near = add(db, 31, 9999, time="14:30:01")
    context = investigate(db, anchor["id"], max_candidates=2)
    assert near["id"] in {e["id"] for e in context["evidence_records"]}
    assert context["limits"]


def test_4647_projection_timeline_without_rewriting_event():
    db = database()
    event = add(db, 1, 4647, data={"SubjectLogonId": "0x10"})
    assert event["artifact_type"] is None
    assert event["kind"] == "logoff_request"
    assert Queries(db).search(artifact_types=["logoff_request"]).total == 1


def test_guid_cycle_is_unresolved():
    db = database()
    a, b = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
    first = add(db, 1, 1, sysmon=True, data={"ProcessGuid": a, "ParentProcessGuid": b, "ProcessId": "10", "ParentProcessId": "20"})
    add(db, 2, 1, sysmon=True, data={"ProcessGuid": b, "ParentProcessGuid": a, "ProcessId": "20", "ParentProcessId": "10"})
    tree = process_tree(db, first["id"])
    assert tree["relationships"]
    assert all(edge["status"] == "UNRESOLVED" for edge in tree["relationships"])


def test_nearest_context_preserves_nanosecond_order():
    db = database()
    add(db, 1, 9999, time="14:30:00.000000100")
    anchor = add(db, 2, 9999, time="14:30:00.000000300")
    nearest = add(db, 3, 9999, time="14:30:00.000000400")
    result = investigate(db, anchor["id"], max_candidates=2)
    assert nearest["id"] in {e["id"] for e in result["evidence_records"]}


def test_equal_time_session_boundaries_are_unresolved():
    from forensic_assistant.correlation.sessions import session
    db = database()
    add(db, 1, 4624, data={"TargetLogonId": "10"})
    add(db, 2, 4634, time="14:30:10", data={"TargetLogonId": "10"})
    add(db, 3, 4608, time="14:30:10")
    result = session(db, "10", hostname="PC.example")
    assert result["status"] == "UNRESOLVED"
    assert "boundaries" in result["reason"]

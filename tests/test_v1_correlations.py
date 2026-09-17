import pytest
from forensic_assistant.correlation.processes import resolve_parent, process_tree
from forensic_assistant.correlation.sessions import session, related_logon_events, logons
from v1_fixtures import database, add, process


def test_pid_parent_and_child():
    db = database()
    parent = process(db, 1, 10, name="WINWORD.EXE")
    child = process(db, 2, 20, 10, time="14:30:10")
    edge = resolve_parent(db, child)
    assert edge["status"] == "LIKELY" and edge["source_id"] == parent["id"]
    tree = process_tree(db, child["id"])
    assert {n["id"] for n in tree["nodes"]} == {parent["id"], child["id"]}
    assert any(e["status"] == "UNRESOLVED" for e in tree["relationships"])


def test_reuse_cross_host_and_missing_parent():
    db = database()
    process(db, 1, 10, name="WINWORD.EXE", host="OTHER")
    child = process(db, 2, 20, 10, time="14:30:10")
    assert resolve_parent(db, child)["status"] == "UNRESOLVED"
    process(db, 3, 10, name="WINWORD.EXE", time="14:29:59")
    assert resolve_parent(db, child)["status"] == "LIKELY"
    process(db, 4, 10, name="WINWORD.EXE", time="14:30:01")
    assert resolve_parent(db, child)["status"] == "UNRESOLVED"


def test_window_and_same_timestamp():
    db = database()
    process(db, 1, 10, name="WINWORD.EXE", time="14:00:00")
    child = process(db, 2, 20, 10, time="14:30:00")
    assert resolve_parent(db, child)["status"] == "UNRESOLVED"
    process(db, 3, 10, name="WINWORD.EXE", time="14:30:00")
    assert resolve_parent(db, child)["status"] == "UNRESOLVED"


def test_guid_confirmed_and_termination():
    db = database()
    guid = "11111111-1111-1111-1111-111111111111"
    parent = add(db, 1, 1, sysmon=True, data={"ProcessGuid": guid, "ProcessId": "10", "Image": "word.exe"})
    child = add(db, 2, 1, sysmon=True, time="14:30:10", data={"ProcessGuid": "22222222-2222-2222-2222-222222222222", "ParentProcessGuid": guid, "ProcessId": "20", "ParentProcessId": "10", "ParentImage": "word.exe"})
    assert resolve_parent(db, child)["status"] == "CONFIRMED"
    add(db, 3, 5, sysmon=True, time="14:30:05", data={"ProcessGuid": guid, "ProcessId": "10"})
    assert resolve_parent(db, child)["status"] == "UNRESOLVED"


def test_session_roles_boundaries_and_hosts():
    db = database()
    start = add(db, 1, 4624, data={"TargetLogonId": "0x42", "TargetUserName": "bob", "TargetDomainName": "DOMAIN"})
    add(db, 2, 4672, time="14:30:01", data={"SubjectLogonId": "66", "SubjectUserName": "bob", "SubjectDomainName": "DOMAIN"})
    proc = process(db, 3, 20, time="14:30:02", data={"SubjectLogonId": "0x42"})
    add(db, 4, 4648, time="14:30:03", data={"SubjectLogonId": "0x42", "TargetUserName": "administrator"})
    add(db, 5, 4647, time="14:30:04", data={"SubjectLogonId": "0x42"})
    add(db, 6, 4634, time="14:30:05", data={"TargetLogonId": "0x42"})
    add(db, 7, 4624, host="OTHER", data={"TargetLogonId": "0x42"})
    assert session(db, "0x42")["status"] == "UNRESOLVED"
    output = session(db, "66", hostname="PC.example")
    assert output["end_reason"] == "logoff"
    assert len(output["records"]) == 6
    assert all(r["status"] == "CONFIRMED" for r in output["relationships"])
    proc_edges = [r for r in output["relationships"] if r["target_id"] == proc["id"]]
    assert [r["relationship"] for r in proc_edges] == ["created_by_session"]
    assert related_logon_events(db, proc["id"])["sessions"]
    assert logons(db, hostname="PC.example").total == 5
    after = session(db, "66", hostname="PC.example", around="2026-09-15T14:31:00Z")
    assert after["status"] == "UNRESOLVED"


def test_boot_and_conflicting_session_account():
    db = database()
    add(db, 1, 4624, data={"TargetLogonId": "10", "TargetUserName": "bob"})
    add(db, 2, 4672, time="14:30:01", data={"SubjectLogonId": "10", "SubjectUserName": "alice"})
    add(db, 3, 4608, time="14:30:02")
    result = session(db, "10", hostname="PC.example")
    assert result["end_reason"] == "boot"
    assert result["relationships"][0]["status"] == "UNRESOLVED"


def test_username_is_not_session_and_reused_id():
    db = database()
    first = add(db, 1, 4624, data={"TargetLogonId": "10", "TargetUserName": "bob"})
    no_key = process(db, 2, 20, time="14:30:05")
    assert related_logon_events(db, no_key["id"])["sessions"] == []
    add(db, 3, 4624, time="15:00:00", data={"TargetLogonId": "10", "TargetUserName": "bob"})
    assert session(db, "10", hostname="PC.example")["status"] == "UNRESOLVED"
    first_session = session(db, "10", anchor_id=first["id"])
    assert first_session["end_reason"] == "logon"
    with pytest.raises(ValueError):
        process_tree(db, "unknown")

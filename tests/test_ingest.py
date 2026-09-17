import json
import pytest
from forensic_assistant.database.db import connect
from forensic_assistant.ingest.normalize import normalize, SECURITY_MAP
from forensic_assistant.ingest.evtx import ParsedRecord, ingest_file, discover, records

SHA = "a" * 64


def xml(event_id=4688, provider="Microsoft-Windows-Security-Auditing", channel="Security", data="", record_id=7):
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
    <Provider Name="{provider}"/><EventID>{event_id}</EventID><Level>0</Level>
    <TimeCreated SystemTime="2026-09-15T14:30:55.1234567Z"/><EventRecordID>{record_id}</EventRecordID>
    <Channel>{channel}</Channel><Computer>PC.example</Computer></System><EventData>{data}</EventData></Event>'''


def test_process():
    raw = xml(data='<Data Name="SubjectUserName">bob</Data><Data Name="SubjectDomainName">DOMAIN</Data><Data Name="NewProcessName">C:\\Windows\\powershell.exe</Data><Data Name="NewProcessId">0x2a</Data><Data Name="ProcessId">15</Data>')
    e = normalize(raw, SHA, "test.evtx", 512)
    assert e.process_id == 42 and e.parent_process_id == 15
    assert e.username == "DOMAIN\\bob" and e.artifact_type == "process"
    assert e.raw_xml == raw and e.command_line is None


@pytest.mark.parametrize("event_id", SECURITY_MAP)
def test_security_types(event_id):
    assert normalize(xml(event_id), SHA, "x", 1).artifact_type == SECURITY_MAP[event_id][0]


def test_unknown_and_provider_collision():
    e = normalize(xml(4688, provider="Other"), SHA, "x", 1)
    assert e.artifact_type is None and e.event_id == 4688
    assert normalize(xml(9999), SHA, "x", 1).raw_xml


def test_powershell_sysmon_and_clear():
    e = normalize(xml(4104, "Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational", '<Data Name="ScriptBlockText">Get-Date</Data>'), SHA, "x", 1)
    assert e.script_block == "Get-Date"
    e = normalize(xml(3, "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", '<Data Name="DestinationIp">::1</Data><Data Name="DestinationPort">443</Data>'), SHA, "x", 1)
    assert e.destination_ip == "::1" and e.destination_port == 443
    e = normalize(xml(1102, "Microsoft-Windows-Eventlog"), SHA, "x", 1)
    assert e.artifact_type == "audit_log_cleared"


def test_bad_fields_and_duplicate_payload():
    e = normalize(xml(data='<Data Name="NewProcessId">bad</Data><Data Name="CommandLine">a</Data><Data Name="CommandLine">b</Data>'), SHA, "x", 1)
    assert e.process_id is None and e.command_line is None
    assert len(json.loads(e.event_data_json)) == 3
    assert len(json.loads(e.normalization_warnings_json)) == 2


def test_unsafe_xml():
    with pytest.raises(Exception):
        normalize('<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>', SHA, "x", 1)


def test_ingestion_duplicate_and_error(tmp_path):
    a, b = tmp_path / "a.evtx", tmp_path / "b.EVTX"
    a.write_bytes(b"fixture"); b.write_bytes(a.read_bytes())
    def reader(path):
        yield ParsedRecord(512, 7, xml())
        yield ParsedRecord(600, 8, "<broken")
        yield ParsedRecord(700, 9, xml(9999, record_id=9))
    db = connect(":memory:")
    first = ingest_file(db, a, batch_size=1, reader=reader)
    second = ingest_file(db, b, reader=reader)
    assert first["inserted"] == 2 and first["errors"] == 1 and first["status"] == "partial"
    assert second["duplicates"] == 2
    assert {r[0] for r in db.execute("SELECT source_file FROM events")} == {str(a.resolve())}
    assert db.execute("SELECT count(*) FROM source_locations").fetchone()[0] == 2
    assert len(list(discover(tmp_path))) == 2


def test_changed_file_rejected(tmp_path):
    source = tmp_path / "a.evtx"
    source.write_bytes(b"before")
    def reader(path):
        yield ParsedRecord(512, 7, xml())
        path.write_bytes(b"after")  # Simulate an external writer, never the parser.
    db = connect(":memory:")
    assert ingest_file(db, source, reader=reader)["status"] == "changed"
    assert db.execute("SELECT count(*) FROM events").fetchone()[0] == 0


def test_real_parser_unreadable(tmp_path):
    source = tmp_path / "bad.evtx"
    source.write_bytes(b"not evtx")
    db = connect(":memory:")
    result = ingest_file(db, source)
    assert result["errors"] >= 1 and result["inserted"] == 0

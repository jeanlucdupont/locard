import pytest
from forensic_assistant.database.db import connect, register_source, insert_events
from forensic_assistant.ingest.normalize import normalize
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.cli import main
from test_ingest import xml, SHA


@pytest.fixture
def queries():
    db = connect(":memory:")
    with db:
        register_source(db, SHA, 1, "a.evtx")
        for n, event_id in enumerate([4624, 4625, 4688, 4697, 4698, 4720, 4672, 4732]):
            data = '<Data Name="TargetUserName">bob</Data><Data Name="SubjectUserName">bob</Data><Data Name="SubjectDomainName">DOMAIN</Data><Data Name="IpAddress">2001:db8::1</Data><Data Name="NewProcessName">C:\\Windows\\powershell.exe</Data>'
            insert_events(db, [normalize(xml(event_id, data=data), SHA, "a.evtx", 512 + n)])
    yield Queries(db)
    db.close()


def test_filters(queries):
    assert queries.events_for_user("bob").total == 8
    assert queries.events_for_user("DOMAIN\\bob").total == 5
    assert queries.events_for_user("' OR 1=1 --").total == 0
    assert queries.events_for_user("%").total == 0
    assert queries.events_for_ip("2001:db8:0:0:0:0:0:1").total == 8
    assert queries.events_by_event_id(4688).total == 1
    assert queries.search(process="powershell.exe").total == 1
    assert queries.search(process="%.exe").total == 0
    assert queries.search(event_id=4688, username="nobody").total == 0


def test_predefined(queries):
    for name, count in [("logons", 2), ("failed_logons", 1), ("processes", 1), ("powershell", 1), ("scheduled_tasks", 1), ("services", 1), ("account_changes", 2)]:
        assert getattr(queries, "find_" + name)().total == count


def test_time_and_paging(queries):
    stamp = "2026-09-15T14:30:55.1234567Z"
    assert queries.events_between(stamp, stamp).total == 8
    assert queries.timeline_around(stamp, minutes=0).total == 8
    assert queries.timeline_around("2026-09-16T14:30:55Z").total == 0
    a, b = queries.search(limit=2), queries.search(limit=2, offset=2)
    assert a.truncated and a.total == 8
    assert {e["id"] for e in a.records}.isdisjoint(e["id"] for e in b.records)
    assert queries.show(a.records[0]["id"])["source_locations"] == ["a.evtx"]
    with pytest.raises(ValueError):
        queries.timeline_around("14:31")
    with pytest.raises(ValueError):
        queries.search(limit=0)
    with pytest.raises(ValueError):
        queries.events_between("2026-09-16T00:00:00Z", "2026-09-15T00:00:00Z")


def test_cli(tmp_path, capsys):
    args = ["--db", str(tmp_path / "case.db")]
    assert main(args + ["search", "--event-id", "4688"]) == 0
    assert '"total": 0' in capsys.readouterr().out
    assert main(args + ["timeline", "14:31"]) == 2
    assert main(args + ["status"]) == 0

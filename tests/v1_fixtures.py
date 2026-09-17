from xml.sax.saxutils import escape
from forensic_assistant.database.db import connect, register_source, insert_events
from forensic_assistant.ingest.normalize import normalize
from forensic_assistant.correlation.models import get_event
from test_ingest import xml, SHA


def database():
    db = connect(":memory:")
    with db:
        register_source(db, SHA, 1, "synthetic.evtx")
    return db


def add(db, offset, event_id=4688, time="14:30:00", host="PC.example", data=None, sysmon=False):
    data = data or {}
    body = "".join(f'<Data Name="{key}">{escape(str(value))}</Data>' for key, value in data.items())
    provider = "Microsoft-Windows-Sysmon" if sysmon else "Microsoft-Windows-Security-Auditing"
    channel = "Microsoft-Windows-Sysmon/Operational" if sysmon else "Security"
    raw = xml(event_id, provider, channel, body, record_id=offset).replace("14:30:55.1234567", time).replace("PC.example", host)
    event = normalize(raw, SHA, "synthetic.evtx", offset)
    with db:
        insert_events(db, [event])
    return get_event(db, event.id)


def process(db, offset, pid, ppid=None, name="powershell.exe", parent="WINWORD.EXE", **kwargs):
    data = {"NewProcessId": pid, "NewProcessName": name, "SubjectUserName": "bob", "SubjectDomainName": "DOMAIN"}
    if ppid is not None:
        data.update(ProcessId=ppid, ParentProcessName=parent)
    data.update(kwargs.pop("data", {}))
    return add(db, offset, data=data, **kwargs)

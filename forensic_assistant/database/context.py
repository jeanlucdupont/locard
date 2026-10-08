"""Versioned derived lookup fields. Original evidence is never rewritten."""
import ipaddress
import json
import uuid
from forensic_assistant.ingest.normalize import SECURITY, SYSMON, number

CONTEXT_VERSION = "1"
COLUMNS = (
    "evidence_id",
    "host_key",
    "timestamp_utc",
    "kind",
    "pid",
    "ppid",
    "process_guid",
    "parent_process_guid",
    "subject_logon_key",
    "target_logon_key",
    "process_logon_key",
    "subject_account",
    "target_account",
    "subject_sid",
    "target_sid",
    "source_ip_key",
    "version",
    "warnings_json"
)


def canonical_id(value):
    try:
        parsed = number(value)
        return str(parsed) if parsed is not None and parsed > 0 else None
    except (ValueError, TypeError, AttributeError):
        return None


def host_key(value):
    return value.strip().casefold().rstrip(".") if value and value.strip() else None


def payload(event):
    """Duplicate fields are ambiguous even when their values happen to agree."""
    result = {}
    for item in json.loads(event["event_data_json"]):
        name = item["name"]
        result[name] = None if name in result else item.get("value")
    return result


def extract(event):
    warnings = []
    try:
        data = payload(event)
    except (ValueError, TypeError, KeyError):
        data = {}
        warnings.append("Payload unavailable; correlation fields not inferred")

    def account(prefix):
        user, domain = data.get(prefix + "UserName"), data.get(prefix + "DomainName")
        if user in (None, "", "-"):
            return None
        return ((domain + "\\" if domain not in (None, "", "-") else "") + user).casefold()

    def guid(name):
        value = data.get(name)
        if not value:
            return None
        try:
            parsed = uuid.UUID(value.strip("{}"))
            return str(parsed) if parsed.int else None
        except (ValueError, AttributeError):
            warnings.append(f"Invalid {name}")
            return None

    result = dict.fromkeys(COLUMNS)
    result.update(
        evidence_id=event["id"],
        host_key=host_key(event["hostname"]),
        timestamp_utc=event["timestamp_utc"],
        kind=event["artifact_type"],
        pid=event["process_id"],
        ppid=event["parent_process_id"],
        version=CONTEXT_VERSION
    )
    if event["provider"] == SECURITY and event["channel"] == "Security":
        result["kind"] = {
            4647: "logoff_request",
            4689: "process_end",
            4608: "boot"
        }.get(event["event_id"], result["kind"])
        for prefix in ("Subject", "Target"):
            key = prefix.lower()
            result[key + "_logon_key"] = canonical_id(data.get(prefix + "LogonId"))
            result[key + "_account"] = account(prefix)
            sid = data.get(prefix + "UserSid")
            result[key + "_sid"] = sid.casefold() if sid and sid != "-" else None
        if event["event_id"] == 4688:
            # Subject identifies the creator. Only an explicit Target identifies execution.
            result["process_logon_key"] = canonical_id(data.get("TargetLogonId"))
        if event["event_id"] == 4689:
            try:
                result["pid"] = number(data.get("ProcessId"))
            except (ValueError, AttributeError):
                warnings.append("Invalid termination ProcessId")
    if event["provider"] == SYSMON and event["channel"] == "Microsoft-Windows-Sysmon/Operational":
        result["kind"] = {1: "process", 3: "network", 5: "process_end"}.get(event["event_id"], result["kind"])
        result["process_guid"] = guid("ProcessGuid")
        result["parent_process_guid"] = guid("ParentProcessGuid")
        result["process_logon_key"] = canonical_id(data.get("LogonId"))
        if event["event_id"] == 5:
            try:
                result["pid"] = number(data.get("ProcessId"))
            except (ValueError, AttributeError):
                warnings.append("Invalid termination ProcessId")
    try:
        result["source_ip_key"] = str(ipaddress.ip_address(event["source_ip"]))
    except ValueError:
        pass
    result["warnings_json"] = json.dumps(warnings)
    return result


def insert_context(db, events):
    sql = "INSERT INTO event_context (" + ",".join(COLUMNS) + ") VALUES (" + ",".join("?" for _ in COLUMNS) + ") ON CONFLICT(evidence_id) DO NOTHING"
    rows = [extract(event.as_dict() if hasattr(event, "as_dict") else dict(event)) for event in events]
    db.executemany(sql, [tuple(row[name] for name in COLUMNS) for row in rows])


DDL = (
    """CREATE TABLE event_context (
    evidence_id TEXT PRIMARY KEY REFERENCES events(id), host_key TEXT, timestamp_utc TEXT,
    kind TEXT, pid INTEGER, ppid INTEGER, process_guid TEXT, parent_process_guid TEXT,
    subject_logon_key TEXT, target_logon_key TEXT, process_logon_key TEXT,
    subject_account TEXT, target_account TEXT, subject_sid TEXT, target_sid TEXT,
    source_ip_key TEXT, version TEXT NOT NULL, warnings_json TEXT NOT NULL)""",
    "CREATE INDEX ctx_host_time ON event_context(host_key,timestamp_utc,evidence_id)",
    "CREATE INDEX ctx_pid ON event_context(host_key,pid,timestamp_utc)",
    "CREATE INDEX ctx_ppid ON event_context(host_key,ppid,timestamp_utc)",
    "CREATE INDEX ctx_guid ON event_context(host_key,process_guid,timestamp_utc)",
    "CREATE INDEX ctx_parent_guid ON event_context(host_key,parent_process_guid,timestamp_utc)",
    "CREATE INDEX ctx_subject_logon ON event_context(host_key,subject_logon_key,timestamp_utc)",
    "CREATE INDEX ctx_target_logon ON event_context(host_key,target_logon_key,timestamp_utc)",
    "CREATE INDEX ctx_process_logon ON event_context(host_key,process_logon_key,timestamp_utc)",
    "CREATE INDEX ctx_kind_time ON event_context(kind,timestamp_utc,evidence_id)",
    "CREATE INDEX ctx_auth ON event_context(host_key,target_account,source_ip_key,timestamp_utc)",
)

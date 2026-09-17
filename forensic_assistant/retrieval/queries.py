from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import ipaddress
from forensic_assistant.model import utc_timestamp


@dataclass
class QueryResult:
    records: list[dict]
    total: int
    limit: int
    offset: int

    @property
    def truncated(self):
        return self.offset > 0 or self.total > len(self.records)

    def as_dict(self):
        return {**asdict(self), "truncated": self.truncated}


def escape_like(value):
    return value.replace("!", "!!").replace("%", "!%").replace("_", "!_")


def required_time(value):
    timestamp, status = utc_timestamp(value)
    if status != "normalized":
        raise ValueError("Use a full ISO timestamp with Z or an explicit UTC offset")
    return timestamp


class Queries:
    def __init__(self, db):
        self.db = db

    def search(self, *, start=None, end=None, username=None, ip=None, event_id=None,
               process=None, hostname=None, artifact_types=None, powershell=False,
               limit=100, offset=0):
        if not 1 <= limit <= 10000 or offset < 0:
            raise ValueError("Limit must be 1..10000 and offset must be nonnegative")
        clauses, params = [], []
        if start:
            start = required_time(start)
            clauses.append("timestamp_utc >= ?"); params.append(start)
        if end:
            end = required_time(end)
            clauses.append("timestamp_utc <= ?"); params.append(end)
        if start and end and start > end:
            raise ValueError("Start must not follow end")
        if username:
            if "\\" in username or "@" in username:
                clauses.append("username = ? COLLATE NOCASE"); params.append(username)
            else:
                clauses.append("(username = ? COLLATE NOCASE OR username LIKE ? ESCAPE '!' COLLATE NOCASE)")
                params.extend([username, "%\\" + escape_like(username)])
        if ip:
            ipaddress.ip_address(ip)
            self.db.create_function("ip_equal", 2, _ip_equal, deterministic=True)
            clauses.append("(source_ip = ? OR destination_ip = ? OR ip_equal(source_ip, ?) OR ip_equal(destination_ip, ?))")
            params.extend([ip] * 4)
        for field, value in (("event_id", event_id), ("hostname", hostname)):
            if value is not None:
                clauses.append(field + " = ? COLLATE NOCASE"); params.append(value)
        if process:
            clauses.append("(process_name = ? COLLATE NOCASE OR process_name LIKE ? ESCAPE '!' COLLATE NOCASE)")
            params.extend([process, "%\\" + escape_like(process)])
        if artifact_types is not None:
            if not artifact_types:
                clauses.append("0")
            else:
                clauses.append("id IN (SELECT evidence_id FROM event_context WHERE kind IN (" + ",".join("?" for _ in artifact_types) + "))")
                params.extend(artifact_types)
        if powershell:
            clauses.append("(artifact_type = ? OR lower(process_name) IN (?,?) OR lower(process_name) LIKE ? OR lower(process_name) LIKE ?)")
            params.extend(["powershell", "powershell.exe", "pwsh.exe", "%\\powershell.exe", "%\\pwsh.exe"])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        total = self.db.execute("SELECT count(*) FROM events" + where, params).fetchone()[0]
        rows = self.db.execute("SELECT * FROM events" + where + " ORDER BY timestamp_utc IS NULL, timestamp_utc, id LIMIT ? OFFSET ?", [*params, limit, offset])
        return QueryResult([dict(row) for row in rows], total, limit, offset)

    def events_between(self, start, end, **kwargs):
        return self.search(start=start, end=end, **kwargs)

    def events_for_user(self, username, **kwargs):
        return self.search(username=username, **kwargs)

    def events_for_ip(self, ip, **kwargs):
        return self.search(ip=ip, **kwargs)

    def events_by_event_id(self, event_id, **kwargs):
        return self.search(event_id=event_id, **kwargs)

    def find_logons(self, **kwargs):
        return self.search(artifact_types=["logon", "explicit_credentials", "privileged_logon"], **kwargs)

    def find_failed_logons(self, **kwargs):
        return self.search(artifact_types=["failed_logon"], **kwargs)

    def find_processes(self, **kwargs):
        return self.search(artifact_types=["process"], **kwargs)

    def find_powershell(self, **kwargs):
        return self.search(powershell=True, **kwargs)

    def find_scheduled_tasks(self, **kwargs):
        return self.search(artifact_types=["scheduled_task"], **kwargs)

    def find_services(self, **kwargs):
        return self.search(artifact_types=["service"], **kwargs)

    def find_account_changes(self, **kwargs):
        return self.search(artifact_types=["account_creation", "group_membership"], **kwargs)

    def timeline_around(self, timestamp, minutes=5, **kwargs):
        if not isinstance(minutes, int) or not 0 <= minutes <= 525600:
            raise ValueError("Minutes must be an integer between 0 and 525600")
        timestamp = required_time(timestamp)
        dt = datetime.strptime(timestamp[:19], "%Y-%m-%dT%H:%M:%S")
        delta = timedelta(minutes=minutes)
        start = (dt - delta).strftime("%Y-%m-%dT%H:%M:%S") + timestamp[19:]
        end = (dt + delta).strftime("%Y-%m-%dT%H:%M:%S") + timestamp[19:]
        return self.search(start=start, end=end, **kwargs)

    def show(self, evidence_id):
        row = self.db.execute("SELECT * FROM events WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            raise ValueError("Evidence ID not found")
        result = dict(row)
        result["source_locations"] = [r[0] for r in self.db.execute(
            "SELECT source_file FROM source_locations WHERE file_sha256=? ORDER BY source_file", (row["file_sha256"],))]
        return result

    def coverage(self):
        return {
            "total_events": self.db.execute("SELECT count(*) FROM events").fetchone()[0],
            "events_without_utc": self.db.execute("SELECT count(*) FROM events WHERE timestamp_utc IS NULL").fetchone()[0],
            "ingestion_runs": [dict(r) for r in self.db.execute("SELECT * FROM ingestion_runs ORDER BY id")],
            "caution": "Missing events do not establish absence of activity. Auditing and supplied logs may be incomplete.",
        }


def _ip_equal(a, b):
    try:
        return int(ipaddress.ip_address(a) == ipaddress.ip_address(b))
    except ValueError:
        return 0

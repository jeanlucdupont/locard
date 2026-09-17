from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import re


def utc_timestamp(value: str | None) -> tuple[str | None, str]:
    """Fixed nine-digit fractional UTC seconds; retain input separately."""
    if not value:
        return None, "missing"
    try:
        match = re.fullmatch(r"(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)?", value)
        if not match:
            return None, "invalid"
        base, fraction, offset = match.groups()
        if offset is None:
            return None, "ambiguous"
        dt = datetime.fromisoformat(base + offset.replace("Z", "+00:00"))
        dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + "." + (fraction or "").ljust(9, "0") + "Z", "normalized"
    except ValueError:
        return None, "invalid"


def evidence_id(sha256: str, offset: int) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", sha256) or offset < 0:
        raise ValueError("Invalid evidence digest or record offset")
    return f"EVTX:{sha256}:Offset:{offset}"


@dataclass
class NormalizedEvent:
    id: str
    file_sha256: str
    source_file: str
    record_offset: int
    raw_xml: str
    record_id: int | None = None
    timestamp_utc: str | None = None
    timestamp_original: str | None = None
    timestamp_status: str = "missing"
    hostname: str | None = None
    computer: str | None = None
    channel: str | None = None
    provider: str | None = None
    event_id: int | None = None
    level: int | None = None
    user_sid: str | None = None
    username: str | None = None
    artifact_type: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    parent_process_name: str | None = None
    parent_process_id: int | None = None
    command_line: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    logon_type: int | None = None
    logon_id: str | None = None
    service_name: str | None = None
    task_name: str | None = None
    script_block: str | None = None
    event_data_json: str = "[]"
    normalization_warnings_json: str = "[]"
    normalizer_version: str = "0.1.0"

    def as_dict(self):
        return asdict(self)

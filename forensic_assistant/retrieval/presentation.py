"""Compact display with escaped untrusted text; no interpretation of commands."""
import json


def safe(value):
    return json.dumps(str(value) if value is not None else "-", ensure_ascii=True)[1:-1]


def detail(event):
    kind = event.get("kind") or event.get("artifact_type")
    if kind == "process":
        return f"{event.get('parent_process_name') or '?'} -> {event.get('process_name') or '?'}"
    if kind in ("logon", "failed_logon"):
        return f"{kind}; logon type={event.get('logon_type')}; source={event.get('source_ip')}"
    if kind == "scheduled_task":
        return f"Task {event.get('task_name') or '?'}; Event ID {event.get('event_id')}"
    if kind == "service":
        return f"Service {event.get('service_name') or '?'}"
    return event.get("command_line") or event.get("script_block") or kind or "Unmapped event"


def render_timeline(result):
    lines = ["TIME | EVIDENCE ID | EVENT ID | TYPE | USER | PROCESS | DETAIL"]
    for event in result["records"]:
        values = [event.get("timestamp_utc"), event["id"], event.get("event_id"),
                  event.get("kind") or event.get("artifact_type"), event.get("username") or event.get("target_account") or event.get("subject_account"),
                  event.get("process_name"), detail(event)]
        lines.append(" | ".join(safe(value) for value in values))
    lines.append(f"Displayed {len(result['records'])} / {result['total']}; truncated={result['truncated']}")
    lines.append("CORRELATION != CAUSATION. Missing logs or auditing may hide activity.")
    return "\n".join(lines)

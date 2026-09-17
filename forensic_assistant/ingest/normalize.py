"""Explicit provider-aware mappings. Unmapped data remains in XML and JSON."""
import json
from defusedxml import ElementTree as ET
from forensic_assistant.model import NormalizedEvent, evidence_id, utc_timestamp

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
SECURITY = "Microsoft-Windows-Security-Auditing"
SYSMON = "Microsoft-Windows-Sysmon"
POWERSHELL = "Microsoft-Windows-PowerShell"

# Each mapping specifies which actor/target account the normalized username means.
SECURITY_MAP = {
    4624: ("logon", "Target"), 4625: ("failed_logon", "Target"),
    4634: ("logoff", "Target"), 4648: ("explicit_credentials", "Subject"),
    4672: ("privileged_logon", "Subject"), 4688: ("process", "Subject"),
    4697: ("service", "Subject"), 4698: ("scheduled_task", "Subject"),
    4702: ("scheduled_task", "Subject"), 4720: ("account_creation", "Target"),
    4728: ("group_membership", "Subject"), 4732: ("group_membership", "Subject"),
    4756: ("group_membership", "Subject"),
}


def clean(value):
    return value if value not in (None, "", "-") else None


def number(value):
    value = clean(value)
    if value is None:
        return None
    return int(value, 16 if value.lower().startswith("0x") else 10)


def normalize(xml, sha, source_file, offset):
    root = ET.fromstring(xml, forbid_dtd=True)
    if root.tag != "{" + NS["e"] + "}Event":
        raise ValueError("Expected a namespaced Windows Event element")
    system = root.find("e:System", NS)
    if system is None:
        raise ValueError("Event has no System metadata")
    event = NormalizedEvent(evidence_id(sha, offset), sha, str(source_file), offset, xml)
    warnings = []

    def text(name):
        return clean(system.findtext("e:" + name, namespaces=NS))

    def integer(field, value):
        try:
            setattr(event, field, number(value))
        except (ValueError, AttributeError):
            warnings.append(f"Invalid integer in {field}: {value!r}")

    for field, name in (("event_id", "EventID"), ("record_id", "EventRecordID"), ("level", "Level")):
        integer(field, text(name))
    event.computer = event.hostname = text("Computer")
    event.channel = text("Channel")
    provider = system.find("e:Provider", NS)
    event.provider = clean(provider.get("Name")) if provider is not None else None
    security = system.find("e:Security", NS)
    event.user_sid = clean(security.get("UserID")) if security is not None else None
    time = system.find("e:TimeCreated", NS)
    event.timestamp_original = time.get("SystemTime") if time is not None else None
    event.timestamp_utc, event.timestamp_status = utc_timestamp(event.timestamp_original)
    if event.timestamp_status != "normalized":
        warnings.append("Timestamp is " + event.timestamp_status)

    # Preserve duplicate names and unnamed payloads rather than collapsing original data.
    payload = []
    for container in root:
        if container.tag.rsplit("}", 1)[-1] not in ("EventData", "UserData"):
            continue
        for node in container.iter():
            if node is container or len(node):
                continue
            payload.append({"name": node.get("Name", node.tag.rsplit("}", 1)[-1]), "value": node.text})
    event.event_data_json = json.dumps(payload, ensure_ascii=True)
    data = {}
    for item in payload:
        name = item["name"]
        if name in data:
            warnings.append(f"Duplicate payload field {name}; normalized value omitted")
            data[name] = None
        else:
            data[name] = clean(item["value"])

    def account(prefix):
        user, domain = data.get(prefix + "UserName"), data.get(prefix + "DomainName")
        event.username = f"{domain}\\{user}" if domain and user else user
        event.user_sid = data.get(prefix + "UserSid") or event.user_sid
        event.logon_id = data.get(prefix + "LogonId")

    def assign(mapping):
        for field, key in mapping.items():
            setattr(event, field, data.get(key))

    if event.provider == SECURITY and event.channel == "Security" and event.event_id in SECURITY_MAP:
        event.artifact_type, prefix = SECURITY_MAP[event.event_id]
        account(prefix)
        assign({"process_name": "ProcessName", "source_ip": "IpAddress",
                "service_name": "ServiceName", "task_name": "TaskName"})
        for field, key in (("process_id", "ProcessId"), ("source_port", "IpPort"), ("logon_type", "LogonType")):
            integer(field, data.get(key))
        if event.event_id == 4688:
            assign({"process_name": "NewProcessName", "parent_process_name": "ParentProcessName", "command_line": "CommandLine"})
            integer("process_id", data.get("NewProcessId"))
            integer("parent_process_id", data.get("ProcessId"))
        if event.event_id == 4697:
            # ServiceFileName is a service configuration string, not proof of execution.
            event.process_name = None
    elif event.event_id == 1102 and event.channel == "Security" and event.provider == "Microsoft-Windows-Eventlog":
        event.artifact_type = "audit_log_cleared"
        account("Subject")
    elif event.provider == POWERSHELL and event.channel == "Microsoft-Windows-PowerShell/Operational" and event.event_id in (4103, 4104):
        event.artifact_type = "powershell"
        event.script_block = data.get("ScriptBlockText") if event.event_id == 4104 else data.get("Payload")
    elif event.provider == SYSMON and event.channel == "Microsoft-Windows-Sysmon/Operational" and event.event_id in (1, 3):
        event.artifact_type = "process" if event.event_id == 1 else "network"
        assign({"username": "User", "process_name": "Image", "parent_process_name": "ParentImage",
                "command_line": "CommandLine", "source_ip": "SourceIp", "destination_ip": "DestinationIp"})
        for field, key in (("process_id", "ProcessId"), ("parent_process_id", "ParentProcessId"),
                           ("source_port", "SourcePort"), ("destination_port", "DestinationPort")):
            integer(field, data.get(key))
    event.normalization_warnings_json = json.dumps(warnings)
    return event

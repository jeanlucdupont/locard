"""Small, intentionally bounded keyword planner; never generates SQL."""
from dataclasses import dataclass, field, asdict
from datetime import date
import ipaddress
import re
from forensic_assistant.retrieval.queries import required_time


@dataclass
class Plan:
    operation: str = "search"
    filters: dict = field(default_factory=dict)
    timestamp: str | None = None
    minutes: int = 5
    notes: list[str] = field(default_factory=list)

    def execute(self, queries, limit=30):
        if self.operation == "timeline":
            return queries.timeline_around(self.timestamp, self.minutes, limit=limit, **self.filters)
        return queries.search(limit=limit, **self.filters)

    def as_dict(self):
        return asdict(self)


def plan_question(question, queries, date_hint=None):
    if not question.strip() or len(question.encode("utf-8")) > 1000:
        raise ValueError("Question must contain 1..1000 UTF-8 bytes")
    plan = Plan()
    remaining = question
    full_time = re.search(r"\b\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)?", remaining)
    if full_time:
        plan.timestamp = required_time(full_time.group())
        remaining = remaining.replace(full_time.group(), " ", 1)
    else:
        time = re.search(r"(?<![\w:])(\d{1,2}):(\d\d)(?::(\d\d))?(?![\w:])", remaining)
        if time:
            dates = [r[0] for r in queries.db.execute("SELECT DISTINCT substr(timestamp_utc,1,10) FROM events WHERE timestamp_utc IS NOT NULL ORDER BY 1 LIMIT 2")]
            explicit_date = re.search(r"\b\d{4}-\d\d-\d\d\b", remaining)
            chosen = date_hint or (explicit_date.group() if explicit_date else None)
            if chosen is None:
                if len(dates) != 1:
                    raise ValueError("Time-only question needs --date YYYY-MM-DD or a full timestamp; evidence does not establish a unique UTC date")
                chosen = dates[0]
                plan.notes.append("Used the sole UTC date present in the evidence: " + chosen)
            date.fromisoformat(chosen)
            h, m, s = time.groups()
            plan.timestamp = required_time(f"{chosen}T{int(h):02}:{m}:{s or '00'}Z")
            plan.notes.append("Time-only values are interpreted as UTC")
            remaining = remaining.replace(time.group(), " ", 1)
    if plan.timestamp:
        plan.operation = "timeline"
    event = re.search(r"\bevent\s*(?:id\s*)?[:=#]?\s*(\d+)\b", remaining, re.I)
    if event:
        plan.filters["event_id"] = int(event.group(1))
        remaining = remaining.replace(event.group(), " ", 1)
    user = re.search(r'''\buser(?:name)?\s+['"]([^'"]+)['"]|\buser(?:name)?\s+([\w.@\\$-]+)''', remaining, re.I)
    if user:
        plan.filters["username"] = (user.group(1) or user.group(2)).rstrip(".?")
        remaining = remaining.replace(user.group(), " ", 1)
    ips = []
    for token in re.findall(r"[0-9A-Fa-f:.%]+", remaining):
        if "." not in token and ":" not in token:
            continue
        try:
            address = str(ipaddress.ip_address(token.rstrip(".")))
            if address not in ips:
                ips.append(address)
        except ValueError:
            pass
    if len(ips) > 1:
        raise ValueError("V0 supports one IP filter per question; use separate searches")
    if ips:
        plan.filters["ip"] = ips[0]
    process = re.search(r"\b([\w.-]+\.exe)\b", remaining, re.I)
    if process:
        plan.filters["process"] = process.group(1)
    lower = remaining.lower()
    concepts = []
    rules = [
        (r"\b(?:powershell|pwsh)\b", "powershell"),
        (r"\bfailed\s+(?:logons?|logins?)\b", "failed_logon"),
        (r"\bprivileged\s+(?:logons?|logins?)\b|\bspecial privileges\b", "privileged_logon"),
        (r"\bscheduled tasks?\b", "scheduled_task"),
        (r"\bservices?\b", "service"),
        (r"\baccount creation\b|\baccounts? created\b|\bcreated accounts?\b|\bnew accounts?\b", "account_creation"),
        (r"\baccount changes?\b|\bgroup membership\b", "account_changes"),
    ]
    for pattern, concept in rules:
        if re.search(pattern, lower):
            concepts.append(concept)
            lower = re.sub(pattern, " ", lower)
    if re.search(r"\blog(?:on|in)s?\b", lower):
        concepts.append("logons")
    if re.search(r"\bprocess(?:es)?\b", lower) and "powershell" not in concepts:
        concepts.append("process")
    if len(concepts) > 1:
        raise ValueError("V0 recognized multiple activity categories; ask about one category at a time or use deterministic search")
    if concepts:
        concept = concepts[0]
        if concept == "powershell":
            plan.filters["powershell"] = True
        else:
            plan.filters["artifact_types"] = {
                "logons": ["logon", "explicit_credentials", "privileged_logon"],
                "account_changes": ["account_creation", "group_membership"],
            }.get(concept, [concept])
    if not plan.filters and not plan.timestamp:
        raise ValueError("No supported retrieval concept found. Specify PowerShell, process, logon, service, scheduled task, account creation, user, IP, Event ID, or timestamp")
    plan.notes.append("Keyword retrieval selects evidence; it does not classify activity as malicious")
    return plan

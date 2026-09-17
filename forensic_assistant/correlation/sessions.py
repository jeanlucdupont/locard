"""Role-aware Logon ID association, scoped by host and observed boundaries."""
from forensic_assistant.database.context import canonical_id, host_key
from forensic_assistant.correlation.models import Relationship, select, get_event, unique_observations
from forensic_assistant.correlation.temporal import shift
from forensic_assistant.retrieval.queries import required_time, escape_like

AUTH_KINDS = ("logon", "failed_logon", "logoff", "logoff_request", "explicit_credentials", "privileged_logon")


def logons(db, username=None, ip=None, hostname=None, start=None, end=None, limit=100, offset=0):
    where = "c.kind IN (" + ",".join("?" for _ in AUTH_KINDS) + ")"
    params = list(AUTH_KINDS)
    if username:
        where += " AND (c.target_account=? OR c.subject_account=? OR c.target_account LIKE ? ESCAPE '!' OR c.subject_account LIKE ? ESCAPE '!')"
        exact = username.casefold()
        suffix = "%\\" + escape_like(exact) if "\\" not in exact else escape_like(exact)
        params.extend([exact, exact, suffix, suffix])
    if ip:
        import ipaddress
        where += " AND c.source_ip_key=?"; params.append(str(ipaddress.ip_address(ip)))
    if hostname:
        where += " AND c.host_key=?"; params.append(host_key(hostname))
    if start:
        where += " AND c.timestamp_utc>=?"; params.append(required_time(start))
    if end:
        where += " AND c.timestamp_utc<=?"; params.append(required_time(end))
    if start and end and required_time(start) > required_time(end):
        raise ValueError("Start must not follow end")
    return select(db, where, params, limit=limit, offset=offset)


def event_roles(event):
    kind = event["kind"]
    if kind == "failed_logon":
        return []
    if kind in ("logon", "logoff"):
        return [(event["target_logon_key"], "target", "session_event")]
    if kind == "process":
        return [(event["subject_logon_key"], "subject", "created_by_session"),
                (event["process_logon_key"], "target", "runs_in_session")]
    if event["process_logon_key"]:
        return [(event["process_logon_key"], "target", "process_session")]
    if event["subject_logon_key"]:
        return [(event["subject_logon_key"], "subject", "initiating_session")]
    return []


def session(db, logon_id, *, hostname=None, around=None, anchor_id=None, max_hours=24, limit=500):
    if not 1 <= max_hours <= 168 or not 1 <= limit <= 10000:
        raise ValueError("Session bounds require 1..168 hours and 1..10000 records")
    key = canonical_id(logon_id)
    if key is None:
        raise ValueError("A nonzero decimal or hexadecimal Logon ID is required")
    anchor = get_event(db, anchor_id) if anchor_id else None
    if anchor:
        if anchor["kind"] != "logon" or anchor["target_logon_key"] != key:
            raise ValueError("Session anchor must be a matching successful logon")
        hostname = anchor["host_key"]
    where, params = "c.kind='logon' AND c.target_logon_key=?", [key]
    if hostname:
        where += " AND c.host_key=?"; params.append(host_key(hostname))
    if around:
        around = required_time(around)
        where += " AND c.timestamp_utc<=? AND c.timestamp_utc>=?"
        params.extend([around, shift(around, -max_hours * 3600)])
    if anchor:
        candidates = [anchor]
    else:
        result = select(db, where, params, limit=100)
        candidates = unique_observations(result.records)
        if around and candidates and len({e["host_key"] for e in candidates}) == 1:
            newest = max(e["timestamp_utc"] for e in candidates)
            candidates = [e for e in candidates if e["timestamp_utc"] == newest]
        if result.truncated or len(candidates) != 1:
            return {"status": "UNRESOLVED", "reason": "No unique successful-logon anchor; specify --hostname and --around, or use --evidence",
                    "candidate_anchor_ids": [e["id"] for e in candidates], "records": [], "relationships": [],
                    "truncated": result.truncated, "logon_id": key}
        anchor = candidates[0]
    if not anchor["host_key"] or not anchor["timestamp_utc"]:
        return {"status": "UNRESOLVED", "reason": "Anchor lacks host or UTC time", "records": [anchor], "relationships": [], "truncated": False}
    start, host = anchor["timestamp_utc"], anchor["host_key"]
    ceiling = shift(start, max_hours * 3600)
    boundaries = select(db, "c.host_key=? AND c.timestamp_utc>? AND c.timestamp_utc<=? AND (c.kind='boot' OR (c.kind IN ('logoff','logon') AND c.target_logon_key=?))",
                        (host, start, ceiling, key), limit=1)
    boundary = boundaries.records[0] if boundaries.records else None
    if boundary:
        ties = select(db, "c.host_key=? AND c.timestamp_utc=? AND (c.kind='boot' OR (c.kind IN ('logoff','logon') AND c.target_logon_key=?))",
                      (host, boundary["timestamp_utc"], key), limit=100)
        if ties.truncated or len(unique_observations(ties.records)) > 1:
            return {"status": "UNRESOLVED", "reason": "Competing session boundaries share a timestamp", "records": [anchor], "relationships": [], "truncated": ties.truncated}
    end = boundary["timestamp_utc"] if boundary else ceiling
    inclusive = bool(boundary and boundary["kind"] == "logoff")
    if around and (around > end or (not inclusive and around == end)):
        return {"status": "UNRESOLVED", "reason": "Requested event is outside the evidenced session interval", "records": [anchor], "relationships": [], "truncated": False}
    boundary_conflict = bool(boundary and any(anchor["target_" + field] and boundary["target_" + field] and anchor["target_" + field] != boundary["target_" + field] for field in ("sid", "account")))
    query = select(db, "c.host_key=? AND c.timestamp_utc>=? AND c.timestamp_utc" + ("<=?" if inclusive else "<?") +
                   " AND (c.target_logon_key=? OR c.subject_logon_key=? OR c.process_logon_key=?)",
                   (host, start, end, key, key, key), limit=limit)
    # A same-time competing logon cannot be ordered by an arbitrary evidence-ID tie-break.
    same_time = select(db, "c.host_key=? AND c.kind='logon' AND c.target_logon_key=? AND c.timestamp_utc=?",
                       (host, key, start), limit=100)
    if same_time.truncated or len(unique_observations(same_time.records)) > 1:
        return {"status": "UNRESOLVED", "reason": "Competing logon anchors share a timestamp", "records": [anchor], "relationships": [], "truncated": False}
    relations, records = [], {anchor["id"]: anchor}
    for event in query.records:
        if event["id"] == anchor["id"]:
            continue
        for event_key, role, relation in event_roles(event):
            if event_key != key:
                continue
            expected_sid, sid = anchor["target_sid"], event[role + "_sid"]
            expected_account, account = anchor["target_account"], event[role + "_account"]
            conflict = (expected_sid and sid and expected_sid != sid) or (expected_account and account and expected_account != account)
            status = "UNRESOLVED" if conflict else "CONFIRMED" if inclusive and not boundary_conflict else "LIKELY"
            reason = "Conflicting account/SID fields" if conflict else "Boundary account/SID contradicts the anchor; session extent is uncertain" if boundary_conflict else "Same host and role-specific Logon ID within an observed start/logoff interval" if inclusive else "Same host and role-specific Logon ID after a unique logon; complete session boundaries are unavailable"
            evidence_ids = [anchor["id"], event["id"]]
            if boundary:
                records[boundary["id"]] = boundary
                if boundary["id"] not in evidence_ids:
                    evidence_ids.append(boundary["id"])
            relations.append(Relationship(relation, status, evidence_ids, reason,
                            ["Unobserved restarts or missing audit records can conceal identifier reuse"], anchor["id"], event["id"]).as_dict())
            records[event["id"]] = event
    return {"status": "CORRELATED", "anchor_id": anchor["id"], "logon_id": key, "hostname": host,
            "start": start, "end": end, "end_reason": boundary["kind"] if boundary else "fallback_ceiling",
            "records": sorted(records.values(), key=lambda e: (e["timestamp_utc"], e["id"])),
            "relationships": relations, "truncated": query.truncated, "candidate_count": query.total,
            "parameters": {"max_hours": max_hours, "limit": limit}}


def related_logon_events(db, evidence_id, **kwargs):
    event = get_event(db, evidence_id)
    if not event["host_key"] or not event["timestamp_utc"]:
        return {"sessions": [], "unresolved": ["Host or UTC time missing"]}
    results = []
    for key in dict.fromkeys(key for key, _, _ in event_roles(event) if key):
        results.append(session(db, key, hostname=event["host_key"], around=event["timestamp_utc"], **kwargs))
    return {"sessions": results, "unresolved": [] if results else ["No usable role-specific session identifier"]}

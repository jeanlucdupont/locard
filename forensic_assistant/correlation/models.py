from dataclasses import dataclass, asdict
from forensic_assistant.database.context import COLUMNS
from forensic_assistant.retrieval.queries import QueryResult


@dataclass
class Relationship:
    relationship: str
    status: str
    evidence_ids: list[str]
    reason: str
    limitations: list[str]
    source_id: str | None = None
    target_id: str | None = None

    def as_dict(self):
        return asdict(self)


CONTEXT_SELECT = "e.*, " + ",".join("c." + col for col in COLUMNS if col not in ("evidence_id", "timestamp_utc"))


def select(db, where="1", params=(), *, limit=100, offset=0, nearest_to=None):
    """SQL predicates are code-owned; every external value is bound separately."""
    if not 1 <= limit <= 10000 or offset < 0:
        raise ValueError("Limit must be 1..10000; offset must be nonnegative")
    base = " FROM event_context c JOIN events e ON e.id=c.evidence_id WHERE " + where
    total = db.execute("SELECT count(*)" + base, params).fetchone()[0]
    order = "c.timestamp_utc IS NULL,c.timestamp_utc,e.id"
    order_params = []
    if nearest_to:
        db.create_function("locard_time_distance", 2, lambda a, b: str(abs(time_ns(a) - time_ns(b))).zfill(30), deterministic=True)
        order = "locard_time_distance(c.timestamp_utc,?),c.timestamp_utc,e.id"
        order_params = [nearest_to]
    rows = db.execute("SELECT " + CONTEXT_SELECT + base + " ORDER BY " + order + " LIMIT ? OFFSET ?",
                      [*params, *order_params, limit, offset])
    return QueryResult([dict(row) for row in rows], total, limit, offset)


def get_event(db, evidence_id):
    result = select(db, "e.id=?", (evidence_id,), limit=1)
    if not result.records:
        raise ValueError("Evidence ID not found")
    return result.records[0]


def order_key(event):
    return (event.get("timestamp_utc") is None, event.get("timestamp_utc") or "", event["id"])


def time_ns(timestamp):
    """Integer ordering preserves all nine normalized fractional digits."""
    from datetime import datetime
    base = datetime.fromisoformat(timestamp[:19])
    seconds = base.toordinal() * 86400 + base.hour * 3600 + base.minute * 60 + base.second
    return seconds * 1000000000 + int(timestamp[20:29])


def observation_key(event):
    """Recognize exact duplicated records across exports without merging evidence."""
    import hashlib
    return (event.get("host_key"), event.get("channel"), event.get("record_id"),
            event.get("timestamp_utc"), hashlib.sha256(event["raw_xml"].encode()).hexdigest())


def unique_observations(events):
    seen = set()
    result = []
    for event in sorted(events, key=order_key):
        key = observation_key(event)
        if key not in seen:
            seen.add(key)
            result.append(event)
    return result

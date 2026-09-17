from datetime import datetime, timedelta
from forensic_assistant.retrieval.queries import required_time
from forensic_assistant.correlation.models import get_event, select


def shift(timestamp, seconds):
    """Shift whole seconds without discarding parser-rendered subsecond precision."""
    if not isinstance(seconds, int) or abs(seconds) > 31536000:
        raise ValueError("Time shift must be an integer within one year")
    timestamp = required_time(timestamp)
    base = datetime.strptime(timestamp[:19], "%Y-%m-%dT%H:%M:%S")
    return (base + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S") + timestamp[19:]


def validate_anchor(event):
    if not event["timestamp_utc"]:
        raise ValueError("Anchor has no unambiguous UTC timestamp; inspect it with show")
    if not event["host_key"]:
        raise ValueError("Anchor has no hostname; cross-host temporal context is unresolved")


def nearby(db, evidence_id, seconds=120, direction="around", limit=100, offset=0, nearest=False):
    if not isinstance(seconds, int) or not 0 <= seconds <= 604800:
        raise ValueError("Seconds must be an integer between 0 and 604800")
    event = get_event(db, evidence_id)
    validate_anchor(event)
    timestamp = event["timestamp_utc"]
    if direction == "before":
        clause = "c.timestamp_utc>=? AND c.timestamp_utc<?"
        bounds = (shift(timestamp, -seconds), timestamp)
    elif direction == "after":
        clause = "c.timestamp_utc>? AND c.timestamp_utc<=?"
        bounds = (timestamp, shift(timestamp, seconds))
    elif direction == "around":
        clause = "c.timestamp_utc>=? AND c.timestamp_utc<=?"
        bounds = (shift(timestamp, -seconds), shift(timestamp, seconds))
    else:
        raise ValueError("Unknown temporal direction")
    return select(db, "c.host_key=? AND " + clause, (event["host_key"], *bounds), limit=limit, offset=offset,
                  nearest_to=timestamp if nearest else None)


def events_before(db, evidence_id, seconds, **kwargs):
    return nearby(db, evidence_id, seconds, "before", **kwargs)


def events_after(db, evidence_id, seconds, **kwargs):
    return nearby(db, evidence_id, seconds, "after", **kwargs)


def events_around(db, evidence_id, seconds, **kwargs):
    return nearby(db, evidence_id, seconds, "around", **kwargs)

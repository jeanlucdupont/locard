"""Analyst-declared IANA metadata only; never used to convert evidence times."""
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def validate(value):
    if value is None or value == '':
        return None
    if not isinstance(value, str) or len(value) > 255 or value != value.strip():
        raise ValueError('Source time zone must be an IANA identifier, for example America/Chicago')
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError as exc:
        try:
            ZoneInfo('UTC')
        except ZoneInfoNotFoundError:
            raise ValueError('IANA time-zone database is unavailable. Install the tzdata dependency in the Locard environment, or leave the source time zone empty (unknown).') from exc
        raise ValueError('Unknown IANA source time zone. Use an identifier such as America/Chicago, or leave it empty.') from exc
    except ValueError as exc:
        raise ValueError('Invalid IANA source time zone; filesystem paths and relative identifiers are not accepted') from exc
    return value


def has_column(db):
    return any(row[1] == 'time_zone' for row in db.execute('PRAGMA table_info(source_assertions)'))


def enable_for_assertion(db, value):
    """Approved additive extension on explicit metadata writes, never on reads."""
    if value is not None and not has_column(db):
        if not db.in_transaction:
            db.execute('BEGIN')
        db.execute('ALTER TABLE source_assertions ADD COLUMN time_zone TEXT')

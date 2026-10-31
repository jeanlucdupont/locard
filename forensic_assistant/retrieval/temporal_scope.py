"""Bounded deterministic temporal intent; never derive authorization from evidence."""
from datetime import date
import re

from .queries import required_time
from forensic_assistant.correlation.models import time_ns

STAMP = r'\b\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)?'
MONTHS = 'January February March April May June July August September October November December'.split()
CLOCK = r'(?<![\w:])(\d{1,2}:\d\d(?::\d\d(?:\.\d{1,9})?)?)(?![\w:])'


def resolve(question, date_hint=None):
    """Date-only scopes use Locard's UTC-calendar convention; bare clocks do not."""
    if len(question.encode('utf-8')) > 1000:
        raise ValueError('Question must contain 1..1000 UTF-8 bytes')
    def unresolved(reason):
        return dict(kind='unresolved', limitation=reason)
    stamps = re.findall(STAMP, question)
    remaining = re.sub(STAMP, ' ', question)
    dates = re.findall(r'\b\d{4}-\d\d-\d\d\b', remaining)
    for match in re.finditer(r'\b(' + '|'.join(MONTHS) + r')\s+(\d{1,2}),?\s+(\d{4})\b', remaining, re.I):
        month = next(i + 1 for i, name in enumerate(MONTHS) if name.lower() == match[1].lower())
        try:
            dates.append(date(int(match[3]), month, int(match[2])).isoformat())
        except ValueError:
            return unresolved('Invalid calendar date; supply an ISO UTC date/window.')
    try:
        dates = [date.fromisoformat(d).isoformat() for d in dates]
        if date_hint:
            dates.append(date.fromisoformat(date_hint).isoformat())
    except ValueError:
        return unresolved('Invalid date hint or calendar date.')
    if len(set(dates)) > 1:
        return unresolved('Conflicting dates; supply one explicit UTC date/window.')
    chosen = dates[0] if dates else None
    if (stamps or chosen) and re.search(r'\blocal\s+time\b|\b(?:CST|CDT|EST|EDT|PST|PDT|CET|CEST|BST)\b', question, re.I):
        return unresolved('Ambiguous timezone abbreviation; use UTC or a numeric offset.')
    paired = bool(re.search(r'\bbetween\b|\bfrom\b.+\bto\b', question, re.I | re.S))
    if not paired and re.search(r'\bbefore\b|\bafter\b|\bprior\b|\bearlier\b|\bsince\b', question, re.I) and (stamps or chosen):
        return {**unresolved('Date is a contextual reference, not an authorized bounded window; choose explicit bounded lookups.'),
                **({'reference_date': chosen} if chosen else {})}
    try:
        if stamps:
            if len(stamps) > 2 or any(not re.search(r'(Z|[+-]\d\d:\d\d)$', s) for s in stamps):
                return unresolved('Timestamp needs an explicit UTC/offset; use at most two bounds.')
            values = [required_time(s) for s in stamps]
            if chosen and any(v[:10] != chosen for v in values):
                return unresolved('Date hint conflicts with the UTC timestamp window.')
            if len(values) == 2:
                if not paired:
                    return unresolved('Two timestamp references are not an explicit range; use between START and END.')
                return window(*values, source='explicit timestamps')
            return anchor(values[0], chosen)
        # Remove numeric timezone offsets before finding clock values.
        zone = re.search(r'(?<![A-Za-z])([+-]\d\d:\d\d)(?!\d)', remaining)
        zones = set(re.findall(r'(?<![A-Za-z])[+-]\d\d:\d\d(?!\d)', remaining))
        if len(zones) > 1 or (zone and re.search(r'\bUTC\b', remaining, re.I) and zone[1] not in ('+00:00', '-00:00')):
            return unresolved('Conflicting clock timezones; supply two full ISO timestamps with offsets.')
        clocks = re.findall(CLOCK, re.sub(r'[+-]\d\d:\d\d', ' ', remaining))
        if clocks:
            if not chosen:
                return unresolved('Time-only request needs --date YYYY-MM-DD or an explicit date.')
            if not zone and not re.search(r'\bUTC\b|\bZ\b', remaining, re.I) and not date_hint:
                return unresolved('Clock time has no timezone; specify UTC or an explicit offset.')
            if len(clocks) > 2 or (len(clocks) == 2 and not paired):
                return unresolved('Ambiguous clock range; use between START and END UTC on DATE.')
            suffix = zone[1] if zone else 'Z'
            def stamp(value):
                parts = value.split(':')
                return required_time(chosen + 'T' + parts[0].zfill(2) + ':' + ':'.join(parts[1:]) + (':00' if len(parts) == 2 else '') + suffix)
            values = [stamp(c) for c in clocks]
            if len(values) == 2:
                return window(*values, source='explicit date and clock range')
            return anchor(values[0], chosen, suffix)
        if chosen:
            qualified_date = re.search(r'\b(?:on|during)\s+(?:\d{4}-\d\d-\d\d|(?:' + '|'.join(MONTHS) + r')\s+\d{1,2},?\s+\d{4})\b', question, re.I)
            if not date_hint and not qualified_date:
                return dict(kind='inferred', date=chosen,
                            limitation='Parsed calendar reference is not an explicit search boundary; choose bounded lookups.')
            return window(chosen + 'T00:00:00Z', chosen + 'T23:59:59.999999999Z',
                          source='--date UTC calendar day' if date_hint else 'parsed date; UTC calendar day')
        if re.search(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|\b(' + '|'.join(MONTHS) + r')\b', question, re.I):
            return unresolved('Ambiguous calendar reference; supply YYYY-MM-DD and UTC for clock times.')
        return dict(kind='none')
    except ValueError:
        return unresolved('Invalid or reversed time window; supply UTC bounds spanning at most 24 hours.')


def window(start, end, *, source):
    start, end = required_time(start), required_time(end)
    if not 0 <= time_ns(end) - time_ns(start) <= 86400 * 10**9:
        raise ValueError('Invalid temporal window')
    return dict(kind='explicit', start=start, end=end, source=source)


def anchor(stamp, calendar_day=None, suffix='Z'):
    from forensic_assistant.correlation.temporal import shift
    start, end = shift(stamp, -300), shift(stamp, 300)
    if calendar_day is None:
        return dict(kind='exploratory', start=start, end=end,
                    source='timestamp anchor; default +/-5 minutes, not an authorization boundary')
    scope = window(calendar_day + 'T00:00:00' + suffix, calendar_day + 'T23:59:59.999999999' + suffix,
                   source='explicit calendar date; initial lookup uses default +/-5 minute anchor window')
    scope.update(initial_anchor=stamp, initial_start=max(scope['start'], start), initial_end=min(scope['end'], end))
    return scope


def validate_proposal(scope, name, args):
    """Called before approval. Expanding an explicit boundary is never implicit."""
    if scope.get('kind') != 'explicit':
        return
    if name == 'show_evidence':
        return  # Full original detail of an already exposed, authorized anchor.
    if name not in ('search_evidence', 'timeline'):
        raise ValueError('Temporal scope requires bounded search/timeline or show_evidence; anchor expansion is not authorized.')
    if not all(k in args for k in ('start', 'end')):
        raise ValueError('Temporal scope requires both start and end within the authorized window.')
    if not time_ns(scope['start']) <= time_ns(required_time(args['start'])) <= time_ns(required_time(args['end'])) <= time_ns(scope['end']):
        raise ValueError('Temporal scope conflict: use start/end within the authorized window; expansion requires a new analyst objective.')

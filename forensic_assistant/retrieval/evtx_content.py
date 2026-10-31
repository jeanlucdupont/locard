"""Explicit bounded EVTX text search over existing retained data, no schema writes."""
import base64
import hashlib
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass

from .event_data import payload, MAX_PAYLOAD
from .queries import required_time
from forensic_assistant.correlation.models import time_ns

CANDIDATES = 1000
PAYLOAD_BYTES = 8 * 1024 * 1024
SECONDS = 5
NORMALIZED = ('process_name', 'parent_process_name', 'command_line', 'script_block', 'service_name', 'task_name')


@dataclass
class ContentResult:
    records: list
    limit: int
    coverage: dict
    limits: list

    def as_dict(self):
        return dict(records=self.records, total=len(self.records), limit=self.limit, offset=0,
                    total_is_lower_bound=not self.coverage['complete'] or self.coverage['continued'],
                    truncated=not self.coverage['complete'], content_search=self.coverage, limits=self.limits)


def cursor(key, scope):
    return base64.urlsafe_b64encode(json.dumps([1, scope, *key], separators=(',', ':')).encode()).decode()


def search(query, **options):
    from forensic_assistant.investigation_ai.case import read_transaction
    if query.db.in_transaction:
        return _search(query, **options)
    with read_transaction(query.db):
        return _search(query, **options)


def _search(query, *, evtx_text, evtx_match='contains', evtx_after=None, start=None, end=None,
           limit=20, offset=0, raw=False, **filters):
    from .evidence import get_evidence
    if not isinstance(evtx_text, str) or not 1 <= len(evtx_text) <= 256 or not evtx_text.strip():
        raise ValueError('EVTX text must contain 1..256 characters')
    if evtx_match not in ('exact', 'contains'):
        raise ValueError('EVTX match must be exact or contains')
    if filters.get('artifact') != 'evtx' or not start or not end:
        raise ValueError('EVTX text search requires --artifact evtx and paired --start/--end')
    if offset or raw or not 1 <= limit <= 50:
        raise ValueError('EVTX text search uses continuation, no raw/offset, and limit 1..50')
    start, end = required_time(start), required_time(end)
    if not 0 <= time_ns(end) - time_ns(start) <= 86400 * 10**9:
        raise ValueError('EVTX text search requires a time window of at most 24 hours')
    filename = next(row[2] for row in query.db.execute('PRAGMA database_list') if row[1] == 'main')
    if filename:
        info = os.stat(filename)
        identity = (info.st_dev, info.st_ino)
    else:
        identity = ('memory', id(query.db))
    scope = hashlib.sha256(json.dumps([identity, evtx_text, evtx_match, start, end, filters], sort_keys=True).encode()).hexdigest()[:24]
    after = None
    if evtx_after is not None:
        try:
            if not isinstance(evtx_after, str) or len(evtx_after) > 1024:
                raise ValueError()
            token = json.loads(base64.b64decode(evtx_after, altchars=b'-_', validate=True))
            if (not isinstance(token, list) or len(token) != 4 or token[:2] != [1, scope]
                    or not all(isinstance(v, str) for v in token[2:]) or len(token[3]) > 160
                    or not start <= token[2] <= end):
                raise ValueError()
            after = tuple(token[2:])
        except (ValueError, TypeError, UnicodeError):
            raise ValueError('Invalid EVTX continuation for this search scope') from None
    db = query.db
    clauses, params = query._where(**filters)
    clauses += ['v.timestamp_utc>=?', 'v.timestamp_utc<=?']
    params += [start, end]
    if after:
        clauses.append('(v.timestamp_utc>? OR (v.timestamp_utc=? AND v.id>?))')
        params += [after[0], after[0], after[1]]
    # LIMIT bounds fetched identities, not SQLite sorting work. The independent
    # interrupt timer bounds that work without replacing the worker's handler.
    sql = ('SELECT v.id,v.timestamp_utc FROM events v INDEXED BY idx_time '
           'CROSS JOIN evidence_records e ON e.evidence_id=v.id WHERE ' + ' AND '.join(clauses)
           + ' ORDER BY v.timestamp_utc,v.id LIMIT ?')
    deadline = time.monotonic() + SECONDS
    expired = threading.Event()
    def interrupt():
        expired.set()
        db.interrupt()
    timer = threading.Timer(SECONDS, interrupt)
    timer.daemon = True
    records, notes = [], []
    examined = consumed = skipped = 0
    last = after
    complete = False
    timer.start()
    try:
        rows = db.execute(sql, [*params, CANDIDATES + 1]).fetchall()
        for row in rows[:CANDIDATES]:
            if time.monotonic() >= deadline or expired.is_set():
                notes.append('EVTX content search execution-time bound reached; coverage incomplete')
                break
            # Fetch bounded prefixes only. Oversize payloads are explicitly skipped,
            # never parsed as if their prefixes were complete original values.
            names = ('event_data_json', *NORMALIZED)
            selected = ','.join('substr('+name+',1,?) AS '+name for name in names)
            lengths = '+'.join('coalesce(length(CAST('+name+' AS BLOB)),0)' for name in names)
            sizes = db.execute('SELECT ('+lengths+') AS payload_bytes, '
                               'length(CAST(raw_xml AS BLOB)) AS xml_bytes FROM events WHERE id=?',
                               (row['id'],)).fetchone()
            size = sizes['payload_bytes']
            if size > MAX_PAYLOAD or sizes['xml_bytes'] > 131072:
                examined += 1
                skipped += 1
                last = (row['timestamp_utc'], row['id'])
                continue
            if consumed + size > PAYLOAD_BYTES:
                notes.append('EVTX content search payload budget reached; coverage incomplete')
                break
            data = dict(db.execute('SELECT '+selected+' FROM events WHERE id=?',
                                   [MAX_PAYLOAD + 1]*len(names) + [row['id']]).fetchone())
            examined += 1
            consumed += size
            entries, issues = payload(data)
            if issues:
                skipped += 1
            matches = []
            for item in [dict(ordinal=None, name=k, value=data.get(k), basis='normalized_field') for k in NORMALIZED] + [dict(x, basis='original_event_data') for x in entries]:
                value = item['value']
                if not isinstance(value, str):
                    continue
                # Literal, case-sensitive comparisons; no implicit normalization.
                position = 0 if evtx_match == 'exact' and value == evtx_text else value.find(evtx_text) if evtx_match == 'contains' else -1
                if position < 0:
                    continue
                begin = max(0, position - 40)
                matches.append(dict(ordinal=item['ordinal'], name=item['name'][:80], basis=item['basis'],
                                    mode=evtx_match, excerpt=value[begin:begin+320], value_offset=begin,
                                    truncated=begin > 0 or len(value) > begin+320 or len(item['name']) > 80))
            if matches:
                record = get_evidence(db, row['id'])
                record['content_matches'] = matches[:4]
                record['content_matches_truncated'] = len(matches) > 4
                records.append(record)
            last = (row['timestamp_utc'], row['id'])
            if len(records) >= limit:
                break
        complete = examined == len(rows) and skipped == 0 and not notes
    except sqlite3.OperationalError as exc:
        if getattr(exc, 'sqlite_errorcode', None) != sqlite3.SQLITE_INTERRUPT or not expired.is_set():
            raise  # Preserve outer worker deadline, authorization and other failures.
        notes.append('EVTX content search execution-time bound reached; coverage incomplete')
    finally:
        timer.cancel()
        timer.join()  # No interrupt can escape into the caller's next operation.
    if skipped:
        notes.append(f'{skipped} candidate payloads were oversized or malformed; coverage incomplete')
    if not complete:
        notes.append('No absence conclusion: only bounded candidates were examined; continue or narrow the filters')
    continuation = cursor(last, scope) if not complete and last is not None and last != after else None
    coverage = dict(complete=complete, continued=bool(after), examined=examined, skipped=skipped,
                    payload_bytes=consumed, next_cursor=continuation,
                    ordering='SystemTime, evidence ID', match=evtx_match,
                    case_consistency='Continuation requires unchanged case contents; no cross-command snapshot is implied')
    return ContentResult(records, limit, coverage, notes)

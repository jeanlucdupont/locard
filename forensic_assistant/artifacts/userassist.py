"""Conservative interpretation of existing Registry value bytes, not new identity.

Layouts: libyal/winreg-kb, docs/sources/explorer-keys/User-assist.md.
Only declared formats 3 (16 bytes) and 5 (72 bytes) are interpreted. Unknown
focus/session fields and known-folder GUID expansion are deliberately omitted.
"""
import codecs
import re

from .times import filetime

PREFIX = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\'
COUNT = re.compile(re.escape(PREFIX) + r'\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}\\Count', re.I)
SLOT = 'UserAssist.LastExecution'
SOURCE = 'UserAssist LastExecution'
MEANING = 'Recorded execution/user-interaction timestamp; not proof of process creation or user intent'
LIMITATION = 'UserAssist binary data could not be interpreted with the current parser.'


def decoded_name(key_path, name):
    if not isinstance(key_path, str) or not COUNT.fullmatch(key_path):
        return None
    return codecs.decode(name, 'rot_13')


def interpret(key_path, name, value_type, raw, version, *, size=None):
    decoded = decoded_name(key_path, name)
    if decoded is None:
        return None
    size = len(raw) if size is None else size
    special = decoded.upper().startswith('UEME_') and not decoded.upper().startswith(('UEME_RUNPATH:', 'UEME_RUNCPL:'))
    result = dict(raw_name=name, decoded_name=decoded, declared_version=version,
                  structure_size=size, entry_kind='control_or_special' if special else 'application_reference',
                  status='unsupported')
    if special:
        result.update(status='control', limitation='Control/special entry; not interpreted as application execution.')
        return result
    if not decoded or value_type != 3 or version not in (3, 5) or size != {3: 16, 5: 72}[version] or len(raw) != size:
        result['limitation'] = LIMITATION
        return result
    counter = int.from_bytes(raw[4:8], 'little')
    offset = 8 if version == 3 else 60
    stamp = filetime(int.from_bytes(raw[offset:offset + 8], 'little'), SLOT, SOURCE, MEANING)
    result.update(status='parsed', recorded_count=counter,
                  count_semantics='Unadjusted legacy counter; not a literal execution total' if version == 3 else
                                  'Recorded run/interaction count; not a process-instance count',
                  last_execution=stamp)
    if stamp['normalization_status'] == 'invalid':
        result['limitation'] = 'UserAssist internal timestamp is invalid; no execution time is inferred.'
    return result


def load(db, evidence_id):
    """Bound raw reads even for unsupported large values; never update evidence."""
    row = db.execute('''SELECT v.value_name,v.value_type,length(v.raw_data) AS size,
        substr(v.raw_data,1,73) AS data,k.key_path,k.parent_id
        FROM registry_values v JOIN registry_keys k ON k.evidence_id=v.key_id
        WHERE v.evidence_id=?''', (evidence_id,)).fetchone()
    if not row or decoded_name(row['key_path'], row['value_name']) is None:
        return None
    versions = db.execute('''SELECT value_type,substr(raw_data,1,5) AS data FROM registry_values
        WHERE key_id=? AND value_name='Version' COLLATE NOCASE LIMIT 2''', (row['parent_id'],)).fetchall()
    version = None
    if len(versions) == 1 and versions[0]['value_type'] == 4 and len(versions[0]['data']) == 4:
        version = int.from_bytes(versions[0]['data'], 'little')
    return interpret(row['key_path'], row['value_name'], row['value_type'], row['data'], version, size=row['size'])


def timeline_cte(db):
    """Read-only fallback for old cases; persisted slots are never duplicated.

    Only recognized UserAssist values gain inherited key context in the timeline.
    Ordinary Registry values keep their existing timeline behavior. SQL pagination,
    host/source filters and worker deadlines still apply to the complete union.
    """
    def execution_time(eid):
        data = load(db, eid)
        return (data or {}).get('last_execution', {}).get('timestamp_utc')
    db.create_function('locard_userassist_time', 1, execution_time)
    return r'''WITH locard_ua AS (
        SELECT v.evidence_id,v.key_id,locard_userassist_time(v.evidence_id) AS timestamp_utc
        FROM registry_values v JOIN registry_keys k ON k.evidence_id=v.key_id
        WHERE k.key_path LIKE 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\%\Count'
    ), locard_times AS (
        SELECT evidence_id,slot,timestamp_utc FROM evidence_timestamps
        UNION ALL
        SELECT u.evidence_id,'UserAssist.LastExecution',u.timestamp_utc FROM locard_ua u
        WHERE u.timestamp_utc IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM evidence_timestamps t WHERE t.evidence_id=u.evidence_id AND t.slot='UserAssist.LastExecution')
        UNION ALL
        SELECT u.evidence_id,t.slot,t.timestamp_utc FROM locard_ua u
        JOIN evidence_timestamps t ON t.evidence_id=u.key_id
        WHERE u.timestamp_utc IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM evidence_timestamps own WHERE own.evidence_id=u.evidence_id AND own.slot=t.slot)
    ) '''

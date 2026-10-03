import hashlib
import json
import re
from forensic_assistant.database.context import host_key
from forensic_assistant.database.db import now
from forensic_assistant.database.artifacts import dump


def normalize_volume_root(volume_root):
    if volume_root and not re.fullmatch(r'[A-Za-z]:\\?', volume_root):
        raise ValueError('Volume root must be an explicit drive letter such as C:')
    volume_root = volume_root[:2].upper() if volume_root else None
    return volume_root


def bind_context(db, sha, source_file, hostname=None, username=None, volume_root=None):
    volume_root = normalize_volume_root(volume_root)
    data = [sha, host_key(hostname), username, volume_root, 'analyst-supplied', source_file]
    key = hashlib.sha256(dump(data).encode()).hexdigest()
    if any((hostname, username, volume_root)):
        db.execute('INSERT INTO source_contexts VALUES (?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING', [key, *data, now()])


def effective_context(db, record):
    rows = [dict(r) for r in db.execute(
        'SELECT * FROM source_contexts WHERE file_sha256=? ORDER BY context_id',
        (record['file_sha256'],)
    )]
    from forensic_assistant.database.sources import memberships, MEMBERSHIP
    members = memberships(db, record['file_sha256'])
    result = {'assertions': rows, 'conflicts': []}
    if db.execute('PRAGMA user_version').fetchone()[0] == 4:
        result.update(source_ids=[s['source_id'] for s in members], source_assertions=members)
    source_conflict = False
    for s in members:
        hosts = {r[0] for r in db.execute(
            '''SELECT DISTINCT lower(e.hostname) FROM evidence_records e JOIN (''' + MEMBERSHIP + ''') m USING(file_sha256)
            WHERE m.source_id=? AND e.hostname IS NOT NULL LIMIT 2''',
            (s['source_id'],)
        )}
        if s['hostname']:
            hosts.add(s['hostname'])
        if len(hosts) > 1:
            source_conflict = True
    for name in ('hostname', 'username', 'volume_root'):
        values = {r[name] for r in [*rows, *members] if r[name]}
        if record.get(name):
            values.add(host_key(record[name]) if name == 'hostname' else record[name])
        result[name] = next(iter(values)) if len(values) == 1 else None
        if len(values) > 1:
            result['conflicts'].append(name)
    if len(members) > 1 or source_conflict:
        result['hostname'] = None
        result['conflicts'].append('source membership' if len(members) > 1 else 'source/artifact hostname')
    result['basis'] = 'artifact field' if record.get('hostname') else 'analyst-supplied' if result['hostname'] else 'unknown'
    return result

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
    browser = record.get('source_type') == 'browser'
    rows = [] if browser else [dict(r) for r in db.execute(
        'SELECT * FROM source_contexts WHERE file_sha256=? ORDER BY context_id',
        (record['file_sha256'],)
    )]
    if browser:
        from forensic_assistant.database.browser import provenance
        rows = []  # File-wide assertions never establish browser occurrence context.
        members, occurrences = provenance(db, record['evidence_id'])
    else:
        from forensic_assistant.database.sources import memberships
        members = memberships(db, record['file_sha256'])
    result = {'assertions': rows, 'conflicts': []}
    if browser:
        result['browser_occurrences'] = occurrences
    if db.execute('PRAGMA user_version').fetchone()[0] in (4, 5):
        result.update(source_ids=[s['source_id'] for s in members], source_assertions=members)
    for name in ('hostname', 'username', 'volume_root'):
        values = {r[name] for r in [*rows, *members] if r[name]}
        if record.get(name):
            values.add(host_key(record[name]) if name == 'hostname' else record[name])
        result[name] = next(iter(values)) if len(values) == 1 else None
        if len(values) > 1:
            result['conflicts'].append(name)
    if len(members) > 1:
        result['hostname'] = None
        result['conflicts'].append('source membership')
    # Other records' artifact hosts describe source coverage, not this record.
    artifact_host = host_key(record.get('hostname'))
    asserted_hosts = {r['hostname'] for r in [*rows, *members] if r['hostname']}
    if len(members) > 1:
        basis = 'ambiguous source membership'
    elif 'hostname' in result['conflicts']:
        basis = 'source/artifact mismatch' if artifact_host else 'conflicting analyst assertions'
    elif artifact_host and asserted_hosts:
        basis = 'source/artifact agreement'
    elif artifact_host:
        basis = 'artifact field'
    else:
        basis = 'analyst-supplied' if result['hostname'] else 'unknown'
    result['basis'] = basis
    return result

"""Deterministic Chromium History parsing; only private copies enter SQLite."""
from contextlib import closing
from pathlib import Path
import hashlib
import shutil
import sqlite3
from .storage import base_record
from .times import filetime
from forensic_assistant.database.artifacts import dump
from forensic_assistant.database.browser import context_id
from forensic_assistant.ingest.evtx import digest

MAX_INPUT = 8 * 1024 ** 3
STATES = {0: 'in progress', 1: 'complete', 2: 'cancelled', 3: 'interrupted'}
TABLES = ('urls', 'visits', 'downloads', 'downloads_url_chains')


def validate_options(product, profile):
    if product not in ('chrome', 'edge'):
        raise ValueError('Browser product must be explicitly chrome or edge')
    if not isinstance(profile, str) or not profile.strip() or len(profile) > 4096 or '\x00' in profile:
        raise ValueError('Supply an explicit browser profile of 1..4096 characters')


def inventory(path):
    """No SQLite connection to original evidence, including its companions."""
    result = {}
    for suffix in ('', '-wal', '-shm', '-journal'):
        item = Path(str(path) + suffix)
        if not item.exists():
            if not suffix:
                raise ValueError('History must be an existing file')
            continue
        if not item.is_file() or item.is_symlink():
            raise ValueError('History and companions must be regular files')
        size = item.stat().st_size
        if size > MAX_INPUT:
            raise ValueError('Browser input exceeds 8 GiB per-file limit')
        result[suffix] = {'sha256': digest(item), 'size': size}
    if result.get('-journal', {}).get('size'):
        raise ValueError('History rollback journal present; supply a consistent acquired snapshot (no recovery performed)')
    return result


def snapshot(path, destination, product, profile):
    validate_options(product, profile)
    before = inventory(path)
    for suffix in ('', '-wal'):
        if suffix in before:
            target = Path(str(destination) + suffix)
            with open(str(path) + suffix, 'rb') as source, target.open('xb') as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            if digest(target) != before[suffix]['sha256']:
                raise ValueError('History changed while copying; snapshot rejected')
    if inventory(path) != before:
        raise ValueError('History companions changed while copying; snapshot rejected')
    # SHM is a reconstructible index, never the identity of committed evidence.
    identity = {key: before[key] for key in ('', '-wal') if key in before}
    sha = hashlib.sha256(dump(identity).encode()).hexdigest()
    return dict(browser_product=product, profile=profile, snapshot_sha256=sha,
                context_id=context_id(sha, product, profile), manifest=before)


def timestamp(value, slot):
    result = filetime(value * 10 if type(value) is int else None, slot,
                      'Chromium History', 'Browser-recorded ' + slot.split('.')[-1])
    result.update(original_value=str(value) if value is not None else None,
                  encoding='Chromium microseconds since 1601-01-01 UTC', precision_ns=1000)
    if value not in (None, 0) and type(value) is not int:
        result['normalization_status'] = 'invalid'
    return result


def parse(path, sha, *, browser_product, profile, snapshot_sha256, context_id, manifest):
    validate_options(browser_product, profile)
    # Writable private directory permits SQLite to reconstruct SHM, but the
    # evidence connection itself is read-only. No checkpoint/repair is issued.
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True, timeout=.2)) as db:
        db.row_factory = sqlite3.Row
        db.enable_load_extension(False)
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA query_only=ON')
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16 * 1024 * 1024)
        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 65536)
        definitions = db.execute("SELECT name,type,sql FROM sqlite_master WHERE name IN ('urls','visits','downloads','downloads_url_chains')").fetchall()
        if any(row['type'] != 'table' or 'VIRTUAL' in (row['sql'] or '').upper() for row in definitions):
            raise ValueError('Unsupported Chromium History schema: executable table/view refused')
        layouts = {name: list(db.execute('PRAGMA table_info(' + name + ')')) for name in TABLES}
        columns = {name: {r['name'] for r in layout} for name, layout in layouts.items()}
        for table in ('urls', 'visits', 'downloads'):
            if columns[table] and [r['name'] for r in layouts[table] if r['pk']] != ['id']:
                raise ValueError('Unsupported Chromium History schema: stable primary row identity required: ' + table)
        required = {'urls': {'id', 'url'}, 'visits': {'id', 'url', 'visit_time'}}
        for table, names in required.items():
            if not names <= columns[table]:
                raise ValueError('Unsupported Chromium History schema: required table/column missing: ' + table)
        if columns['downloads'] and not {'id', 'start_time'} <= columns['downloads']:
            raise ValueError('Unsupported Chromium History schema: required download columns missing')
        if 'full_path' in columns['downloads'] and not {'target_path', 'current_path'} & columns['downloads']:
            raise ValueError('Unsupported Chromium History schema: legacy download timestamp epoch; no conversion guessed')
        if columns['downloads_url_chains'] and not {'id', 'chain_index', 'url'} <= columns['downloads_url_chains']:
            raise ValueError('Unsupported Chromium History schema: required URL-chain columns missing')
        allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ}
        db.set_authorizer(lambda action, a, b, c, d: sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY)
        warnings = ['Browser history may be deleted, expired, synchronized, or absent from the supplied profile; missing history is not proof of no activity.']
        if '-wal' not in manifest:
            warnings.append('No WAL supplied; uncheckpointed browser activity may be absent.')
        else:
            warnings.append('Committed WAL content read by SQLite from a private copy; no WAL carving performed.')
        optional = {'urls': ('title', 'visit_count', 'typed_count'), 'visits': ('transition',),
                    'downloads': ('target_path', 'current_path', 'end_time', 'state', 'danger_type', 'mime_type', 'received_bytes', 'total_bytes', 'referrer')}
        for table, names in optional.items():
            missing = sorted(set(names) - columns[table])
            if missing:
                warnings.append('Unavailable optional ' + table + ' fields: ' + ', '.join(missing))
        def field(table, alias, name, output=None):
            return (alias + '.' + name if name in columns[table] else 'NULL') + ' AS ' + (output or name)
        fields = ['v.id', 'v.url AS url_row_id', 'v.visit_time', 'u.url']
        fields += [field('urls', 'u', n, 'url_' + n if n.endswith('count') else n) for n in optional['urls']]
        fields += [field('visits', 'v', 'transition')]
        for row in db.execute('SELECT ' + ','.join(fields) + ' FROM visits v LEFT JOIN urls u ON u.id=v.url ORDER BY v.id'):
            detail = dict(row)
            yield pack(detail, 'visit', [timestamp(row['visit_time'], 'Browser.VisitTime')], warnings,
                       browser_product, profile, context_id)
        if not columns['downloads']:
            return
        names = ('target_path', 'current_path', 'full_path', 'url', 'referrer', 'mime_type',
                 'received_bytes', 'total_bytes', 'state', 'danger_type', 'end_time')
        chains = iter(db.execute('SELECT id,chain_index,url FROM downloads_url_chains ORDER BY id,chain_index,url')) if columns['downloads_url_chains'] else iter(())
        chain = next(chains, None)
        for row in db.execute('SELECT d.id,d.start_time,' + ','.join(field('downloads', 'd', n) for n in names) + ' FROM downloads d ORDER BY d.id'):
            detail = dict(row)
            urls = []
            while chain is not None and chain['id'] <= row['id']:
                if chain['id'] == row['id']:
                    if type(chain['chain_index']) is not int or chain['chain_index'] < 0:
                        raise ValueError('Invalid Chromium download chain index')
                    if len(urls) >= 1000:
                        raise ValueError('Download URL chain exceeds 1000-entry bound')
                    urls.append({'chain_index': chain['chain_index'], 'url': chain['url']})
                chain = next(chains, None)
            detail['url_chain'] = urls
            detail['state_name'] = STATES.get(detail['state'], 'unknown')
            stamps = [timestamp(row['start_time'], 'Browser.DownloadStart'), timestamp(row['end_time'], 'Browser.DownloadEnd')]
            yield pack(detail, 'download', stamps, warnings, browser_product, profile, context_id)


def pack(detail, kind, stamps, warnings, product, profile, context):
    row_id = detail.pop('id')
    if type(row_id) is not int:
        raise ValueError('Unsupported Chromium History row identity')
    detail.update(browser_product=product, profile=profile, context_id=context)
    eid = 'BROWSER:' + context.split(':', 1)[1] + ':' + kind + ':' + str(row_id)
    objects = []
    if kind == 'download':
        for name in ('target_path', 'current_path', 'full_path'):
            if isinstance(detail.get(name), str) and detail[name]:
                objects.append(dict(slot=name, role='download_target' if name == 'target_path' else 'download_path', original=detail[name]))
    urls = ([detail.get('url')] if kind == 'visit' else [detail.get('url'), *(item['url'] for item in detail['url_chain'])])
    for index, url in enumerate(urls):
        if isinstance(url, str) and url:
            objects.append(dict(slot='url:' + str(index), role='browser_url', original=url))
    notes = [*warnings, 'Browser-recorded navigation does not prove that a user read or interacted with the page.' if kind == 'visit' else 'A download record does not prove execution or that the file still exists.']
    return dict(record=base_record(eid, 'browser', 'browser_' + kind,
                                 {'table': 'visits' if kind == 'visit' else 'downloads', 'row_id': row_id, 'context_id': context}, notes, detail),
                detail=detail, timestamps=stamps, objects=objects)

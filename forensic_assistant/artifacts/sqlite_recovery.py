"""Bounded SQLite rollback on a separate private working set, never sources."""
from contextlib import closing, ExitStack
from datetime import datetime, timezone
from pathlib import Path
import os
import shutil
import sqlite3
import stat
import struct
import time
import uuid

from .browser_journal import MAGIC, SnapshotError, head, validate
from forensic_assistant.ingest.evtx import digest
from forensic_assistant.investigation_ai.storage import local_path, DirectoryGuard
from forensic_assistant.investigation_ai.snapshot import _private_mkdir, SnapshotFile

MAX_BYTES = 8 * 1024**3
TIMEOUT = 120
LIMITATION = 'Source freeze was not established; stable copies and SQLite consistency do not prove a single filesystem instant.'


def stamp():
    return datetime.now(timezone.utc).isoformat()


def fail(category, reason, manifest):
    raise SnapshotError(category, reason, manifest)


def regular(path):
    path = local_path(Path(path).absolute())
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('SQLite snapshot must be an unaliased regular file')
    return info


def identity(path):
    info = regular(path)
    return dict(device=info.st_dev, inode=info.st_ino, size=info.st_size, mtime_ns=info.st_mtime_ns)


def inventory(path):
    result = {}
    for suffix in ('', '-wal', '-shm', '-journal'):
        item = Path(str(path)+suffix)
        if not item.exists():
            if not suffix: raise ValueError('History must be an existing file')
            continue
        info = regular(item)
        if info.st_size > MAX_BYTES:
            fail('resource_limit', 'SQLite input exceeds the per-file size limit', result)
        result[suffix] = dict(sha256=digest(item), size=info.st_size)
    return result


def acquire(path, destination, source_context=None):
    """Read-only acquisition plus supervised validation, independent of CLI/browser identity."""
    from forensic_assistant.activity import AuditError
    try:
        with DirectoryGuard(Path(destination).absolute().parent):
            return _acquire(path, destination, source_context)
    except (SnapshotError, AuditError):
        raise
    except (OSError, ValueError) as exc:
        error = SnapshotError('filesystem_io_failure' if isinstance(exc,OSError) else 'inconsistent_acquisition',
                              'SQLite acquisition could not be validated', {})
        error.diagnostics['exception_class'] = type(exc).__name__
        for key in ('errno','winerror'):
            if type(getattr(exc,key,None)) is int: error.diagnostics[key] = getattr(exc,key)
        raise error from exc


def _acquire(path, destination, source_context):
    from .progress import snapshot_reader
    from .ingest import worker
    before = inventory(path)
    required = sum(item['size'] for suffix,item in before.items() if suffix != '-shm')
    if required > MAX_BYTES or shutil.disk_usage(Path(destination).parent).free < required + 64*1024**2:
        fail('resource_limit', 'insufficient SQLite acquisition staging capacity', before)
    identities = {suffix: identity(str(path)+suffix) for suffix in before}
    for suffix in ('', '-wal', '-journal'):
        if suffix not in before: continue
        target = Path(str(destination)+suffix)
        with snapshot_reader(Path(str(path)+suffix)) as source, target.open('xb') as output:
            opened = os.fstat(source.fileno())
            if (opened.st_dev, opened.st_ino) != (identities[suffix]['device'], identities[suffix]['inode']):
                fail('inconsistent_acquisition', 'source identity changed before copying', before)
            shutil.copyfileobj(source, output, 1024*1024)
        if digest(target) != before[suffix]['sha256']:
            fail('snapshot_consistency_not_established', 'SQLite source changed while copying', before)
    if inventory(path) != before or any(identity(str(path)+s) != identities[s] for s in before):
        fail('snapshot_consistency_not_established', 'SQLite companions changed while copying', before)
    recovery = None
    try:
        validation = worker('sqlite_validate', str(destination), before['']['sha256'],
                            Path(str(destination)+'.validation'), dict(manifest=before), 30)
    except SnapshotError as exc:
        if exc.diagnostics['category'] in ('journal_indeterminate', 'snapshot_consistency_not_established',
                                            'missing_required_companion', 'sqlite_validation_failed'):
            from .sqlite_immutable import prepare
            extracted, extraction = prepare(destination, before, path, identities, source_context, exc.diagnostics)
            return dict(manifest=before, extraction=extraction, _database_path=str(extracted),
                        sqlite_validation=dict(rollback_journal=exc.diagnostics['category'], recovery_performed=False))
        if exc.diagnostics['category'] != 'journal_active_or_hot': raise
        extracted, recovery = recover(destination, before, path, identities, source_context)
        validation = dict(rollback_journal='recovered', recovery_performed=True,
                          validation='read_only_integrity_check', acquisition_limitation=LIMITATION)
    except KeyboardInterrupt as exc:
        exc.diagnostics = dict(artifact='browser', category='recovery_cancelled', recovery_attempted=False)
        raise
    except (OSError, ValueError) as exc:
        category = 'resource_limit' if 'timed out' in str(exc) or 'limit' in str(exc) else 'filesystem_io_failure' if isinstance(exc,OSError) else 'sqlite_validation_failed'
        raise SnapshotError(category, 'bounded SQLite snapshot validation did not complete', before) from exc
    result = dict(manifest=before, sqlite_validation=validation)
    validation.update(extraction_mode='recovered' if recovery else 'normal',
                      acquisition_consistency='not_established',
                      transactional_consistency='not_established', integrity_check='passed')
    if recovery: result.update(recovery=recovery, _database_path=str(extracted))
    return result


def eligible(path, manifest, deadline):
    """Validate journal records, not implement rollback. Reject external references.

    SQLite may ignore a bad checksum. We must reject it before SQLite entry.
    A final unsynced segment is allowed only when every page still equals the
    main-file page, proving no rollback of that segment is necessary.
    """
    dbhead = head(path, 100)
    page = int.from_bytes(dbhead[16:18], 'big'); page = 65536 if page == 1 else page
    if (len(dbhead) != 100 or dbhead[:16] != b'SQLite format 3\0' or dbhead[18:20] != b'\1\1'
            or page < 512 or page > 65536 or page & (page-1)
            or manifest.get('-wal', {}).get('size') or manifest.get('-shm', {}).get('size')):
        fail('recovery_unsupported', 'mixed or unsupported SQLite recovery state', manifest)
    size = manifest['']['size']
    if size % page or size < page:
        fail('inconsistent_acquisition', 'database is truncated or has invalid page geometry', manifest)
    journal = Path(str(path) + '-journal')
    length = manifest.get('-journal', {}).get('size', 0)
    seen = set(); segments = 0; original_pages = None; first_sector = None; position = 0
    with journal.open('rb') as stream, Path(path).open('rb') as database:
        stream.seek(-min(length, 8), 2)
        if stream.read(8) == MAGIC:
            fail('recovery_unsupported', 'external super-journal references are unsupported', manifest)
        while position < length:
            if time.monotonic() >= deadline or len(seen) >= 1_000_000:
                fail('resource_limit', 'SQLite recovery eligibility limit reached', manifest)
            stream.seek(position); raw = stream.read(28)
            if len(raw) != 28:
                fail('journal_incomplete', 'rollback journal header is truncated', manifest)
            count, nonce, pages, sector, journal_page = struct.unpack('>5I', raw[8:])
            if (sector < 512 or sector > 65536 or sector & (sector-1) or journal_page != page
                    or not pages or pages > size // page or (original_pages is not None and pages != original_pages)
                    or first_sector is not None and sector != first_sector):
                fail('journal_malformed', 'rollback journal geometry is inconsistent', manifest)
            original_pages = pages
            first_sector = sector
            unsynced = raw[:8] == bytes(8) and count == 0 and segments > 0
            if raw[:8] != MAGIC and not unsynced:
                fail('recovery_unsupported', 'journal has no supported synchronized recovery header', manifest)
            start = position + sector
            if unsynced or count == 0xffffffff:
                remaining = length - start
                if remaining < 0 or remaining % (page+8):
                    fail('journal_incomplete', 'rollback journal tail is incomplete or references an external journal', manifest)
                count = remaining // (page+8)
            if count == 0 or start + count*(page+8) > length:
                fail('journal_incomplete', 'rollback journal records are missing', manifest)
            stream.seek(start)
            for _ in range(count):
                if time.monotonic() >= deadline or len(seen) >= 1_000_000:
                    fail('resource_limit', 'SQLite recovery eligibility limit reached', manifest)
                number = int.from_bytes(stream.read(4), 'big'); data = stream.read(page)
                checksum = int.from_bytes(stream.read(4), 'big')
                if not 1 <= number <= pages or number in seen:
                    fail('journal_malformed', 'invalid or duplicate journal page or external reference', manifest)
                if (nonce + sum(data[i] for i in range(page-200, -1, -200))) & 0xffffffff != checksum:
                    fail('journal_malformed', 'rollback journal page checksum failed', manifest)
                seen.add(number)
                if unsynced:
                    database.seek((number-1)*page)
                    if database.read(page) != data:
                        fail('inconsistent_acquisition', 'unsynchronized journal page differs from the database', manifest)
            end = start + count*(page+8)
            if end == length:
                break
            if unsynced:
                fail('recovery_unsupported', 'unexpected rollback journal tail', manifest)
            position = ((end+sector-1)//sector)*sector
            # Only zero alignment padding is permitted; no super-journal footer.
            if position > length or stream.read(position-end) != bytes(position-end):
                fail('recovery_unsupported', 'unexpected rollback journal reference or tail', manifest)
            segments += 1
    return dict(journal_pages=len(seen), original_database_pages=original_pages, page_size=page)


def recover_worker(path, control, options):
    """Invoked only through the existing guarded parser subprocess."""
    manifest = options['manifest']; path = Path(path)
    root = Path(control).parent / 'sqlite-working'
    deadline = time.monotonic() + TIMEOUT
    started = stamp()
    for suffix, item in manifest.items():
        if suffix == '-shm': continue  # SHM not used for rollback; rejected if nonempty.
        regular(str(path)+suffix)
        if digest(str(path)+suffix) != item['sha256']:
            fail('inconsistent_acquisition', 'private acquisition hash changed', manifest)
    geometry = eligible(path, manifest, deadline)
    total = sum(item['size'] for item in manifest.values())
    if total * 2 > MAX_BYTES or shutil.disk_usage(path.parent).free < total + 64*1024**2:
        fail('resource_limit', 'insufficient SQLite recovery staging capacity', manifest)
    _private_mkdir(root)
    with DirectoryGuard(root):
        working = root / 'History'
        for suffix in ('', '-journal'):
            with open(str(path)+suffix, 'rb') as source, open(str(working)+suffix, 'xb') as output:
                shutil.copyfileobj(source, output, 1024*1024)
            regular(str(working)+suffix)
            if digest(str(working)+suffix) != manifest[suffix]['sha256']:
                fail('inconsistent_acquisition', 'working copy hash mismatch', manifest)
        try:
            # First schema read triggers SQLite's own hot-journal rollback.
            with closing(sqlite3.connect(working.as_uri()+'?mode=rw', uri=True, timeout=.2)) as db:
                db.enable_load_extension(False)
                db.execute('PRAGMA trusted_schema=OFF')
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16*1024*1024)
                db.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
                db.execute('SELECT count(*) FROM sqlite_schema').fetchone()
        except sqlite3.Error as exc:
            error = SnapshotError('sqlite_recovery_failed', 'SQLite rollback failed on the disposable copy', manifest, attempted=True)
            error.diagnostics['sqlite_errorcode'] = getattr(exc, 'sqlite_errorcode', None)
            raise error from exc
        remaining = Path(str(working)+'-journal')
        if remaining.exists() and remaining.stat().st_size and head(remaining, 28) != bytes(28):
            raise SnapshotError('sqlite_recovery_failed', 'SQLite did not complete rollback', manifest, attempted=True)
        derived = dict(sha256=digest(working), size=regular(working).st_size)
        try:
            validate(working, {'': derived})
        except SnapshotError as exc:
            raise SnapshotError('derived_validation_failed', 'derived SQLite validation failed', manifest, attempted=True) from exc
        # Acquisition bytes remain available and unchanged throughout recovery.
        for suffix in ('', '-journal'):
            if digest(str(path)+suffix) != manifest[suffix]['sha256']:
                fail('inconsistent_acquisition', 'preserved acquisition changed during recovery', manifest)
        return dict(contract='sqlite-recovery-v1', category='recovery_succeeded', method='sqlite_hot_journal_rollback',
                    sqlite_version=sqlite3.sqlite_version, started_utc=started, completed_utc=stamp(),
                    original_manifest=manifest, derived=derived, geometry=geometry,
                    validation='read_only_integrity_check', disposable_copy=True,
                    companion_disposition='SQLite invalidated/deleted the working journal; acquired journal preserved',
                    limitations=[LIMITATION])


def recover(path, manifest, source_path, identities, source_context=None):
    """Parent service. Audit completion is durable before callers can publish."""
    from forensic_assistant import activity
    from .ingest import worker
    if activity.CURRENT.get() is None:
        fail('recovery_unsupported', 'a bound mandatory audit session is required for recovery', manifest)
    reference = uuid.uuid4().hex
    with activity.mutation('SQLITE_RECOVERY', acquisition_reference=reference,
                           source_path=str(source_path), original_manifest=manifest,
                           original_file_identities=identities, source_context=source_context or {}, limitations=[LIMITATION]) as event:
        activity.event('SQLITE_RECOVERY_START', required=True, acquisition_reference=reference)
        try:
            with ExitStack() as guards:
                guards.enter_context(DirectoryGuard(Path(path).parent))
                for suffix in ('', '-journal'):
                    pinned = SnapshotFile(str(path)+suffix)
                    guards.callback(pinned.close)
                result = worker('sqlite_recovery', str(path), manifest['']['sha256'],
                                Path(path).parent/'sqlite-control', dict(manifest=manifest), TIMEOUT)
        except KeyboardInterrupt as exc:
            exc.diagnostics = dict(category='recovery_cancelled', artifact='browser')
            event.update(recovery_status='cancelled', worker_cleanup='confirmed')
            raise
        except (OSError, ValueError) as exc:
            event.update(recovery_status='failed', worker_cleanup='confirmed')
            if isinstance(exc, SnapshotError):
                exc.diagnostics.update(acquisition_reference=reference, worker_cleanup='confirmed')
                event['diagnostics'] = exc.diagnostics
                raise
            category = 'resource_limit' if 'timed out' in str(exc) or 'limit' in str(exc) else 'filesystem_io_failure'
            error = SnapshotError(category, 'bounded SQLite recovery did not complete', manifest, attempted=True)
            error.diagnostics['exception_class'] = type(exc).__name__
            for key in ('errno','winerror'):
                if type(getattr(exc,key,None)) is int: error.diagnostics[key] = getattr(exc,key)
            raise error from exc
        working = Path(path).parent/'sqlite-working'/'History'
        if (result.get('contract') != 'sqlite-recovery-v1' or result.get('original_manifest') != manifest
                or digest(working) != result.get('derived', {}).get('sha256')):
            fail('derived_validation_failed', 'recovery result identity could not be verified', manifest)
        regular(working)
        result.update(acquisition_reference=reference, source_path=str(source_path), worker_cleanup='confirmed',
                      original_file_identities=identities, source_context=source_context or {})
        event.update(transformation=result)
    return working, result


def release(working, recovery):
    """Remove only fixed derived names before publication; audit failure blocks it."""
    from forensic_assistant import activity
    from forensic_assistant.investigation_ai.lifecycle import CleanupError
    working = local_path(Path(working).absolute())
    if working.name != 'History' or working.parent.name != 'sqlite-working':
        raise CleanupError('Unexpected SQLite working directory')
    root = working.parent
    try:
        with DirectoryGuard(root):
            if digest(working) != recovery['derived']['sha256']:
                raise ValueError('Derived SQLite identity changed after extraction')
            for item in root.iterdir():
                if item.name not in ('History', 'History-journal', 'History-wal', 'History-shm'):
                    raise ValueError('Unexpected derived SQLite file')
                regular(item); item.unlink()
        root.rmdir()
    except (ValueError, OSError) as exc:
        raise CleanupError('SQLite derived-file cleanup unconfirmed') from exc
    activity.event('SQLITE_RECOVERY_CLEANUP', required=True,
                   acquisition_reference=recovery['acquisition_reference'], outcome='success', cleanup='confirmed')

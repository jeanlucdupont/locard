"""Audited main-file-only extraction preparation. Never SQLite recovery."""
from contextlib import closing, ExitStack
from pathlib import Path
import shutil
import sqlite3
import time
import uuid

from . import sqlite_recovery as safe
from .browser_journal import SnapshotError
from forensic_assistant.investigation_ai.snapshot import SnapshotFile, _private_mkdir
from forensic_assistant.investigation_ai.storage import DirectoryGuard

MODE = 'best_effort_immutable'
LIMITATIONS = [
    'Records were extracted from the main database without applying journal or WAL transactions.',
    'Transactional consistency, acquisition atomicity and complete browsing coverage are not established.',
]


def connection(path):
    if sqlite3.sqlite_version_info < (3, 22, 0):
        raise ValueError('SQLite immutable support is unavailable')
    db = sqlite3.connect(Path(path).absolute().as_uri() + '?mode=ro&immutable=1', uri=True, timeout=.2)
    try:
        db.row_factory = sqlite3.Row
        db.enable_load_extension(False)
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA query_only=ON')
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16*1024*1024)
        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 65536)
        return db
    except BaseException:
        db.close()
        raise


def prepare_worker(path, control, options):
    manifest = options['manifest']
    raw = safe.head(path, 100)
    page = int.from_bytes(raw[16:18], 'big'); page = 65536 if page == 1 else page
    size = manifest['']['size']
    if (len(raw) != 100 or raw[:16] != b'SQLite format 3\0' or page < 512 or page > 65536
            or page & (page-1) or size < page or size % page or raw[18:20] not in (b'\1\1', b'\2\2')):
        raise SnapshotError('sqlite_validation_failed', 'main database header or page alignment is invalid; immutable extraction refused', manifest)
    total = sum(x['size'] for x in manifest.values()) + size
    if total > safe.MAX_BYTES or shutil.disk_usage(Path(path).parent).free < size + 64*1024**2:
        raise SnapshotError('resource_limit', 'insufficient immutable extraction staging capacity', manifest)
    safe.regular(path)
    root = Path(control).parent / 'sqlite-immutable'
    _private_mkdir(root)
    with DirectoryGuard(root):
        working = root/'History'
        with open(path,'rb') as source, working.open('xb') as target:
            shutil.copyfileobj(source,target,1024*1024)
        if safe.digest(working) != manifest['']['sha256'] or safe.digest(path) != manifest['']['sha256']:
            raise SnapshotError('inconsistent_acquisition', 'immutable copy hash mismatch', manifest)
        with closing(connection(working)) as db:
            deadline = time.monotonic()+10
            db.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
            try:
                check = db.execute('PRAGMA quick_check(1)').fetchone()
                assessment = dict(quick_check='passed' if check and check[0]=='ok' else 'failed', integrity_check='not_performed')
            except sqlite3.Error as exc:
                assessment = dict(quick_check='incomplete' if time.monotonic()>=deadline else 'failed',
                                  integrity_check='not_performed', sqlite_errorcode=getattr(exc,'sqlite_errorcode',None))
        return dict(contract='browser-extraction-v1', mode=MODE, recovery_applied=False,
                    transactional_consistency='not_established', acquisition_consistency='not_established',
                    original_manifest=manifest, derived=dict(sha256=safe.digest(working),size=size),
                    sqlite_version=sqlite3.sqlite_version, validation=assessment,
                    header=dict(page_size=page,declared_pages=int.from_bytes(raw[28:32],'big'),physical_pages=size//page),
                    limitations=list(LIMITATIONS), tables={}, counts={}, started_utc=options['started_utc'],
                    prepared_utc=safe.stamp())


def prepare(path, manifest, source_path, identities, source_context, refusal):
    from forensic_assistant import activity
    from .ingest import worker
    if activity.CURRENT.get() is None:
        raise SnapshotError(refusal['category'], refusal['reason'] + '; best-effort extraction requires a bound mandatory audit session', manifest)
    reference = uuid.uuid4().hex
    with activity.mutation('SQLITE_IMMUTABLE_PREPARE', acquisition_reference=reference,
                           original_manifest=manifest, source_path=str(source_path), source_context=source_context or {},
                           mode=MODE, normal_refusal=refusal) as event:
        with ExitStack() as stack:
            stack.enter_context(DirectoryGuard(Path(path).parent))
            for suffix in ('','-journal','-wal'):
                if suffix in manifest:
                    pinned=SnapshotFile(str(path)+suffix); stack.callback(pinned.close)
            result=worker('sqlite_immutable',str(path),manifest['']['sha256'],Path(path).parent/'immutable-control',
                          dict(manifest=manifest,started_utc=safe.stamp()),safe.TIMEOUT)
        working=Path(path).parent/'sqlite-immutable'/'History'
        safe.regular(working)
        if result.get('contract')!='browser-extraction-v1' or result.get('derived')!=manifest[''] or safe.digest(working)!=manifest['']['sha256']:
            raise SnapshotError('derived_validation_failed','immutable copy identity could not be verified',manifest)
        result.update(acquisition_reference=reference,source_path=str(source_path),source_context=source_context or {},
                      original_file_identities=identities,journal_classification=refusal['category'],normal_refusal=refusal)
        result['limitations'].insert(0,'Normal snapshot processing refused: '+refusal['reason']+'.')
        if result['header']['declared_pages']!=result['header']['physical_pages']:
            result['limitations'].append('Declared and physical database page counts differ; trailing pages are not carved.')
        if result['validation']['quick_check']!='passed':
            result['limitations'].append('SQLite quick_check did not pass; independently readable records only.')
        event['extraction']=result
    return working,result


def release(path, extraction):
    from forensic_assistant import activity
    from forensic_assistant.investigation_ai.lifecycle import CleanupError
    path=safe.local_path(Path(path).absolute())
    try:
        if path.name!='History' or path.parent.name!='sqlite-immutable':
            raise ValueError('Unexpected immutable staging path')
        with DirectoryGuard(path.parent):
            if list(path.parent.iterdir())!=[path] or safe.digest(path)!=extraction['derived']['sha256']:
                raise ValueError('Immutable working set changed')
            safe.regular(path); path.unlink()
        path.parent.rmdir()
    except (ValueError,OSError) as exc:
        raise CleanupError('Immutable extraction cleanup or identity unconfirmed') from exc
    activity.event('SQLITE_IMMUTABLE_CLEANUP',required=True,acquisition_reference=extraction['acquisition_reference'],cleanup='confirmed')


def extract(runner, path, sha, stage, options, timeout):
    """Persist extraction decision and cleanup before the caller may publish."""
    from forensic_assistant import activity
    proof=options['extraction']
    with activity.mutation('SQLITE_IMMUTABLE_EXTRACT',extraction=proof) as event:
        try:
            with ExitStack() as guards:
                guards.enter_context(DirectoryGuard(Path(path).parent))
                pinned=SnapshotFile(path);guards.callback(pinned.close)
                result=runner('browser',path,sha,stage,options,timeout)
            result['extraction']['counts']['staged']=result['records']
            result['extraction']['counts']['errors']=result['errors']
            if result['errors']: result['extraction']['empty_readable']=False
            event['extraction']=result['extraction']
            if result['errors']: event['_outcome']='failure'
        finally:
            release(path,proof)
    return result

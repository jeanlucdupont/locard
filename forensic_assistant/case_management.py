"""Local case names and evidence-only SQLite snapshots; no AI or history rebinding."""
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import time
import uuid

from .interactive.state import state_path
from .interactive.case import validate, check_structure, expected_schema
from .investigation_ai.storage import local_path, DirectoryGuard

MAX_CASES = 1000
MAX_CONFIG = 256 * 1024


def name(value):
    if not isinstance(value, str) or not value or len(value) > 100 or value in ('.', '..') or not any(c.isalnum() for c in value):
        raise ValueError('CASE_NAME_INVALID: use one nonempty directory name, at most 100 characters')
    if value.endswith((' ', '.')) or value.startswith('.') or any(c in '<>:"/\\|?*' or ord(c) < 32 for c in value):
        raise ValueError('CASE_NAME_INVALID: paths, reserved characters and trailing spaces/periods are forbidden')
    if re.fullmatch(r'CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]', value.split('.')[0], re.I):
        raise ValueError('CASE_NAME_INVALID: reserved Windows device name')
    return value


def config_path():
    return local_path(state_path().parent / 'case-workspaces.json')


def default_root():
    return local_path(Path(os.environ.get('USERPROFILE') or Path.home()) / 'Locard' / 'Cases')


def preferences():
    p = config_path()
    try:
        with p.open('rb') as f:
            raw = f.read(MAX_CONFIG + 1)
    except FileNotFoundError:
        return {'format': 1, 'root': str(default_root()), 'registered': {}}
    if len(raw) > MAX_CONFIG:
        raise ValueError('CASE_CONFIG_INVALID: size limit exceeded; original preserved')
    from .reporting.model import loads
    value = loads(raw)
    if (type(value) is not dict or set(value) != {'format', 'root', 'registered'} or value['format'] != 1
            or not isinstance(value['root'], str) or not Path(value['root']).is_absolute()
            or type(value['registered']) is not dict or len(value['registered']) > MAX_CASES):
        raise ValueError('CASE_CONFIG_INVALID: unsupported configuration; original preserved')
    seen = set()
    for label, entry in value['registered'].items():
        key = name(label).casefold()
        if (key in seen or type(entry) is not dict or set(entry) != {'path','device','inode'}
                or not isinstance(entry['path'], str) or not Path(entry['path']).is_absolute()
                or type(entry['device']) is not int or type(entry['inode']) is not int):
            raise ValueError('CASE_CONFIG_INVALID: invalid registration')
        seen.add(key)
    return value


@contextmanager
def _configuration():
    p = config_path()
    with DirectoryGuard(p.parent, create=True):
        lock = p.with_suffix('.lock')
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise ValueError('CASE_CONFIG_BUSY: configuration lock exists; review interrupted work before retrying') from None
        os.close(fd)
        try:
            value = preferences()
            yield value
            raw = json.dumps(value, ensure_ascii=True, indent=2).encode()
            if len(raw) > MAX_CONFIG:
                raise ValueError('CASE_CONFIG_INVALID: size limit exceeded')
            fd, temporary = tempfile.mkstemp(prefix='.case-config-', dir=p.parent)
            try:
                with os.fdopen(fd, 'wb') as f:
                    f.write(raw); f.flush(); os.fsync(f.fileno())
                local_path(p)
                os.replace(temporary, p)
            finally:
                Path(temporary).unlink(missing_ok=True)
        finally:
            lock.unlink()


def root():
    return local_path(preferences()['root'])


def set_root(path):
    if not Path(path).is_absolute():
        raise ValueError('CASE_ROOT_INVALID: supply an absolute local directory')
    p = local_path(path)
    if p == Path(p.anchor) or p == config_path().parent or config_path().parent.is_relative_to(p):
        raise ValueError('CASE_ROOT_INVALID: choose a dedicated cases directory')
    if any((ancestor / 'case.db').is_file() for ancestor in (p, *p.parents)):
        raise ValueError('CASE_ROOT_INVALID: root must not be inside a case workspace')
    with DirectoryGuard(p, create=True):
        with tempfile.TemporaryFile(dir=p):
            pass
        with _configuration() as value:
            value['root'] = str(p)
    return p


def discover():
    """Bounded directory listing only. No SQLite opens, fingerprints or sidecar replay."""
    config = preferences()
    roots = [(Path(config['root']), 'configured'), (state_path().parent / 'cases', 'legacy')]
    entries, seen = [], set()
    for directory, kind in roots:
        directory = local_path(directory)
        if not directory.exists():
            continue
        for index, folder in enumerate(directory.iterdir()):
            if index >= MAX_CASES:
                raise ValueError('CASE_DISCOVERY_LIMIT: too many directory entries; use an explicit path')
            if folder.name.startswith('.'):
                continue
            try:
                path = local_path(folder / 'case.db')
                if not path.is_file():
                    continue
            except (OSError, ValueError):
                continue  # Never follow redirected entries.
            key = os.path.normcase(str(path))
            if key not in seen:
                entries.append(dict(name=folder.name, path=str(path), origin=kind, status='discovered; not validated'))
                seen.add(key)
    for label, binding in config['registered'].items():
        path = binding['path']
        status = 'unavailable'
        try:
            if local_path(path).is_file():
                info = Path(path).stat()
                status = ('discovered; not validated' if (info.st_dev,info.st_ino)==(binding['device'],binding['inode'])
                          else 'identity changed; registration must be reviewed')
        except (OSError, ValueError):
            pass
        entries.append(dict(name=label, path=path, origin='registered', status=status))
    return sorted(entries, key=lambda e: (e['name'].casefold(), e['path'].casefold(), e['origin']))


def resolve(value, *, check_identity=True):
    if Path(value).is_absolute():
        p = local_path(value)
        if p.is_dir():
            p = p / 'case.db'
    else:
        label = name(value)
        rows = [e for e in discover() if e['name'].casefold() == label.casefold()]
        if any('identity changed' in e['status'] for e in rows):
            raise ValueError('CASE_IDENTITY_MISMATCH: registered database was replaced; review its original binding')
        matches = {e['path'] for e in rows}
        if not matches:
            raise ValueError('CASE_NOT_FOUND: ' + label)
        if len(matches) != 1:
            raise ValueError('CASE_NAME_AMBIGUOUS: use an explicit path:\n' + '\n'.join(sorted(matches)))
        p = Path(matches.pop())
    try:
        p = validate(local_path(p))
    except sqlite3.DatabaseError as exc:
        raise ValueError('CASE_DATABASE_INVALID: inaccessible or corrupted SQLite database; no repair attempted') from exc
    except OSError as exc:
        raise ValueError('CASE_INACCESSIBLE: database cannot be read; permissions unchanged') from exc
    if check_identity:
        validate_identity(p)
    return p


def validate_identity(path):
    """Validate existing path/file-bound briefing and assessment history without repair."""
    from .briefing_store import Store
    from .assessment_store import AssessmentStore
    Store(path).load()
    AssessmentStore(path).history()
    return path


def register(label, path):
    label = name(label)
    if not Path(path).is_absolute():
        raise ValueError('CASE_REGISTRATION_PATH: supply an absolute existing case location')
    target = resolve(str(Path(path)), check_identity=True)
    with _configuration() as value:
        if any(e['name'].casefold() == label.casefold() for e in discover()):
            raise ValueError('CASE_NAME_EXISTS: registration already exists')
        info=target.stat()
        value['registered'][label] = dict(path=str(target),device=info.st_dev,inode=info.st_ino)
    return target


def unregister(label):
    name(label)
    with _configuration() as value:
        matches = [k for k in value['registered'] if k.casefold() == label.casefold()]
        if not matches:
            raise ValueError('CASE_NOT_REGISTERED')
        del value['registered'][matches[0]]


def destination(label):
    label = name(label)
    directory = root()
    if directory.exists() and any(p.name.casefold() == label.casefold() for p in directory.iterdir()):
        raise ValueError('CASE_NAME_EXISTS: destination already exists')
    target = local_path(directory / label / 'case.db')
    if not target.is_relative_to(directory):
        raise ValueError('CASE_PATH_ESCAPE')
    return target


def create(label, *, expected_path=None):
    from .interactive.workspace import initialize, target as named_target
    target = named_target(label)
    if expected_path is not None and target != Path(expected_path):
        raise ValueError('CASE_DESTINATION_CHANGED: review the current root before creating')
    with DirectoryGuard(target.parent.parent, create=True):
        if named_target(label) != target:
            raise ValueError('CASE_DESTINATION_CHANGED')
        initialize(target)
    return validate(target)


def clone(source, label, *, seconds=3600, progress=None, expected_source=None, expected_destination=None):
    """Copy only known evidence tables via a pinned SQLite read transaction.

    Running ingestion at that snapshot is refused. Later source commits are not
    included. No sidecar, external artifact, AI decision or authorization is copied.
    """
    source = resolve(source, check_identity=False)
    target = destination(label)
    if expected_destination is not None and target != Path(expected_destination):
        raise ValueError('CASE_DESTINATION_CHANGED: confirm the current destination')
    if expected_source is not None and (source.stat().st_dev,source.stat().st_ino) != expected_source:
        raise ValueError('CASE_IDENTITY_CHANGED: confirm the current source')
    if target.parent.is_relative_to(source.parent) or source.is_relative_to(target.parent):
        raise ValueError('CASE_CLONE_OVERLAP')
    deadline = time.monotonic() + seconds
    identity = source.stat()
    if identity.st_nlink != 1:
        raise ValueError('CASE_IDENTITY_AMBIGUOUS: hard-linked source database')
    published = False
    owned = []
    with DirectoryGuard(source.parent), DirectoryGuard(target.parent.parent, create=True):
        destination(label)
        from .investigation_ai.snapshot import _private_mkdir
        _private_mkdir(target.parent)  # Exclusive private reservation; no case.db until publication.
        folder_identity = target.parent.stat()
        try:
            with DirectoryGuard(target.parent):
                with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True, timeout=.2)) as db:
                    db.execute('PRAGMA query_only=ON')
                    db.execute('PRAGMA trusted_schema=OFF')
                    db.enable_load_extension(False)
                    db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                    db.execute('BEGIN')
                    check_structure(db)
                    version = db.execute('PRAGMA user_version').fetchone()[0]
                    known = {n for n, _ in expected_schema(version)}
                    actual = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if actual != known:
                        raise ValueError('CASE_CLONE_SCHEMA: unknown tables; evidence/state separation is not established')
                    for table in ('ingestion_runs', 'ingestion_batches'):
                        if table in known and db.execute(f"SELECT 1 FROM {table} WHERE finished_utc IS NULL OR status IN ('running','started') LIMIT 1").fetchone():
                            raise ValueError('CASE_BUSY: unfinished ingestion; finish or investigate it before cloning')
                    if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)] or db.execute('PRAGMA foreign_key_check').fetchone():
                        raise ValueError('CASE_INTEGRITY_FAILURE: source database failed integrity checks')
                    size = db.execute('PRAGMA page_count').fetchone()[0] * db.execute('PRAGMA page_size').fetchone()[0]
                    if shutil.disk_usage(target.parent).free < size + max(size // 10, 16 * 1024 * 1024):
                        raise ValueError('CASE_STORAGE_INSUFFICIENT: clone requires database size plus safety margin')
                    staged = target.parent / '.clone.sqlite'
                    owned.append(staged)
                    def advance(status, remaining, total):
                        if time.monotonic() >= deadline:
                            raise TimeoutError('CASE_CLONE_TIMEOUT: source unchanged')
                        if progress:
                            progress(remaining, total)
                    with closing(sqlite3.connect(staged)) as copied:
                        db.backup(copied, pages=1024, progress=advance, sleep=.05)
                        copied.execute('PRAGMA journal_mode=DELETE')
                        check_structure(copied)
                        if copied.execute('PRAGMA integrity_check').fetchall() != [('ok',)] or copied.execute('PRAGMA foreign_key_check').fetchone():
                            raise ValueError('CASE_CLONE_INTEGRITY_FAILURE')
                    references = db.execute('SELECT source_file FROM source_locations ORDER BY source_file LIMIT 21').fetchall()
                    origin = dict(format=1, clone_id=uuid.uuid4().hex, created=datetime.now(timezone.utc).isoformat(),
                        source=dict(path=str(source), device=identity.st_dev, inode=identity.st_ino),
                        schema=version, snapshot_bytes=size, external_evidence_copied=False,
                        source_reference_sample=[r[0] for r in references[:20]], references_truncated=len(references)>20,
                        meaning='Copied normalized evidence and ingestion/source provenance; fresh investigative context. External references retain original locations.')
                final_source = local_path(source).stat()
                if (final_source.st_dev, final_source.st_ino) != (identity.st_dev, identity.st_ino):
                    raise ValueError('CASE_IDENTITY_CHANGED: source replaced during clone')
                marker = target.parent / 'clone-origin.json'
                owned.append(marker)
                with marker.open('x', encoding='utf-8') as f:
                    json.dump(origin, f, ensure_ascii=True, indent=2); f.flush(); os.fsync(f.fileno())
                validate(staged)
                with staged.open('r+b') as f:
                    os.fsync(f.fileno())
                info = local_path(target.parent).stat()
                if (info.st_dev, info.st_ino) != (folder_identity.st_dev, folder_identity.st_ino):
                    raise ValueError('CASE_DESTINATION_CHANGED')
                # Atomic no-overwrite file publication; metadata is already durable.
                os.link(staged, target)
                published = True
                staged.unlink()
                validate(target)
                return dict(path=str(target), origin=origin)
        finally:
            if not published:
                info = local_path(target.parent).stat()
                if (info.st_dev, info.st_ino) == (folder_identity.st_dev, folder_identity.st_ino):
                    for p in owned:
                        local_path(p).unlink(missing_ok=True)
                    # Never recursively remove an unexpected/rival file.
                    try:
                        target.parent.rmdir()
                    except OSError:
                        import warnings
                        warnings.warn('CASE_CLONE_CLEANUP_LIMITATION: reserved destination contains unexpected files; retained for review', RuntimeWarning)

"""Existing-case-only access, independent of the database creation API."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import time
from .diagnostics import measure


def open_readonly(path, deadline=None, profile=None, *, _transaction_guard=None):
    with measure(profile, 'database_open'):
        path = Path(path).resolve(strict=True)
        if not path.is_file():
            raise ValueError('Case must be an existing SQLite file')
        db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=.2)
    db.row_factory = sqlite3.Row
    try:
        with measure(profile, 'schema_validation'):
            if db.execute('PRAGMA user_version').fetchone()[0] not in (3, 4, 5):
                raise ValueError('An existing schema-3, schema-4 or schema-5 case is required')
            db.execute('PRAGMA query_only=ON')
            db.execute('PRAGMA trusted_schema=OFF')
            db.enable_load_extension(False)
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2 * 1024 * 1024)
            db.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
            db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 65536)
            allowed = {
                sqlite3.SQLITE_SELECT,
                sqlite3.SQLITE_READ,
                sqlite3.SQLITE_FUNCTION,
                sqlite3.SQLITE_TRANSACTION,
                sqlite3.SQLITE_SAVEPOINT,
                sqlite3.SQLITE_RECURSIVE
            }
            def authorize(action, a, b, database, source):
                if action == sqlite3.SQLITE_TRANSACTION and _transaction_guard and _transaction_guard['locked']:
                    return sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_FUNCTION and (b or a or '').lower() in ('load_extension', 'writefile', 'readfile'):
                    return sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_PRAGMA:
                    if a.lower() in (
                        'user_version',
                        'table_info',
                        'database_list'
                    ) and (b is None or a.lower() == 'table_info'):
                        return sqlite3.SQLITE_OK
                    return sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_READ and database not in ('main', None):
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY
            db.set_authorizer(authorize)
            if deadline is not None:
                db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        return db
    except BaseException:
        db.close()
        raise


@contextmanager
def read_transaction(db):
    db.execute('BEGIN')
    try:
        yield db
    finally:
        db.rollback()


class ReadView:
    """Worker-owned pinned read transaction; never a physical database copy."""
    def __init__(self, path, deadline, profile=None):
        self.path = Path(path).resolve(strict=True)
        info = self.path.stat()
        self.identity = (info.st_dev, info.st_ino)
        self.guard = {'locked': False}
        self.db = None
        self.active = False
        self.fingerprint = None
        try:
            self.db = open_readonly(self.path, deadline, profile, _transaction_guard=self.guard)
            with measure(profile, 'read_transaction'):
                self.db.execute('BEGIN')
                # BEGIN is deferred: this first read establishes the actual view.
                self.db.execute('SELECT name FROM sqlite_master LIMIT 1').fetchone()
                self.guard['locked'] = True
                self.active = True
                self.check_identity()
        except BaseException:
            self.close()
            raise

    def check_identity(self):
        try:
            info = self.path.stat()
        except OSError:
            raise ValueError('EVIDENCE_STATE_CHANGED: case path unavailable') from None
        if (info.st_dev, info.st_ino) != self.identity:
            raise ValueError('EVIDENCE_STATE_CHANGED: case file identity changed')

    def deadline(self, value):
        self.db.set_progress_handler(lambda: int(time.monotonic() >= value), 1000)

    def close(self):
        self.active = False
        self.guard['locked'] = False
        if self.db is not None:
            db, self.db = self.db, None
            try:
                db.set_progress_handler(None, 0)
                db.rollback()
            finally:
                db.close()


class ReadViewFingerprint:
    """Full logical hash valid only in this locked transaction/connection lifetime."""
    def __init__(self, view):
        self.view = view
        if not view.active or not view.db.in_transaction or view.fingerprint is None:
            raise ValueError('Read view fingerprint is unavailable')

    def value(self, db):
        view = self.view
        if not view.active or db is not view.db or not db.in_transaction or not view.guard['locked']:
            raise ValueError('Read view fingerprint is outside its transaction')
        view.check_identity()
        return view.fingerprint

"""Existing-case-only access, independent of the database creation/migration API."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import time


def open_readonly(path,deadline=None):
    path=Path(path).resolve(strict=True)
    if not path.is_file():raise ValueError('Case must be an existing SQLite file')
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.2)
    db.row_factory=sqlite3.Row
    try:
        if db.execute('PRAGMA user_version').fetchone()[0]!=3:
            raise ValueError('V4 requires an existing schema-3 case')
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        db.enable_load_extension(False)
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,2*1024*1024)
        db.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED,0)
        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH,65536)
        allowed={sqlite3.SQLITE_SELECT,sqlite3.SQLITE_READ,sqlite3.SQLITE_FUNCTION,
                 sqlite3.SQLITE_TRANSACTION,sqlite3.SQLITE_SAVEPOINT,sqlite3.SQLITE_RECURSIVE}
        def authorize(action,a,b,database,source):
            if action==sqlite3.SQLITE_FUNCTION and (b or a or '').lower() in ('load_extension','writefile','readfile'):
                return sqlite3.SQLITE_DENY
            if action==sqlite3.SQLITE_PRAGMA:
                if a.lower() in ('user_version','table_info','database_list') and (b is None or a.lower()=='table_info'):
                    return sqlite3.SQLITE_OK
                return sqlite3.SQLITE_DENY
            if action==sqlite3.SQLITE_READ and database not in ('main',None):return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY
        db.set_authorizer(authorize)
        if deadline is not None:db.set_progress_handler(lambda:int(time.monotonic()>=deadline),1000)
        return db
    except BaseException:
        db.close();raise


@contextmanager
def read_transaction(db):
    db.execute('BEGIN')
    try:yield db
    finally:db.rollback()

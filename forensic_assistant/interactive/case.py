"""Existing-case selection: no creation, evidence scans, or migration."""
from contextlib import closing
from functools import lru_cache
from pathlib import Path
import sqlite3
import time
from forensic_assistant.reporting.transcripts import safe_path


def normalize(path):
    if not isinstance(path, (str, Path)) or not str(path).strip():
        raise ValueError('Enter an existing database path')
    if '\x00' in str(path):
        raise ValueError('Invalid database path')
    target = safe_path(Path(path).absolute())
    if not target.is_file():
        raise ValueError('Case must be an existing regular database file')
    return target.resolve(strict=True)


@lru_cache(maxsize=1)
def expected_schema():
    # Cache only trusted application schema metadata, never case data.
    from forensic_assistant.database.db import connect
    with closing(connect(':memory:')) as reference:
        names = [r[0] for r in reference.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        return tuple((name, tuple(tuple(row)[1:] for row in reference.execute(f'PRAGMA table_info("{name}")')))
                     for name in names)


def check_structure(db):
    if db.execute('PRAGMA user_version').fetchone()[0] != 3:
        raise ValueError('An existing schema-3 Locard database is required')
    if db.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1").fetchone():
        raise ValueError('Unexpected executable schema objects in case')
    for name, columns in expected_schema():
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone():
            raise ValueError('Incomplete Locard database structure')
        actual = tuple(tuple(row)[1:] for row in db.execute(f'PRAGMA table_info("{name}")'))
        if actual != columns:
            raise ValueError('Unsupported Locard table structure: ' + name)


def validate(path):
    target = normalize(path)
    from forensic_assistant.investigation_ai.case import open_readonly
    with closing(open_readonly(target, deadline=time.monotonic()+3)) as db:
        check_structure(db)
    return target


def open_existing(path):
    target = normalize(path)
    # mode=rw closes the missing-file race without changing scripted CLI behavior.
    db = sqlite3.connect(target.as_uri()+'?mode=rw', uri=True, timeout=.2)
    try:
        db.row_factory = sqlite3.Row
        db.enable_load_extension(False)
        db.execute('PRAGMA trusted_schema=OFF')
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        deadline = time.monotonic()+3
        check_structure(db)
        db.set_progress_handler(None, 0)
        db.execute('PRAGMA foreign_keys=ON')
        return db
    except BaseException:
        db.close()
        raise

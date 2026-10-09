"""Read-only discovery on private copies, invoked only in the bounded worker."""
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
from .browser import copy_snapshot, schema_columns


def check(path, staging_directory):
    # The parent owns this tree and removes it even if this worker is killed.
    with tempfile.TemporaryDirectory(prefix='locard-browser-probe-', dir=staging_directory) as directory:
        copied = Path(directory) / 'History'
        # Acquisition/copy failures are not silently treated as unsupported schemas.
        copy_snapshot(path, copied)
        try:
            with closing(sqlite3.connect(copied.as_uri() + '?mode=ro', uri=True, timeout=.2)) as db:
                db.row_factory = sqlite3.Row
                db.enable_load_extension(False)
                db.execute('PRAGMA trusted_schema=OFF')
                db.execute('PRAGMA query_only=ON')
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16 * 1024 * 1024)
                db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 65536)
                schema_columns(db)
            return {'supported': True}
        except (ValueError, sqlite3.Error):
            return {'supported': False}

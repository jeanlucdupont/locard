"""Conservative validation of private Chromium SQLite copies; never recovery."""
from contextlib import closing
from pathlib import Path
import sqlite3
import struct
import time

MAGIC = bytes.fromhex('d9d505f920a163d7')
VALIDATION_SECONDS = 30


class SnapshotError(ValueError):
    def __init__(self, category, reason, manifest):
        super().__init__('Browser History requires a consistent acquisition; ' + reason + ' (no recovery performed)')
        self.diagnostics = dict(artifact='browser', category=category, recovery_performed=False,
                                companions=manifest)


def head(path, length):
    with Path(path).open('rb') as stream:
        return stream.read(length)


def validate(path, manifest):
    """Stable copies are necessary, not proof of historical acquisition coherence."""
    path = Path(path)
    def reject(category, reason):
        raise SnapshotError(category, reason, manifest)
    header = head(path, 100)
    if len(header) != 100 or header[:16] != b'SQLite format 3\0':
        reject('sqlite_validation_failed', 'invalid SQLite database header')
    page = int.from_bytes(header[16:18], 'big')
    page = 65536 if page == 1 else page
    if page < 512 or page > 65536 or page & (page - 1):
        reject('sqlite_validation_failed', 'invalid SQLite page size')
    mode = header[18:20]
    if mode not in (b'\1\1', b'\2\2'):
        reject('snapshot_consistency_not_established', 'unsupported database journal-mode header')
    wal = manifest.get('-wal', {}).get('size', 0)
    journal = manifest.get('-journal')
    state = 'absent' if journal is None else 'empty'
    if journal and journal['size']:
        raw = head(str(path) + '-journal', 28)
        if len(raw) != 28:
            reject('journal_incomplete', 'rollback journal header is incomplete')
        if raw[:8] == MAGIC:
            sector = int.from_bytes(raw[20:24], 'big')
            journal_page = int.from_bytes(raw[24:28], 'big')
            if sector < 512 or sector > 65536 or sector & (sector - 1) or journal_page != page:
                reject('journal_malformed', 'rollback journal geometry does not match the database')
            if journal['size'] < sector:
                reject('journal_incomplete', 'rollback journal sector is incomplete')
            # Original locks and super-journal state are not acquired. Do not
            # claim that every valid header proves a hot journal or roll it back.
            reject('journal_active_or_hot', 'active rollback journal requires recovery or a consistent acquisition')
        if raw != bytes(28):
            if raw[:8] == bytes(8):
                reject('journal_indeterminate', 'rollback journal may be an unfinished pre-sync transaction')
            reject('journal_malformed', 'rollback journal header is neither valid nor canonically inactive')
        if journal['size'] <= 512:
            reject('journal_indeterminate', 'rollback-journal state could not be validated')
        if mode != b'\1\1' or wal:
            reject('snapshot_consistency_not_established', 'rollback journal and WAL-mode state conflict')
        state = 'inactive'
    if wal:
        raw = head(str(path) + '-wal', 32)
        if (mode != b'\2\2' or len(raw) != 32 or
                int.from_bytes(raw[:4], 'big') not in (0x377f0682, 0x377f0683) or
                int.from_bytes(raw[4:8], 'big') != 3007000 or
                int.from_bytes(raw[8:12], 'big') != page or (wal - 32) % (page + 24)):
            reject('snapshot_consistency_not_established', 'WAL header or frame geometry is invalid')
        words = struct.unpack(('<' if raw[3] == 0x82 else '>') + '6I', raw[:24])
        first = second = 0
        for index in range(0, 6, 2):
            first = (first + words[index] + second) & 0xffffffff
            second = (second + words[index + 1] + first) & 0xffffffff
        if (first, second) != struct.unpack('>2I', raw[24:32]):
            reject('snapshot_consistency_not_established', 'WAL header checksum is invalid')
    elif mode == b'\2\2' and manifest.get('-shm', {}).get('size'):
        reject('missing_required_companion', 'WAL-mode SHM is present without a nonempty WAL')
    if not wal:
        # Modern, self-consistent main-file header is required for accepting a
        # PERSIST journal, not merely a zero journal prefix or integrity_check.
        pages = int.from_bytes(header[28:32], 'big')
        if state == 'inactive' and (header[24:28] != header[92:96] or
                                   pages == 0 or pages * page != manifest['']['size']):
            reject('snapshot_consistency_not_established', 'database size/change counters do not establish an inactive-journal snapshot')
    started = time.monotonic()
    try:
        with closing(sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True, timeout=.2)) as db:
            db.enable_load_extension(False)
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA query_only=ON')
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16 * 1024 * 1024)
            db.set_progress_handler(lambda: time.monotonic() - started >= VALIDATION_SECONDS, 1000)
            if db.execute('PRAGMA integrity_check(1)').fetchone() != ('ok',):
                reject('sqlite_validation_failed', 'SQLite integrity validation failed')
    except sqlite3.Error:
        reject('sqlite_validation_failed', 'read-only SQLite validation failed or exceeded its time budget')
    return dict(rollback_journal=state, validation='read_only_integrity_check', recovery_performed=False,
                acquisition_limitation='Stable acquired bytes do not independently prove historical acquisition coherence.')

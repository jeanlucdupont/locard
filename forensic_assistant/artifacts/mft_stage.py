"""Bounded timestamp/object writes for the private MFT stage only.

Completed parser outcomes commit every 20,000 entries, including errors and
duplicates. Cancellation can therefore discard more uncommitted stage work
than the former 500-entry cadence. The final record tail and reconstruction
still share the final transaction; no stage is published after worker failure.
"""
import sys

BATCH_ROWS = 2000
BUFFER_BYTES = 4 * 1024 * 1024
TRANSACTION_ENTRIES = 20000
_BATCH_SQL = frozenset({
    'INSERT INTO evidence_timestamps VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING',
    'INSERT INTO evidence_objects VALUES (?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING',
})


class MftStage:
    """Keep dependency-sensitive writes immediate; never emulate cursor counts."""
    def __init__(self, db):
        self.db = db
        self.pending = {}
        self.rows = self.bytes = 0
        self.peak_rows = self.peak_bytes = 0
        self.failed = False

    def execute(self, sql, parameters=()):
        if self.failed:
            raise RuntimeError('MFT staging writer cannot continue after a write failure')
        if sql not in _BATCH_SQL:
            return self.db.execute(sql, parameters)
        row = tuple(parameters)
        # Count referenced values conservatively, including shared strings. The
        # row limit separately bounds list/dictionary overhead. Oversize rows
        # bypass the buffer without weakening the worker's record/memory limits.
        size = sys.getsizeof(row) + sum(map(sys.getsizeof, row))
        if self.rows and (self.rows >= BATCH_ROWS or self.bytes + size > BUFFER_BYTES):
            self.flush()
        if size > BUFFER_BYTES:
            self.flush()
            try:
                return self.db.execute(sql, row)
            except BaseException:
                self.failed = True
                raise
        self.pending.setdefault(sql, []).append(row)
        self.rows += 1
        self.bytes += size
        self.peak_rows = max(self.peak_rows, self.rows)
        self.peak_bytes = max(self.peak_bytes, self.bytes)
        if self.rows == BATCH_ROWS:
            self.flush()

    def flush(self):
        if self.failed:
            raise RuntimeError('MFT staging writer cannot continue after a write failure')
        try:
            for sql, rows in self.pending.items():
                self.db.executemany(sql, rows)
        except BaseException:
            self.failed = True
            raise
        finally:
            # A failed executemany may have written a prefix. Never replay it:
            # worker failure closes/rolls back the transaction, without publish.
            self.discard()

    def discard(self):
        self.pending.clear()
        self.rows = self.bytes = 0

    def commit(self):
        self.flush()
        try:
            self.db.commit()
        except BaseException:
            self.failed = True
            raise

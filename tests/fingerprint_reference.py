"""6.63 fingerprint byte-stream oracle; deliberately unchanged for equivalence tests."""
import hashlib
def fingerprint(db):
    """Hash every authoritative table/cell in bounded pieces, including raw bytes.

    Deliberately conservative: run/provenance-only changes also invalidate an index.
    Physical row ordering changes may invalidate it even with equivalent content.
    Caller holds a consistent SQLite snapshot. No file-stat/WAL assumptions.
    """
    h = hashlib.sha256()
    def feed(value):
        value = value if isinstance(value, bytes) else str(value).encode('utf-8')
        h.update(len(value).to_bytes(8, 'little'))
        h.update(value)
    def quoted(name):
        return '"' + name.replace('"', '""') + '"'
    feed(db.execute('PRAGMA user_version').fetchone()[0])
    tables = db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    for name, ddl in tables:
        feed(name)
        feed(ddl)
        cols = [r[1] for r in db.execute('PRAGMA table_info(' + quoted(name) + ')')]
        expressions = []
        for col in cols:
            col = quoted(col)
            expressions += [f'typeof({col})', f'length(CAST({col} AS BLOB))', f'substr(CAST({col} AS BLOB),1,65536)']
        for row in db.execute('SELECT rowid,' + ','.join(expressions) + ' FROM ' + quoted(name) + ' ORDER BY rowid'):
            feed('row')
            for i, col in enumerate(cols):
                kind, size, value = row[1 + i * 3:4 + i * 3]
                feed(kind)
                feed(size)
                feed(value or b'')
                for offset in range(65536, size or 0, 65536):
                    value = db.execute(
                        'SELECT substr(CAST(' + quoted(col) + ' AS BLOB),?,65536) FROM ' + quoted(name) + ' WHERE rowid=?',
                        (offset + 1, row[0])
                    ).fetchone()[0]
                    feed(value)
    return h.hexdigest()


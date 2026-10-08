"""Synthetic empty historical schemas for read-compatibility tests."""
from pathlib import Path
import sqlite3
from forensic_assistant.database import db as database, context, artifacts, sources


def legacy(path, version=3):
    assert version in (3, 4)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript(Path(database.__file__).with_name('schema.sql').read_text())
    with db:
        definitions = (context.DDL, artifacts.DDL)
        if version == 4:
            definitions += (sources.DDL,)
        for statements in definitions:
            for statement in statements:
                db.execute(statement)
        db.execute(f'PRAGMA user_version={version}')
    return db

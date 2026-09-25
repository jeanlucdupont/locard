import sqlite3
import pytest
from forensic_assistant.database.db import connect
from forensic_assistant.database import artifacts, migrations
from test_v1_migration import old_database


def v1(path):
    original=old_database(path)
    db=sqlite3.connect(path);db.row_factory=sqlite3.Row
    with db: migrations.upgrade(db)
    context=dict(db.execute('SELECT * FROM event_context').fetchone());db.close()
    return original,context


def test_v1_to_v2_preserves_evidence(tmp_path):
    path=tmp_path/'case.db';original,context=v1(path)
    with pytest.raises(ValueError,match='Unsupported legacy database schema'):connect(path)
    result=migrations.migrate(path);db=connect(path)
    assert dict(db.execute('SELECT * FROM events').fetchone())==original
    assert dict(db.execute('SELECT * FROM event_context').fetchone())==context
    assert db.execute('SELECT evidence_id FROM evidence_records').fetchone()[0]==original['id']
    backup=sqlite3.connect(result['backup']);assert backup.execute('pragma user_version').fetchone()[0]==2
    backup.close();db.close()


def test_v2_rollback(tmp_path,monkeypatch):
    path=tmp_path/'case.db';v1(path)
    def fail(db):
        db.execute('CREATE TABLE broken(x)');raise ValueError('injected')
    monkeypatch.setattr(artifacts,'upgrade3',fail)
    with pytest.raises(ValueError,match='rolled back'):migrations.migrate(path)
    db=sqlite3.connect(path)
    assert db.execute('pragma user_version').fetchone()[0]==2
    assert not db.execute("SELECT name FROM sqlite_master WHERE name='broken'").fetchone()
    db.close()

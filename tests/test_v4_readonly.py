import sqlite3
import time
import pytest
from forensic_assistant.database.db import connect
from forensic_assistant.investigation_ai.case import open_readonly,read_transaction
from forensic_assistant.semantic.documents import fingerprint


@pytest.fixture
def case(tmp_path):
    p=tmp_path/'synthetic.db';db=connect(p);db.close();return p


@pytest.mark.parametrize('sql',[
 'CREATE TABLE forbidden(x)', 'DELETE FROM events', 'UPDATE events SET hostname=hostname',
 "ATTACH ':memory:' AS other", 'PRAGMA user_version=4', 'PRAGMA query_only=OFF',
 'PRAGMA writable_schema=ON', 'VACUUM', "SELECT load_extension('anything')",
 "CREATE TEMP TABLE forbidden(x)",
])
def test_sql_authorizer_denies_writes_and_escape(case,sql):
    db=open_readonly(case)
    with pytest.raises(sqlite3.DatabaseError):db.execute(sql)
    assert db.total_changes==0;db.close()


def test_readonly_fingerprint_and_snapshot(case):
    db=open_readonly(case)
    with read_transaction(db):assert len(fingerprint(db))==64
    assert not db.in_transaction;db.close()


def test_missing_database_is_not_created(tmp_path):
    p=tmp_path/'missing.db'
    with pytest.raises(FileNotFoundError):open_readonly(p)
    assert not p.exists()


def test_query_deadline_interrupts(case):
    db=open_readonly(case,time.monotonic()-1)
    with pytest.raises(sqlite3.OperationalError):
        db.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000000) SELECT sum(x) FROM n').fetchone()
    db.close()

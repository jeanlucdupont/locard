import json
from forensic_assistant.database.db import connect
from forensic_assistant.artifacts.ingest import ingest_artifact
from v2_fixtures import registry_file


def test_registry_binary_and_persistence(tmp_path):
    p=registry_file(tmp_path/'misleading.SYSTEM');before=p.read_bytes();db=connect(':memory:')
    result=ingest_artifact(db,p,'registry');assert result['status']=='complete',result
    assert db.execute('SELECT hive_type FROM registry_hives').fetchone()[0]=='NTUSER'
    value=db.execute("SELECT * FROM registry_values WHERE value_name='Binary'").fetchone()
    assert value['raw_data']==b'\x00\xff\x1b\x00'
    assert before[value['cell_offset']:value['cell_offset']+2]==b'vk'
    assert not db.execute('SELECT * FROM evidence_timestamps WHERE evidence_id=?',(value['evidence_id'],)).fetchone()
    assert db.execute("SELECT count(*) FROM registry_views WHERE category='persistence'").fetchone()[0]==2
    assert db.execute("SELECT normalized FROM evidence_objects WHERE role='persistence_target'").fetchone()[0]=='c:\\temp\\payload.exe'
    again=ingest_artifact(db,p,'registry');assert again['inserted']==0 and again['duplicates']>0
    assert p.read_bytes()==before


def test_dirty_and_truncated_hives(tmp_path):
    p=registry_file(tmp_path/'hive',dirty=True);db=connect(':memory:')
    assert ingest_artifact(db,p,'registry')['inserted']>0
    assert db.execute('SELECT dirty FROM registry_hives').fetchone()[0]==1
    p.write_bytes(b'regf'+bytes(10));result=ingest_artifact(db,p,'registry')
    assert result['errors']>0 and result['inserted']==0

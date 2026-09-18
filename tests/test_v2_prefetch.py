import pytest
from forensic_assistant.database.db import connect
from forensic_assistant.artifacts.ingest import ingest_artifact
from v2_fixtures import prefetch_file


@pytest.mark.parametrize('version',[17,23,26])
def test_prefetch_binary(tmp_path,version):
    p=prefetch_file(tmp_path/'x.pf',version=version);db=connect(':memory:')
    result=ingest_artifact(db,p,'prefetch');assert result['status']=='complete',result
    row=db.execute('SELECT * FROM prefetch_records').fetchone()
    assert row['run_count']==17 and row['raw_file']==p.read_bytes()
    assert db.execute('SELECT count(*) FROM evidence_timestamps WHERE timestamp_utc IS NOT NULL').fetchone()[0]==1
    assert ingest_artifact(db,p,'prefetch')['duplicates']==1


def test_prefetch_malformed(tmp_path):
    p=tmp_path/'bad.pf';p.write_bytes(b'MAM\x04'+(100_000_000).to_bytes(4,'little'))
    db=connect(':memory:');result=ingest_artifact(db,p,'prefetch')
    assert result['errors'] and result['inserted']==0

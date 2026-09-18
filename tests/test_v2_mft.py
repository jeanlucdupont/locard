import hashlib
import json
from forensic_assistant.database.db import connect
from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.artifacts.mft import parse
from v2_fixtures import mft_file,mft_record


def test_mft_binary_ingestion_and_duplicates(tmp_path):
    path=mft_file(tmp_path/'$MFT',names=('payload.exe','PAYLOA~1.EXE'),allocated=False)
    before=path.read_bytes();db=connect(':memory:')
    result=ingest_artifact(db,path,'mft',hostname='pc',volume_root='C:')
    assert result['status']=='complete',result
    assert result['inserted']==3
    row=db.execute('SELECT * FROM mft_records WHERE record_number=6').fetchone()
    assert row['allocated']==0 and row['raw_record']==mft_record(names=('payload.exe','PAYLOA~1.EXE'),allocated=False)
    assert db.execute('SELECT count(*) FROM mft_names WHERE evidence_id=?',(row['evidence_id'],)).fetchone()[0]==2
    stamps=[dict(r) for r in db.execute('SELECT * FROM evidence_timestamps WHERE evidence_id=?',(row['evidence_id'],))]
    assert len(stamps)==12 and len({s['source'].split()[1] for s in stamps})==2
    assert db.execute('SELECT reconstructed_path FROM mft_names WHERE evidence_id=? ORDER BY slot',(row['evidence_id'],)).fetchone()[0]=='\\payload.exe'
    copied=tmp_path/'copy';copied.write_bytes(before)
    again=ingest_artifact(db,copied,'mft')
    assert again['inserted']==0 and again['duplicates']==3
    assert db.execute('SELECT count(*) FROM source_locations').fetchone()[0]==2
    assert path.read_bytes()==before


def test_bad_record_and_parent_reuse(tmp_path):
    path=mft_file(tmp_path/'MFT',parent_sequence=99)
    path.write_bytes(path.read_bytes()+b'FILE'+bytes(50))
    db=connect(':memory:');result=ingest_artifact(db,path,'mft')
    assert result['status']=='partial' and result['errors']==1
    row=db.execute('SELECT path_status FROM mft_names WHERE filename=?',('payload.exe',)).fetchone()
    assert row[0]=='missing_or_reused_parent'


def test_integrity_change_rejects_stage(tmp_path):
    from forensic_assistant.artifacts.worker import run
    p=mft_file(tmp_path/'mft');db=connect(':memory:')
    def changed(kind,path,sha,stage,options,timeout):
        result=run(kind,path,sha,stage,options);p.write_bytes(p.read_bytes()+b'x');return result
    result=ingest_artifact(db,p,'mft',runner=changed)
    assert result['status']=='changed'
    assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]==0


def test_record_offsets_do_not_use_header_numbers(tmp_path):
    p=mft_file(tmp_path/'mft',number=999)
    sha=hashlib.sha256(p.read_bytes()).hexdigest();records=list(parse(p,sha))
    assert records[-1]['record']['evidence_id']==f'MFT:{sha}:Offset:6144'
    assert records[-1]['detail']['record_number']==6


def test_four_byte_terminator_near_record_end(tmp_path):
    import struct
    raw=bytearray(mft_record())
    end=struct.unpack_from('<I',raw,24)[0]-8
    length=1008-end
    struct.pack_into('<IIBBHHHIHBB',raw,end,128,length,0,0,0,0,8,length-24,24,0,0)
    struct.pack_into('<I',raw,1008,0xffffffff)
    struct.pack_into('<I',raw,24,1016)
    # Rebuild the update-sequence entries after changing sector contents.
    raw[50:52]=raw[510:512];raw[52:54]=raw[1022:1024]
    raw[510:512]=raw[1022:1024]=raw[48:50]
    p=tmp_path/'mft';p.write_bytes(raw)
    records=list(parse(p,hashlib.sha256(raw).hexdigest()))
    assert len(records)==1 and 'error' not in records[0]

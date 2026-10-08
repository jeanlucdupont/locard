"""Generated EVTX framing with controlled XML decoding; no real evidence fixtures."""
import binascii
import json
import struct

import pytest

from forensic_assistant.ingest import evtx_recovery as recovery
from forensic_assistant.ingest.evtx import ingest_file, records
from forensic_assistant.database.db import connect
from forensic_assistant.retrieval.status_display import error_details
from test_ingest import xml


def chunk(numbers, *, bad_checksum=False, bad_record=False):
    data = bytearray(65536)
    data[:8] = b'ElfChnk\0'
    for offset, number in zip((8, 16, 24, 32), (numbers[0], numbers[-1], numbers[0], numbers[-1])):
        struct.pack_into('<Q', data, offset, number)
    struct.pack_into('<III', data, 40, 128, 512 + 32 * (len(numbers) - 1), 512 + 32 * len(numbers))
    for index, number in enumerate(numbers):
        offset = 512 + 32 * index
        struct.pack_into('<IIQ', data, offset, 0x2a2a, 32, number)
        struct.pack_into('<I', data, offset + 28, 32)
    if bad_record:
        struct.pack_into('<I', data, 512, 0)
    struct.pack_into('<I', data, 52, binascii.crc32(data[512:512 + 32 * len(numbers)]) ^ int(bad_checksum))
    struct.pack_into('<I', data, 124, binascii.crc32(data[:120] + data[128:512]))
    return data


def file_bytes(chunks, *, declared=None, dirty=False, minor=1):
    header = bytearray(4096)
    header[:8] = b'ElfFile\0'
    declared = len(chunks) if declared is None else declared
    struct.pack_into('<QQQ', header, 8, 0, max(0, declared - 1), 100)
    struct.pack_into('<IHHHH', header, 32, 128, minor, 3, 4096, declared)
    struct.pack_into('<I', header, 120, int(dirty))
    struct.pack_into('<I', header, 124, binascii.crc32(header[:120]))
    return header + b''.join(chunks)


@pytest.fixture
def decode(monkeypatch):
    monkeypatch.setattr(recovery.Record, 'xml', lambda r: xml(record_id=r.record_num()))


def test_bad_chunk_then_valid_chunk_and_repeat(tmp_path, decode):
    path = tmp_path/'synthetic.evtx'
    path.write_bytes(file_bytes([chunk([1]), chunk([2], bad_checksum=True), chunk([3,4])]))
    db = connect(':memory:')
    first = ingest_file(db, path)
    assert (first['inserted'], first['errors'], first['status']) == (3, 1, 'partial')
    assert [r[0] for r in db.execute('SELECT record_id FROM events ORDER BY record_id')] == [1,3,4]
    diagnostic = error_details(db)[0]['diagnostics']
    assert diagnostic['chunk_number'] == 1 and diagnostic['last_record_number'] == 1
    assert diagnostic['resume_offset'] == 4096 + 2*65536 + 512
    assert diagnostic['parsed_records_after_error'] == 2
    again = ingest_file(db, path)
    assert again['inserted'] == 0 and again['duplicates'] == 3 and again['status'] == 'partial'
    assert db.execute('SELECT count(*) FROM evidence_timestamps').fetchone()[0] == 3
    db.close()


def test_dirty_header_tail_recovery(tmp_path, decode):
    path = tmp_path/'synthetic.evtx'
    path.write_bytes(file_bytes([chunk([1,2]), chunk([3,4]), bytes(65536)], declared=1, dirty=True, minor=2))
    db = connect(':memory:')
    result = ingest_file(db, path)
    assert result['inserted'] == 4 and result['errors'] == 2 and result['status'] == 'partial'
    errors = error_details(db)
    assert errors[0]['diagnostics']['header_checksum_valid'] is True
    assert errors[0]['diagnostics']['minor_version'] == 2
    assert errors[0]['diagnostics']['parsed_records_after_error'] == 4
    assert errors[0]['diagnostics']['resume_offset'] is None
    assert errors[1]['diagnostics']['parsed_records_after_error'] == 2
    assert errors[1]['diagnostics']['recovery'] == 'validated_contiguous_dirty_tail'
    assert db.execute('PRAGMA user_version').fetchone()[0] == 5
    db.close()


@pytest.mark.parametrize('dirty,later', [(False,[3]), (True,[1]), (True,[20])])
def test_undeclared_stale_or_unestablished_chunks_excluded(tmp_path, decode, dirty, later):
    path = tmp_path/'synthetic.evtx'
    path.write_bytes(file_bytes([chunk([1,2]), chunk(later)], declared=1, dirty=dirty))
    parsed = list(records(path))
    assert [r.record_id for r in parsed if r.xml] == [1,2]
    assert any('continuity' in (r.error or '') for r in parsed)


def test_bad_record_boundary_skips_to_next_chunk(tmp_path, decode):
    path = tmp_path/'synthetic.evtx'
    path.write_bytes(file_bytes([chunk([1]), chunk([2],bad_record=True), chunk([3])]))
    found=list(records(path))
    assert [r.record_id for r in found if r.xml] == [1,3]
    assert len([r for r in found if r.error]) == 1


def test_xml_error_resumes_at_validated_record_boundary(tmp_path, monkeypatch):
    def decode(record):
        if record.record_num() == 2:
            raise ValueError('synthetic XML failure')
        return xml(record_id=record.record_num())
    monkeypatch.setattr(recovery.Record, 'xml', decode)
    path=tmp_path/'synthetic.evtx'
    path.write_bytes(file_bytes([chunk([1,2,3])]))
    found=list(records(path))
    assert [r.record_id for r in found if r.xml] == [1,3]
    diagnostic=next(r.diagnostics for r in found if r.error)
    assert diagnostic['record_number']==2 and diagnostic['parsed_records_after_error']==1
    assert diagnostic['resume_offset']==4096+512+64


def test_record_header_xml_number_difference_is_not_recovery_error(tmp_path, monkeypatch):
    monkeypatch.setattr(recovery.Record,'xml',lambda r: xml(record_id=r.record_num()+1000))
    path=tmp_path/'synthetic.evtx';path.write_bytes(file_bytes([chunk([1,2])]))
    db=connect(':memory:');result=ingest_file(db,path)
    assert result['inserted']==2 and result['errors']==0 and result['status']=='complete'
    assert sum(result['validation_notes'].values())==2
    db.close()


def test_no_retry_on_repeated_invalid_chunks(tmp_path, monkeypatch, decode):
    original=recovery.ChunkHeader
    seen=[]
    def load(buf,offset):
        seen.append(offset)
        return original(buf,offset)
    monkeypatch.setattr(recovery,'ChunkHeader',load)
    path=tmp_path/'synthetic.evtx'
    path.write_bytes(file_bytes([chunk([i],bad_checksum=True) for i in range(1,11)]))
    found=list(records(path))
    assert len(seen)==len(set(seen))==10
    assert not any(r.xml for r in found) and len(found)==10


def test_deadline_stops_recovery_without_retry(tmp_path,monkeypatch,decode):
    ticks=iter([0,0,2])
    monkeypatch.setattr(recovery.time,'monotonic',lambda: next(ticks))
    path=tmp_path/'synthetic.evtx';path.write_bytes(file_bytes([chunk([1,2])]))
    found=list(records(path,timeout=1))
    assert len(found)==1 and 'deadline' in found[0].error


def test_clean_unused_capacity_is_not_error(tmp_path,decode):
    path=tmp_path/'synthetic.evtx';path.write_bytes(file_bytes([chunk([1]),bytes(65536)],declared=1))
    found=list(records(path))
    assert len(found)==1 and found[0].record_id==1 and not found[0].error


def test_unknown_header_shape_not_parsed(tmp_path,decode):
    path=tmp_path/'synthetic.evtx';path.write_bytes(file_bytes([chunk([1])],minor=99))
    found=list(records(path))
    assert not any(r.xml for r in found) and any('Unsupported' in r.error for r in found)


def test_status_exposes_recovery_and_preserves_old_fields(tmp_path,decode):
    from forensic_assistant.cli import build_parser
    from forensic_assistant.v2_cli import dispatch
    from forensic_assistant.retrieval.status_display import render
    path=tmp_path/'synthetic.evtx'
    path.write_bytes(file_bytes([chunk([1]),chunk([2],bad_checksum=True),chunk([3])]))
    db=connect(':memory:');ingest_file(db,path)
    presentation={}
    result,_=dispatch(db,build_parser().parse_args(['status']),presentation=presentation)
    assert result['ingestion_runs'][0]['inserted_count']==2
    assert result['ingestion_errors'][0]['message']
    assert result['ingestion_errors'][0]['diagnostics']['record_number'] is None
    text=render(result,'synthetic',presentation['status'])
    assert 'Recorded error (1)' in text and '1 later records parsed successfully' in text
    assert 'Partial: 1' in text
    db.close()


def test_bad_header_checksum_cannot_authorize_tail(tmp_path,decode):
    path=tmp_path/'synthetic.evtx'
    data=file_bytes([chunk([1]),chunk([2])],declared=1,dirty=True)
    data[124] ^= 1
    path.write_bytes(data)
    found=list(records(path))
    assert [r.record_id for r in found if r.xml]==[1]
    assert any('continuity' in (r.error or '') for r in found)


def test_recovered_timeline_uses_evidence_time_not_recovery_order(tmp_path,monkeypatch):
    from forensic_assistant.retrieval.evidence import EvidenceQueries
    monkeypatch.setattr(recovery.Record,'xml',lambda r: xml(record_id=r.record_num()).replace(
        '14:30:55','14:30:50' if r.record_num()==3 else '14:30:55'))
    path=tmp_path/'synthetic.evtx'
    path.write_bytes(file_bytes([chunk([1]),chunk([2],bad_checksum=True),chunk([3])]))
    db=connect(':memory:');ingest_file(db,path)
    assert [r['record_id'] for r in EvidenceQueries(db).search(timeline=True).records]==[3,1]
    db.close()

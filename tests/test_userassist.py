"""Synthetic UserAssist bytes: identity, raw provenance and timestamp boundaries."""
import base64
import codecs
import copy
import hashlib
import json
import sqlite3
import struct
from contextlib import closing

import pytest

from forensic_assistant import v2_cli, terminal
from forensic_assistant.artifacts import userassist as ua
from forensic_assistant.cli import build_parser, main
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant.retrieval.evidence import EvidenceQueries, get_evidence
from forensic_assistant.retrieval.registry_display import render, projected_values, KEY_CORRUPTION
from forensic_assistant.retrieval.search_display import render as search_text
from forensic_assistant.investigation_ai.case import open_readonly
from v2_fixtures import registry_file, FT

KEY = ua.PREFIX + r'{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count'
NAME = r'C:\Windows\System32\coreupdater.exe'
RAW_NAME = codecs.encode(NAME, 'rot_13')


def binary(version=5, count=7, ft=FT - 10_000_000):
    data = bytearray(16 if version == 3 else 72)
    struct.pack_into('<I', data, 4, count)
    struct.pack_into('<Q', data, 8 if version == 3 else 60, ft)
    return bytes(data)


@pytest.mark.parametrize('name', ['HRZR_PGYFRFFVBA', RAW_NAME, 'pnss\u00e9_\u03a9_%!', '', 'A1-z9'])
def test_rot13_is_ascii_only_and_scoped(name):
    assert ua.decoded_name(KEY, name) == codecs.decode(name, 'rot_13')
    assert ua.decoded_name(KEY.lower(), name) == codecs.decode(name, 'rot_13')
    for path in (r'Software\Other', KEY + r'\Child', 'Prefix\\' + KEY, KEY.replace('Count', 'Counter'), KEY.replace('CEBFF5CD', 'notaguid')):
        assert ua.decoded_name(path, name) is None


@pytest.mark.parametrize('version', [3, 5])
def test_supported_binary_fields_are_exact_and_raw_unchanged(version):
    raw = binary(version)
    before = bytes(raw)
    result = ua.interpret(KEY, RAW_NAME, 3, raw, version)
    assert result['status'] == 'parsed' and result['recorded_count'] == 7
    assert result['last_execution']['original_value'] == str(FT - 10_000_000)
    assert result['last_execution']['precision_ns'] == 100
    assert result['last_execution']['slot'] == ua.SLOT
    assert raw == before
    if version == 3:
        assert 'Unadjusted' in result['count_semantics']
    assert not any('focus' in key for key in result)


@pytest.mark.parametrize('length', [0, 4, 15, 17, 68, 71, 73, 1612])
def test_unsupported_lengths_fall_back_without_timestamps(length):
    result = ua.interpret(KEY, RAW_NAME, 3, bytes(length), 5)
    assert result['status'] == 'unsupported' and 'last_execution' not in result
    assert result['limitation'] == ua.LIMITATION


@pytest.mark.parametrize('version', [None, 0, 4, 6, 3])
def test_declared_format_gate(version):
    assert ua.interpret(KEY, RAW_NAME, 3, binary(5), version)['status'] == 'unsupported'


@pytest.mark.parametrize('name', ['UEME_CTLSESSION', 'UEME_CTLCUACount:ctor', 'UEME_OTHER'])
def test_special_entries_never_become_executions(name):
    data = ua.interpret(KEY, codecs.encode(name, 'rot_13'), 3, binary(), 5)
    assert data['status'] == 'control' and 'recorded_count' not in data and 'last_execution' not in data


@pytest.mark.parametrize('value_type,name', [(1, RAW_NAME), (4, RAW_NAME), (3, '')])
def test_nonbinary_and_default_names_not_interpreted(value_type, name):
    assert ua.interpret(KEY, name, value_type, binary(), 5)['status'] == 'unsupported'


@pytest.mark.parametrize('ft,status', [(0, 'missing'), (2**64 - 1, 'invalid')])
def test_invalid_and_zero_filetime_not_fabricated(ft, status):
    result = ua.interpret(KEY, RAW_NAME, 3, binary(ft=ft), 5)
    assert result['last_execution']['timestamp_utc'] is None
    assert result['last_execution']['normalization_status'] == status


@pytest.fixture(params=[3, 5])
def case(tmp_path, request):
    version = request.param
    path = tmp_path / 'case.db'
    raw = binary(version)
    hive = registry_file(tmp_path / 'synthetic.DAT', userassist=[
        (RAW_NAME, 3, raw), ('HRZR_PGYFRFFVBA', 3, bytes(1612)),
        ('onq.rkr', 3, b'bad'), ('', 3, raw)
    ], userassist_version=version)
    with closing(connect(path)) as db:
        with db:
            sid = sources.create(db, name='Synthetic UserAssist', hostname='lab', username='analyst')
            other = sources.create(db, name='Other source', hostname='lab')
        args = build_parser().parse_args(['ingest-registry', str(hive), '--source', sid])
        result, code = v2_cli.dispatch(db, args)
        assert code == 0, result
        eid = db.execute('SELECT evidence_id FROM registry_values WHERE value_name=?', (RAW_NAME,)).fetchone()[0]
    return path, eid, raw, sid, other


def test_ingestion_identity_raw_bytes_source_and_search(case):
    path, eid, raw, sid, other = case
    with closing(connect(path)) as db:
        q = EvidenceQueries(db)
        found = q.search(artifact='registry', value_name_contains='COREUPDATER', source_id=sid)
        assert [r['id'] for r in found.records] == [eid]
        assert q.search(value_name=RAW_NAME).records[0]['id'] == eid
        assert q.search(value_name=NAME).records[0]['id'] == eid
        assert q.search(value_name_contains='coreupdater', source_id=other).total == 0
        assert q.search(value_name_contains='%').total == 0
        assert q.search(value_name='').total == 1
        r = get_evidence(db, eid, True)
        assert r['detail']['value_name'] == RAW_NAME
        assert base64.b64decode(r['detail']['raw_data']['data']) == raw
        assert base64.b64decode(r['detail']['value_data']['data']) == raw
        assert r['context']['source_ids'] == [sid] and r['host_key'] == 'lab'
        assert ':ValueOffset:' in eid and not eid.startswith('USERASSIST:')
        assert db.execute('SELECT slot FROM evidence_timestamps WHERE evidence_id=?', (eid,)).fetchone()[0] == ua.SLOT
        assert q.search(value_name_contains='Example').records[0]['detail'].get('userassist') is None
        with pytest.raises(ValueError): q.search(artifact='prefetch', value_name=NAME)
        with pytest.raises(ValueError): q.search(value_name=NAME, value_name_contains='core')
        with pytest.raises(ValueError): q.search(value_name_contains='')


def test_legacy_projection_readonly_timeline_slots_and_filters(case):
    path, eid, raw, sid, _ = case
    with closing(connect(path)) as db:
        q = EvidenceQueries(db)
        before = q.search(timeline=True, value_name=RAW_NAME).as_dict()
        search_order = [r['id'] for r in q.search(artifact='registry').records]
        with db:
            db.execute('DELETE FROM evidence_timestamps WHERE evidence_id=?', (eid,))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with closing(open_readonly(path)) as db:
        q = EvidenceQueries(db)
        assert [r['id'] for r in q.search(artifact='registry').records] == search_order
        result = q.search(timeline=True, value_name=RAW_NAME).as_dict()
        assert result == before
        assert {r['timestamp']['slot'] for r in result['records']} == {ua.SLOT, 'LastWrite'}
        assert result['total'] == 2
        assert q.search(timeline=True, value_name=RAW_NAME, limit=1, offset=1).records[0]['timestamp']['slot'] == 'LastWrite'
        internal = result['records'][0]['timestamp_utc']
        assert q.search(value_name=RAW_NAME, start=internal, end=internal).total == 1
        anchor = get_evidence(db, eid)
        with pytest.raises(ValueError): v2_cli.anchor_time(anchor)
        assert v2_cli.anchor_time(anchor, ua.SLOT) == internal
        for t in anchor['timestamps']: t['timestamp_utc'] = internal
        with pytest.raises(ValueError): v2_cli.anchor_time(anchor)
        assert v2_cli.anchor_time(anchor, 'LastWrite') == internal
        assert not db.execute('SELECT 1 FROM evidence_timestamps WHERE evidence_id=?', (eid,)).fetchone()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest


def test_show_search_timeline_around_cli_and_color(case, capsys):
    path, eid, raw, sid, _ = case
    with closing(connect(path)) as db:
        r = get_evidence(db, eid)
        before = copy.deepcopy(r)
        text = render(r)
        assert terminal.SGR.sub('', render(r, terminal.Palette(True))) == text
        for value in ('UserAssist value', NAME, RAW_NAME, 'Registry key last write', 'UserAssist last execution/interaction',
                      '[LastWrite]', '[' + ua.SLOT + ']', 'user intent'):
            assert value in text
        assert r == before
        key = get_evidence(db, r['detail']['key_id'])
        values = projected_values(db, key['id'])
        key_text = render(key, values=values)
        assert 'DECODED NAME' in key_text and 'UEME_CTLSESSION' in key_text
        assert all(v.get('userassist') for v in values['values'])
        result = EvidenceQueries(db).search(value_name=NAME).as_dict()
        text = search_text(result, width=220)
        assert NAME in text and RAW_NAME not in text
        assert 'KEY TIME (UTC)' in text  # Internal time does not replace LastWrite.
        assert 'coreupdater.exe' in search_text(result, width=80)
        assert terminal.SGR.sub('', search_text(result, terminal.Palette(True), width=220)) == text
    assert main(['--db', str(path), 'search', '--artifact', 'registry', '--source', sid,
                 '--value-name-contains', 'coreupdater', '--ids']) == 0
    assert eid in capsys.readouterr().out
    assert main(['--db', str(path), 'around', eid, '--text']) != 0
    capsys.readouterr()
    assert main(['--db', str(path), 'around', eid, '--timestamp-slot', ua.SLOT, '--text']) == 0
    text = capsys.readouterr().out
    assert f'Anchor: UserAssist value [{ua.SLOT}]' in text and '<- anchor' in text
    assert main(['--db', str(path), 'show', eid, '--raw']) == 0
    result = json.loads(capsys.readouterr().out)
    assert base64.b64decode(result['detail']['raw_data']['data']) == raw


def test_warning_consolidation_keeps_raw_record_warnings(case):
    path, eid, _, _, _ = case
    with closing(connect(path)) as db:
        r = get_evidence(db, eid)
    r['warnings'] = [KEY_CORRUPTION, KEY_CORRUPTION, 'Synthetic unknown warning']
    result = dict(records=[copy.deepcopy(r) for _ in range(3)], total=3)
    before = copy.deepcopy(result)
    text = search_text(result)
    assert text.count('Parser flagged possible key corruption') == 3
    assert '3 displayed records' not in text
    assert 'Synthetic unknown warning' in text and result == before
    assert 'Parser flagged possible key corruption' in render(r)


def test_no_declared_version_does_not_guess_layout(tmp_path):
    from forensic_assistant.artifacts.ingest import ingest_artifact
    hive = registry_file(tmp_path / 'hive', userassist=[(RAW_NAME, 3, binary())], userassist_version=None)
    with closing(connect(':memory:')) as db:
        assert ingest_artifact(db, hive, 'registry')['status'] == 'complete'
        row = EvidenceQueries(db).search(value_name_contains='coreupdater').records[0]
        assert row['detail']['userassist']['status'] == 'unsupported'
        assert not any(t['slot'] == ua.SLOT for t in row['timestamps'])
        assert ua.LIMITATION in render(row)


def test_temporal_window_filters_before_host_resolution(case, monkeypatch):
    from forensic_assistant.database.artifacts import register, add_timestamp
    from forensic_assistant.artifacts.times import filetime
    from forensic_assistant.retrieval import evidence
    path, eid, _, sid, _ = case
    with closing(connect(path)) as db:
        record = dict(db.execute('SELECT * FROM evidence_records WHERE evidence_id=?', (eid,)).fetchone())
        stamp = filetime(FT + 86400 * 10_000_000, 'LastWrite', 'Registry Key LastWrite', 'Key context')
        with db:
            for i in range(200):
                other = dict(record, evidence_id=f"REGISTRY:{record['file_sha256']}:KeyOffset:{900000+i}", artifact_type='registry_key')
                register(db, other)
                db.execute('INSERT INTO registry_keys VALUES (?,?,?,?)', (other['evidence_id'], f'Software\\Outside{i}', None, 900000+i))
                add_timestamp(db, other['evidence_id'], stamp)
        calls = []
        original = evidence.effective_context
        def counted(db, record):
            calls.append(record)
            return original(db, record)
        monkeypatch.setattr(evidence, 'effective_context', counted)
        internal = ua.interpret(KEY, RAW_NAME, 3, binary(), 5)['last_execution']['timestamp_utc']
        result = EvidenceQueries(db).search(timeline=True, start=internal, end=internal,
                                            hostname='lab', strict_host=True, source_scope=sid)
        assert result.total == 1 and result.records[0]['id'] == eid
        assert len(calls) < 20  # Context work follows the small time window, not all source rows.

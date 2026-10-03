"""Synthetic FileCreate records; no real evidence is stored in the repository."""
import json
from contextlib import closing
from xml.sax.saxutils import escape
import pytest
from forensic_assistant.database.db import connect, register_source, insert_events
from forensic_assistant.ingest.normalize import normalize
from forensic_assistant.model import utc_timestamp
from forensic_assistant.retrieval.evidence import get_evidence, EvidenceQueries
from forensic_assistant.retrieval.presentation import detail
from forensic_assistant.retrieval.search_display import render as search
from forensic_assistant.retrieval.show_display import render as show
from forensic_assistant.correlation.cross_artifact import correlate, relevant_times
from forensic_assistant.detections.engine import detections, available_rules
from forensic_assistant.v2_cli import anchor_time
from test_ingest import xml, SHA

ACTOR = r'C:\Windows\System32\writer.exe'
TARGET = r'C:\Collected\Example\deep\folder\target.bin'
GUID = '11111111-2222-4333-8444-555555555555'
TIME = '2026-09-15 14:30:54.123'
FIELDS = [
    ('RuleName', None),
    ('Image', ACTOR),
    ('ProcessId', '1556'),
    ('ProcessGuid', '{' + GUID + '}'),
    ('TargetFilename', TARGET),
    ('UtcTime', TIME),
    ('CreationUtcTime', TIME)
]


def raw_event(
    fields=None,
    event_id=11,
    provider='Microsoft-Windows-Sysmon',
    channel='Microsoft-Windows-Sysmon/Operational'
):
    data = ''.join(
        f'<Data Name="{k}">{escape(v) if v is not None else ""}</Data>'
        for k,
        v in (FIELDS if fields is None else fields)
    )
    return xml(event_id, provider, channel, data).replace('</System>', '<Security UserID="S-1-5-18"/></System>')


def add(db, raw=None, offset=512):
    event = normalize(raw or raw_event(), SHA, 'synthetic.evtx', offset)
    with db:
        register_source(db, SHA, 1, 'synthetic.evtx')
        insert_events(db, [event])
    return get_evidence(db, event.id, True)


def test_fields_projections_identity_and_presentation():
    with closing(connect(':memory:')) as db:
        e = add(db)
        assert e['id'] == f'EVTX:{SHA}:Offset:512'
        assert e['artifact_type'] == e['kind'] == 'file_create'
        assert e['process_name'] == ACTOR and e['process_id'] == e['pid'] == 1556
        assert e['process_guid'] == GUID and e['user_sid'] == 'S-1-5-18'
        for key in (
            'username',
            'parent_process_name',
            'parent_process_id',
            'parent_process_guid',
            'command_line',
            'logon_id'
        ):
            assert e[key] is None
        assert e['raw_xml'] == raw_event() and e['record_id'] == 7
        assert json.loads(e['event_data_json']) == [dict(name=k, value=v) for k, v in FIELDS]
        assert {(o['slot'], o['role'], o['original']) for o in e['objects']} == {
            ('process_name', 'process_image', ACTOR), ('TargetFilename', 'file_create_target', TARGET)}
        stamps = {t['slot']: t for t in e['timestamps']}
        assert set(stamps) == {'SystemTime', 'Sysmon.UtcTime', 'Sysmon.CreationUtcTime'}
        assert e['timestamp_utc'] == '2026-09-15T14:30:55.123456700Z'
        for slot in ('Sysmon.UtcTime', 'Sysmon.CreationUtcTime'):
            t = stamps[slot]
            assert t['original_value'] == TIME and t['timestamp_utc'] == '2026-09-15T14:30:54.123000000Z'
            assert t['precision_ns'] == 1_000_000 and t['normalization_status'] == 'normalized'
            assert t['source'] and t['meaning'] and t['encoding']
        assert 'file creation/overwrite' in detail(e) and TARGET in detail(e)
        shown = show(e)
        assert 'PID: 1556' in shown and GUID in shown and 'Target:' in shown
        assert all(slot in shown for slot in stamps)
        compact = search(dict(records=[e], total=1), width=160)
        assert 'file creation/overwrite' in compact and 'target.bin' in compact
        assert 'Unmapped event' not in compact
        q = EvidenceQueries(db)
        assert q.search(process='writer.exe').total == 1
        assert q.search(process='target.bin').total == 0
        assert q.search(path='target.bin').total == 1
        assert q.search(event_id=11).total == 1
        timeline = q.search(timeline=True)
        assert timeline.total == 3 and {r['timestamp']['slot'] for r in timeline.records} == set(stamps)
        with pytest.raises(ValueError, match='timestamp-slot'):
            anchor_time(e)
        assert anchor_time(e, 'SystemTime') == e['timestamp_utc']
        assert anchor_time(e, 'Sysmon.UtcTime') == stamps['Sysmon.UtcTime']['timestamp_utc']


@pytest.mark.parametrize('field', ['Image', 'ProcessId', 'TargetFilename', 'UtcTime', 'CreationUtcTime', 'ProcessGuid'])
def test_duplicates_are_not_selected(field):
    fields = FIELDS + [(field, dict(FIELDS)[field])]
    with closing(connect(':memory:')) as db:
        e = add(db, raw_event(fields))
        assert any('Duplicate payload field ' + field in w for w in e['warnings'])
        assert len(json.loads(e['event_data_json'])) == len(fields)
        if field == 'Image':
            assert e['process_name'] is None and all(o['role'] != 'process_image' for o in e['objects'])
        if field == 'ProcessId':
            assert e['process_id'] is None
        if field == 'ProcessGuid':
            assert e['process_guid'] is None
        if field == 'TargetFilename':
            assert all(o['role'] != 'file_create_target' for o in e['objects']) and TARGET not in detail(e)
        if field in ('UtcTime', 'CreationUtcTime'):
            assert 'Sysmon.' + field not in {t['slot'] for t in e['timestamps']}


@pytest.mark.parametrize('field', ['UtcTime', 'CreationUtcTime'])
@pytest.mark.parametrize(
    'value',
    [None, '', '-', 'nonsense', '2026-02-30 12:00:00.123', '2026-09-15 12:00:00.1234567890']
)
def test_missing_invalid_payload_times_do_not_fall_back(field, value):
    fields = [(k, value if k == field else v) for k, v in FIELDS]
    with closing(connect(':memory:')) as db:
        e = add(db, raw_event(fields))
        assert e['timestamp_utc'] == '2026-09-15T14:30:55.123456700Z'
        stamps = {t['slot']: t for t in e['timestamps']}
        if value in (None, '', '-'):
            assert 'Sysmon.' + field not in stamps
        else:
            t = stamps['Sysmon.' + field]
            assert t['timestamp_utc'] is None and t['original_value'] == value
            assert t['normalization_status'] == 'invalid' and t['precision_ns'] is None
            assert any('Sysmon.' + field + ' timestamp is invalid' in w for w in e['warnings'])


@pytest.mark.parametrize(
    'value,precision',
    [
        ('2026-09-15 12:00:00', 1_000_000_000),
        ('2026-09-15 12:00:00.1', 100_000_000),
        ('2026-09-15 12:00:00.1234567', 100),
        ('2026-09-15 12:00:00.123456789', 1)
    ]
)
def test_payload_precision_is_source_precision(value, precision):
    with closing(connect(':memory:')) as db:
        e = add(db, raw_event([('UtcTime', value)]))
        t = next(t for t in e['timestamps'] if t['slot'] == 'Sysmon.UtcTime')
        assert t['precision_ns'] == precision and t['normalization_status'] == 'normalized'
    assert utc_timestamp(value) == (None, 'ambiguous')


@pytest.mark.parametrize(
    'provider,channel',
    [('Other', 'Microsoft-Windows-Sysmon/Operational'), ('Microsoft-Windows-Sysmon', 'Other')]
)
def test_provider_channel_qualification(provider, channel):
    with closing(connect(':memory:')) as db:
        e = add(db, raw_event(provider=provider, channel=channel))
        assert e['kind'] is None and e['process_name'] is None and not e['objects']
        assert [t['slot'] for t in e['timestamps']] == ['SystemTime']


@pytest.mark.parametrize(
    'event_id,kind',
    [
        (1, 'process'),
        (3, 'network'),
        (5, 'process_end'),
        (7, None),
        (10, None),
        (12, None),
        (13, None),
        (14, None),
        (17, None),
        (18, None),
        (22, None)
    ]
)
def test_other_sysmon_ids_unchanged(event_id, kind):
    fields = FIELDS + [
        ('ParentImage', r'C:\parent.exe'),
        ('ParentProcessId', '42'),
        ('CommandLine', 'example'),
        ('DestinationPort', '443'),
        ('User', r'LAB\Analyst')
    ]
    with closing(connect(':memory:')) as db:
        e = add(db, raw_event(fields, event_id=event_id))
        assert e['kind'] == kind and e['process_guid'] == GUID
        assert [t['slot'] for t in e['timestamps']] == ['SystemTime']
        assert all(o['role'] != 'file_create_target' for o in e['objects'])
        if event_id in (1, 3):
            assert e['process_name'] == ACTOR and e['process_id'] == 1556
            assert e['parent_process_id'] == 42 and e['parent_process_name'] == r'C:\parent.exe'
            assert e['command_line'] == 'example' and e['destination_port'] == 443 and e['username'] == r'LAB\Analyst'
        else:
            assert e['process_name'] is None and e['process_id'] is None
        if event_id == 5:
            assert e['pid'] == 1556


def test_invalid_pid_guid_and_absent_fields():
    with closing(connect(':memory:')) as db:
        e = add(db, raw_event([('ProcessId', 'bad'), ('ProcessGuid', 'bad')]))
        assert e['process_id'] is None and e['process_guid'] is None
        assert 'Invalid integer' in e['normalization_warnings_json']
        assert not e['objects'] and len(e['timestamps']) == 1


def test_no_process_tree_or_detection_promotion():
    from forensic_assistant.correlation.processes import process_tree
    from forensic_assistant.correlation.investigation import investigate
    with closing(connect(':memory:')) as db:
        e = add(db)
        assert all('file_create' not in r.kinds for r in available_rules())
        result = detections(db)
        assert not result['detections'] and all(c['candidate_count'] == 0 for c in result['rule_coverage'])
        with pytest.raises(ValueError):
            process_tree(db, e['id'])
        result = investigate(db, e['id'])
        assert any('timestamp' in str(r).lower() for r in result['unresolved_relationships'])
        assert not result['temporal_neighbor_ids']
        selected = investigate(db, e['id'], timestamp_slot='SystemTime')
        assert not any(r['relationship'] == 'temporal' for r in selected['unresolved_relationships'])


@pytest.mark.parametrize('reverse', [False, True])
def test_payload_times_cannot_strengthen_actor_correlation(tmp_path, reverse):
    from forensic_assistant.artifacts.ingest import ingest_artifact
    from forensic_assistant.artifacts.times import filetime
    from v2_fixtures import prefetch_file, FT
    payload_time = filetime(FT, 'x', 'x', 'x')['timestamp_utc'].removesuffix('Z')
    fields = [('Image', r'C:\Temp\PAYLOAD.EXE'), ('UtcTime', payload_time), ('CreationUtcTime', payload_time)]
    with closing(connect(':memory:')) as db:
        e = add(db, raw_event(fields).replace('PC.example', 'host'))
        ingest_artifact(db, prefetch_file(tmp_path / 'synthetic.pf'), 'prefetch', hostname='host')
        pf = db.execute('select evidence_id from prefetch_records').fetchone()[0]
        result = correlate(db, pf if reverse else e['id'])['relationships']
        assert len(result) == 1 and result[0]['status'] == 'POSSIBLE'
        comparison = result[0]['timestamp_comparison']
        assert comparison['candidate' if reverse else 'anchor']['slot'] == 'SystemTime'
        assert [t['slot'] for t in relevant_times(e)] == ['SystemTime']
        # Removing payload projections cannot change automatic actor correlation.
        db.execute("delete from evidence_timestamps where slot like 'Sysmon.%'")
        assert correlate(db, pf if reverse else e['id'])['relationships'] == result


def test_target_excluded_from_cross_artifact_comparison(tmp_path):
    from forensic_assistant.artifacts.ingest import ingest_artifact
    from v2_fixtures import prefetch_file, mft_file
    with closing(connect(':memory:')) as db:
        e = add(db, raw_event([('TargetFilename', r'C:\Temp\PAYLOAD.EXE')]))
        ingest_artifact(db, prefetch_file(tmp_path / 'synthetic.pf'), 'prefetch', hostname='pc.example')
        ingest_artifact(db, mft_file(tmp_path / 'synthetic.mft'), 'mft', hostname='pc.example', volume_root='C:')
        assert correlate(db, e['id'])['candidate_count'] == 0
        for r in EvidenceQueries(db).search().records:
            if r['id'] != e['id']:
                assert all(e['id'] not in link['evidence_ids'] for link in correlate(db, r['id'])['relationships'])

"""Synthetic analyst views; assertions cover provenance and uncertainty, not cosmetics."""
import copy
import json
import sqlite3
from contextlib import closing

import pytest

from forensic_assistant.cli import main
from forensic_assistant.correlation.investigation import investigate
from forensic_assistant.correlation.sessions import session
from forensic_assistant.retrieval.analysis_display import render_session, render_investigation
from forensic_assistant.retrieval.evidence import get_evidence
from forensic_assistant.retrieval.presentation import safe
from forensic_assistant.retrieval.search_display import render as search_display
from forensic_assistant.terminal import Palette, SGR
from forensic_assistant.v1_cli import omit_raw
from v1_fixtures import database, add


def logon(db, offset=1, **kwargs):
    data = dict(TargetLogonId='0x123', SubjectLogonId='0x456', TargetLinkedLogonId='0x789',
                TargetUserName='analyst', TargetDomainName='LAB', LogonType='2',
                ProcessName=r'C:\Windows\login.exe', ProcessId='12')
    data.update(kwargs.pop('data', {}))
    return add(db, offset, event_id=kwargs.pop('event_id', 4624), data=data, **kwargs)


@pytest.fixture
def db():
    with closing(database()) as connection:
        yield connection


def assembly(db):
    parent_guid = '{11111111-1111-4111-8111-111111111111}'
    parent = add(db, 10, 1, time='14:30:00', sysmon=True, data={
        'Image': r'C:\Windows\cmd.exe', 'ProcessId': '10', 'ProcessGuid': parent_guid,
        'User': 'LAB\\analyst'})
    child = add(db, 20, 1, time='14:30:01', sysmon=True, data={
        'Image': r'C:\Windows\downloader.exe', 'ProcessId': '20',
        'ProcessGuid': '{22222222-2222-4222-8222-222222222222}',
        'ParentProcessGuid': parent_guid, 'ParentImage': r'C:\Windows\cmd.exe', 'ParentProcessId': '10',
        'User': 'LAB\\analyst', 'LogonId': '0x987', 'CommandLine': 'downloader.exe /example'})
    neighbor = add(db, 30, 11, time='14:30:02', sysmon=True, data={
        'Image': r'C:\Windows\writer.exe', 'ProcessId': '30',
        'ProcessGuid': '{33333333-3333-4333-8333-333333333333}',
        'TargetFilename': r'C:\Example\file.bin',
        'UtcTime': '2026-09-15 14:30:01.995', 'CreationUtcTime': '2026-09-15 14:30:01.995'})
    return parent, child, neighbor


@pytest.mark.parametrize('target,expected', [('0x123', '0x123'), ('291', '0x123'),
                                           (None, '-'), ('0', '-'), ('invalid', '-')])
def test_logon_search_target_only_and_ids(db, target, expected):
    event = logon(db, data={'TargetLogonId': target or ''})
    record = get_evidence(db, event['id'])
    result = dict(records=[record], total=1)
    before = copy.deepcopy(result)
    rendered = search_display(result, ids=True, width=120)
    assert 'LOGON ID' in rendered and expected in rendered
    assert '0x456' not in rendered and '0x789' not in rendered
    assert f"    ID: {event['id']}" in rendered
    assert result == before
    # Vertical layout still retains the copyable Logon ID.
    assert 'LOGON ID: ' + expected in search_display(result, width=35)


def test_failed_logon_never_uses_subject_as_session_id(db):
    event = logon(db, event_id=4625, data={'TargetLogonId': ''})
    rendered = search_display(dict(records=[get_evidence(db, event['id'])], total=1), width=35)
    assert 'LOGON ID: -' in rendered and '0x456' not in rendered


def test_mixed_search_preserves_numbering_and_query_order(db):
    first = logon(db)
    second = add(db, 2, 4688, data={'NewProcessName': 'example.exe'})
    third = logon(db, 3, event_id=4625)
    records = [get_evidence(db, e['id']) for e in (first, second, third)]
    text = search_display(dict(records=records, total=3), ids=True, width=120)
    for record in records:
        assert f"    ID: {record['id']}" in text
    assert text.index(first['id']) < text.index(second['id']) < text.index(third['id'])
    assert text.index('0x123') < text.index('example.exe') < text.index('4625')


def test_session_fallback_is_not_observed_end(db):
    logon(db)
    result = session(db, '0x123')
    before = copy.deepcopy(result)
    text = render_session(result)
    assert text.startswith('Status: CORRELATED\n') and not text.startswith('{')
    for item in ('LAB', 'analyst', 'pc.example', '0x123', '2026-09-15 14:30:00.000 UTC', 'login.exe', 'PID: 12'):
        assert item in text
    assert 'End: Not observed' in text
    assert 'Correlation boundary: 2026-09-16 14:30:00.000 UTC (fallback_ceiling)' in text
    assert 'Maximum correlation window: 24 hours' in text
    assert result == before


@pytest.mark.parametrize('event_id,account,observed', [(4634, 'analyst', True),
                                                     (4634, 'other', False),
                                                     (4608, 'analyst', False),
                                                     (4624, 'analyst', False)])
def test_session_boundary_interpretation(db, event_id, account, observed):
    anchor = logon(db)
    add(db, 2, event_id, time='14:31:00', data={
        'TargetLogonId': '0x123', 'TargetUserName': account, 'TargetDomainName': 'LAB'})
    result = session(db, '0x123', anchor_id=anchor['id'])
    text = render_session(result)
    assert ('End: 2026-09-15 14:31:00.000 UTC' in text) == observed
    assert ('End: Not observed' in text) != observed
    if account == 'other':
        assert 'Conflicting account/SID fields' in text


def test_session_truncation_cannot_establish_end(db):
    anchor = logon(db)
    add(db, 2, 4634, time='14:31:00', data={'TargetLogonId': '0x123'})
    result = session(db, '0x123', anchor_id=anchor['id'], limit=1)
    text = render_session(result)
    assert 'End: Not observed' in text and 'results are incomplete' in text


def test_unresolved_session_and_validation_help(db, capsys):
    text = render_session(session(db, '0x123'))
    assert 'UNRESOLVED' in text and 'No unique successful-logon anchor' in text
    assert 'End:' not in text
    with pytest.raises(ValueError, match='A nonzero decimal or hexadecimal Logon ID is required'):
        session(db, 'EVTX:fake:Offset:1')
    with pytest.raises(SystemExit) as exited:
        main(['session', '--help'])
    assert exited.value.code == 0
    help_text = ' '.join(capsys.readouterr().out.split())
    assert 'Windows authentication Logon ID' in help_text
    assert 'not a Locard evidence ID' in help_text


def test_investigation_relationships_and_neighbors_separate(db):
    parent, child, neighbor = assembly(db)
    result = investigate(db, child['id'], seconds=5)
    before = copy.deepcopy(result)
    text = render_investigation(result)
    assert text.startswith('Anchor\n')
    assert 'downloader.exe [PID 20]' in text and 'downloader.exe /example' in text
    confirmed = text.split('Confirmed relationships\n')[1].split('Nearby evidence')[0]
    assert 'cmd.exe [PID 10] -> downloader.exe [PID 20]' in confirmed
    assert 'Explicit same-host parent/process GUID match' in confirmed
    assert 'writer.exe' not in confirmed
    nearby = text.split('Nearby evidence\n')[1].split('Unresolved')[0]
    assert 'writer.exe - file creation/overwrite:' in nearby
    assert 'Temporal proximity only' in nearby and '->' not in nearby
    for slot in ('SystemTime', 'Sysmon.UtcTime', 'Sysmon.CreationUtcTime'):
        assert slot in nearby
    assert '+0.995s' in nearby and '+1.000s' in nearby
    assert 'Session\n  No unique successful-logon anchor' in text
    assert '3 evidence records retrieved | EVTX' in text
    assert 'None in the returned result.' in text
    assert 'source_query_counts' not in text and child['id'] not in text
    assert result == before


def test_investigation_missing_anchor_timestamp_never_guessed(db):
    _, _, neighbor = assembly(db)
    text = render_investigation(investigate(db, neighbor['id']))
    assert 'No unambiguous selected timestamp' in text
    assert 'select --timestamp-slot' in text
    assert '+0.005s' not in text
    selected = render_investigation(investigate(db, neighbor['id'], timestamp_slot='Sysmon.UtcTime'))
    assert 'Timestamp slot: Sysmon.UtcTime' in selected
    assert 'Time: 2026-09-15 14:30:01.995 UTC' in selected


def test_investigation_limits_and_actual_retrieved_coverage(db):
    _, child, _ = assembly(db)
    result = investigate(db, child['id'], max_candidates=1)
    text = render_investigation(result)
    assert '1 evidence records retrieved | EVTX' in text
    assert 'limit reached' in text
    assert 'Evidence outside returned set' in text
    assert 'Supporting evidence omitted' in text


def test_detection_and_conflict_limitations_are_retained(db):
    _, child, _ = assembly(db)
    result = investigate(db, child['id'])
    result['detections'] = [dict(severity='low', rule_id='TEST', rule_name='Synthetic test',
                                reason='Review only', limitations=['Does not establish compromise'])]
    result['evidence_records'][0]['context']['conflicts'] = ['hostname']
    result['coverage']['incomplete_ingestion_runs'] = 2
    text = render_investigation(result)
    for value in ('low | TEST | Synthetic test', 'Review only', 'Does not establish compromise',
                  'Conflicting context: hostname', '2 incomplete ingestion runs'):
        assert value in text


@pytest.fixture
def stored(tmp_path, db):
    logon(db)
    _, child, _ = assembly(db)
    path = tmp_path / 'case.db'
    with closing(sqlite3.connect(path)) as target:
        db.backup(target)
    return path, child['id']


@pytest.mark.parametrize('command', ['session', 'investigate'])
def test_cli_json_raw_text_and_destinations(stored, db, command, tmp_path, capsys, monkeypatch):
    from forensic_assistant import output
    path, eid = stored
    before = path.read_bytes()
    selection = ['session', '--logon-id', '0x123'] if command == 'session' else ['investigate', eid]
    args = ['--db', str(path), *selection]
    expected = session(db, '0x123') if command == 'session' else investigate(db, eid)
    for mode in ([], ['--json']):
        assert main(args + mode) == 0
        assert json.loads(capsys.readouterr().out) == omit_raw(expected)
    assert main(args + ['--raw']) == 0
    raw = json.loads(capsys.readouterr().out)
    assert 'raw_xml' in raw['records' if command == 'session' else 'evidence_records'][0]
    assert main(args + ['--raw', '--text']) == 0
    assert json.loads(capsys.readouterr().out) == raw
    assert main(args + ['--text']) == 0
    text = capsys.readouterr().out
    assert text.startswith('Status: CORRELATED\n' if command == 'session' else 'Anchor\n')
    captured = []
    monkeypatch.setattr(output, 'page', lambda stream, palette=None: captured.append(stream.read()))
    assert main(args + ['--text', '--page']) == 0 and captured == [text]
    target = tmp_path / 'analysis.txt'
    from forensic_assistant import terminal
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    monkeypatch.delenv('NO_COLOR', raising=False)
    assert main(args + ['--text', '--output', str(target)]) == 0
    assert target.read_text(encoding='utf-8') == text
    assert main(args + ['--text', '--append', str(target)]) == 0
    assert target.read_text(encoding='utf-8') == text + '\n' + text
    assert '\x1b' not in target.read_text(encoding='utf-8')
    assert path.read_bytes() == before


def test_search_cli_supplies_session_input(stored, capsys):
    path, _ = stored
    assert main(['--db', str(path), 'search', '--kind', 'logons', '--ids']) == 0
    text = capsys.readouterr().out
    assert 'LOGON ID' in text and '0x123' in text
    assert '    ID: EVTX:' in text and '0x456' not in text and '0x789' not in text


@pytest.mark.parametrize('command', ['session', 'investigate'])
def test_colors_and_escaping(db, command):
    logon(db)
    _, child, _ = assembly(db)
    result = session(db, '0x123') if command == 'session' else investigate(db, child['id'])
    renderer = render_session if command == 'session' else render_investigation
    record = result['records'][0] if command == 'session' else result['direct_evidence'][0]
    hostile = 'user\x1b[31m\nFORGED'
    record['username'] = hostile
    plain = renderer(result, Palette(False))
    colored = renderer(result, Palette(True))
    assert safe(hostile) in plain and '\x1b' not in plain
    assert '\x1b' in colored and SGR.sub('', colored) == plain


@pytest.mark.parametrize('flag', [[], ['--no-color']])
def test_cli_no_color_policy(stored, monkeypatch, capsys, flag):
    from forensic_assistant import terminal
    path, eid = stored
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    monkeypatch.delenv('NO_COLOR', raising=False)
    args = ['--db', str(path), 'investigate', eid, '--text', *flag]
    assert main(args) == 0
    assert ('\x1b' in capsys.readouterr().out) == (not flag)
    monkeypatch.setenv('NO_COLOR', '')
    assert main(args) == 0 and '\x1b' not in capsys.readouterr().out

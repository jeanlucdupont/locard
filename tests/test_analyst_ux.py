"""Synthetic analyst UX checks; no manual evidence and no network/model calls."""
from contextlib import closing
from copy import deepcopy
import json
import sqlite3

import pytest

from forensic_assistant import activity, output, terminal, v1_cli
from forensic_assistant.cli import build_parser, main
from forensic_assistant.cli_parser import InvalidArguments
from forensic_assistant.correlation.processes import process_tree
from forensic_assistant.correlation.sessions import logons, session
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.retrieval import analyst_display as display
from forensic_assistant.terminal import Palette, SGR
from shell_output import before_shutdown
from test_interactive_shell import Input
from v1_fixtures import database, add, process


@pytest.fixture
def case(tmp_path):
    with closing(database()) as db:
        for offset, event_id in enumerate((4624, 4625, 4672, 4648, 4647, 4634), 1):
            add(db, offset, event_id, time=f'14:30:0{offset}', data={
                'TargetUserName': 'analyst', 'TargetDomainName': 'LAB', 'TargetLogonId': '0x123',
                'SubjectUserName': 'SYSTEM', 'SubjectDomainName': 'NT AUTHORITY', 'SubjectLogonId': '0x123',
                'LogonType': '5', 'IpAddress': '127.0.0.1', 'ProcessName': r'C:\Windows\service.exe'})
        process(db, 20, 10, name='parent.exe', time='14:30:10')
        child = process(db, 21, 20, 10, name='child.exe', parent='parent.exe', time='14:30:11')
        add(db, 30, 4720, time='14:30:15', data={'TargetUserName': 'new-account'})
        path = tmp_path / 'case.db'
        with closing(sqlite3.connect(path)) as target:
            db.backup(target)
    return path, child['id']


def selection(command, eid):
    return {'logons': ['logons'], 'detections': ['detections'],
            'session': ['session', '--logon-id', '0x123'],
            'process-tree': ['process-tree', '--evidence', eid],
            'investigate': ['investigate', eid]}[command]


COMMANDS = ('logons', 'detections', 'session', 'process-tree', 'investigate')
HEADINGS = {'logons': 'TIME (UTC)', 'detections': 'Rule coverage', 'session': 'Status: CORRELATED',
            'process-tree': 'Process evidence', 'investigate': 'Anchor'}


@pytest.mark.parametrize('command', COMMANDS)
@pytest.mark.parametrize('flags', [[], ['--json'], ['--text']])
def test_actual_shell_defaults_explicit_modes_json_and_audit(case, command, flags, capsys):
    path, eid = case
    words = selection(command, eid)
    before = path.read_bytes()
    assert main(['--db', str(path), *words, '--json']) == 0
    expected = json.loads(capsys.readouterr().out)
    def entered():
        capsys.readouterr()
        return ' '.join([*words, *flags])
    shell = Shell(State(None), Input(str(path), entered, 'exit'), no_color=True)
    assert shell.run() == shell.last_status == 0
    text = before_shutdown(capsys.readouterr().out)
    if flags == ['--json']:
        assert json.loads(text) == expected
    else:
        assert HEADINGS[command] in text and not text.lstrip().startswith('{')
    audit = activity.inspect(activity.sidecar(path), 1000)
    assert audit['valid']
    entry = [r for r in audit['records'] if r['action'] == 'COMMAND' and r.get('command') == command
             and r.get('phase') == 'complete'][-1]
    assert entry['argv'] == words + flags
    assert entry['parameters']['text'] == (flags != ['--json'])
    assert '\x1b' not in activity.sidecar(path).read_text()
    assert path.read_bytes() == before


@pytest.mark.parametrize('command', COMMANDS)
def test_direct_json_contract_raw_and_mutual_exclusion(case, command, capsys, monkeypatch):
    path, eid = case
    args = ['--db', str(path), *selection(command, eid)]
    with closing(sqlite3.connect(path)) as db:
        db.row_factory = sqlite3.Row
        expected = v1_cli.dispatch(db, build_parser().parse_args(args))
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    monkeypatch.delenv('NO_COLOR', raising=False)
    for flags in ([], ['--json'], ['--raw']):
        assert main(args + flags) == 0
        raw = capsys.readouterr().out
        assert '\x1b' not in raw
        value = json.loads(raw)
        assert v1_cli.omit_raw(value) == v1_cli.omit_raw(expected)
    for interactive in (False, True):
        with pytest.raises((SystemExit, InvalidArguments)):
            build_parser(interactive=interactive).parse_args(args + ['--json', '--text'])
    raw_args = build_parser(interactive=True).parse_args(args + ['--raw'])
    assert raw_args.json and not raw_args.text


@pytest.mark.parametrize('command', COMMANDS)
@pytest.mark.parametrize('json_mode', [False, True])
@pytest.mark.parametrize('mode', ['--output', '--append'])
def test_interactive_resolved_output_files(case, tmp_path, command, json_mode, mode, capsys, monkeypatch):
    path, eid = case
    target = tmp_path / 'derived.txt'
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    monkeypatch.delenv('NO_COLOR', raising=False)
    words = selection(command, eid) + (['--json'] if json_mode else []) + [mode, str(target)]
    shell = Shell(State(None), Input(str(path), ' '.join(words), 'exit'))
    assert shell.run() == shell.last_status == 0
    text = target.read_text(encoding='utf-8')
    assert '\x1b' not in text
    if json_mode:
        assert isinstance(json.loads(text), dict)
    else:
        assert HEADINGS[command] in text
    assert activity.inspect(activity.sidecar(path), 1000)['valid']
    assert '\x1b' not in activity.sidecar(path).read_text()


@pytest.mark.parametrize('command', COMMANDS)
def test_interactive_pager_uses_human_mode(case, command, monkeypatch):
    path, eid = case
    pages = []
    monkeypatch.setattr(output, 'page', lambda stream, palette=None: pages.append(stream.read()))
    shell = Shell(State(None), Input(str(path), ' '.join(selection(command, eid) + ['--page']), 'exit'), no_color=True)
    assert shell.run() == shell.last_status == 0
    assert len(pages) == 1 and HEADINGS[command] in pages[0]
    assert main(['--db', str(path), *selection(command, eid), '--json', '--page']) == 2


def test_logon_kinds_fields_pagination_recovery_and_json_unchanged(case, capsys):
    path, _ = case
    with closing(sqlite3.connect(path)) as db:
        db.row_factory = sqlite3.Row
        result = logons(db).as_dict()
        assert len(result['records']) == 6
        sha = result['records'][0]['file_sha256']
        db.execute("INSERT INTO ingestion_runs(source_file,file_sha256,started_utc,status,error_count) VALUES (?,?,?,'partial',1)",
                   ('synthetic.evtx', sha, '2026-01-01'))
        db.execute("INSERT INTO ingestion_runs(source_file,file_sha256,started_utc,status) VALUES (?,?,?,'complete')",
                   ('renamed.evtx', sha, '2026-01-02'))
        db.commit()
        before = deepcopy(result)
        context = display.evtx_context(db, result['records'])
        text = display.render_logons(result, context=context, width=150)
        for label, _ in display.EVENT_LABELS.values():
            assert label in text
        assert '127.0.0.1' in text and 'Logon type: 5' in text and r'C:\Windows\service.exe' in text
        assert text.count('a partial EVTX ingestion attempt is recorded') == 1
        assert 'Missing records do not prove absence of activity.' in text
        for record in result['records']:
            assert text.count('ID: ' + record['id']) == 1
        assert result == before
        page = logons(db, limit=2, offset=2).as_dict()
        paged = display.render_logons(page)
        assert 'Showing 3–4 of 6 logon events' in paged and 'bounded result page' in paged
        beyond = display.render_logons(logons(db, offset=100).as_dict())
        assert 'No logon events on this page.' in beyond and 'Showing 0 of 6' in beyond
    assert main(['--db', str(path), 'logons', '--json']) == 0
    assert json.loads(capsys.readouterr().out) == v1_cli.omit_raw(result)


def test_logon_absent_fields_noise_accounts_and_controls():
    with closing(database()) as db:
        for i, name in enumerate(('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'Window Manager', 'Font Driver Host'), 1):
            add(db, i, 4624, data={'TargetUserName': name, 'LogonType': '5'})
        result = logons(db).as_dict()
        text = display.render_logons(result, width=180)
        for name in ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'Window Manager', 'Font Driver Host'):
            assert name in text
        assert 'Source IP: -' in text and 'Process: -' in text and len(result['records']) == 5
        result['records'][0]['username'] = 'élève\x1b[31m\nFORGED'
        plain = display.render_logons(result, width=40)
        colored = display.render_logons(result, Palette(True), width=40)
        assert 'élève' in plain and '\x1b' not in plain and '\\u001b' in plain
        assert SGR.sub('', colored) == plain


def test_no_evtx_and_no_matching_logons_are_distinct(tmp_path, capsys):
    from forensic_assistant.database.db import connect
    from forensic_assistant.artifacts.ingest import ingest_artifact
    from v2_fixtures import mft_file
    path = tmp_path / 'mft-only.db'
    with closing(connect(path)) as db:
        ingest_artifact(db, mft_file(tmp_path / '$MFT'), 'mft')
    for args in (['logons'], ['session', '--logon-id', '0x123']):
        assert main(['--db', str(path), *args, '--text']) == 0
        text = capsys.readouterr().out
        assert 'This case contains no EVTX evidence.' in text
        assert 'Missing or incomplete Security logs do not prove that no logons occurred.' in text
        assert 'No logon events found.' in text if args[0] == 'logons' else 'UNRESOLVED' in text
    with closing(connect(path)) as db:
        from test_ingest import SHA
        from forensic_assistant.database.db import register_source
        register_source(db, SHA, 1, 'synthetic.evtx')
        add(db, 1, 9999)
    assert main(['--db', str(path), 'logons', '--text']) == 0
    text = capsys.readouterr().out
    assert 'No logon events found.' in text and 'contains no EVTX' not in text and 'Security log is absent' not in text


def detection_result():
    findings = [dict(detection_id='DETECTION:' + str(i) * 64, timestamp='2026-01-01T00:00:00.000000000Z',
                     rule_id='TEST-' + str(i), rule_name='Synthetic rule', severity=severity,
                     evidence_ids=['EVTX:' + str(i) * 64 + ':Offset:1'], reason='Synthetic observed condition',
                     limitations=[display.SHARED_DETECTION_CAUTION], parameters={})
                for i, severity in enumerate(('low', 'medium', 'high'), 1)]
    findings[0]['limitations'].append('Only the first detection has this limitation')
    return dict(detections=findings, total_evaluated_detections=3, truncated=False,
                rule_coverage=[dict(rule_id=d['rule_id'], candidate_count=1, evaluated_count=1, truncated=False) for d in findings],
                caution='DETECTION != COMPROMISE. Missing matches do not prove absence of activity.')


@pytest.mark.parametrize('width', [35, 180])
def test_detection_ids_local_limits_coverage_color_and_immutability(width):
    result = detection_result()
    before = deepcopy(result)
    text = display.render_detections(result, width=width)
    colored = display.render_detections(result, Palette(True), width=width)
    assert SGR.sub('', colored) == text and result == before
    for finding in result['detections']:
        assert text.count(finding['detection_id']) == 1 and text.count(finding['evidence_ids'][0]) == 1
    assert text.index(result['detections'][0]['detection_id']) < text.index('Only the first') < text.index(result['detections'][1]['detection_id'])
    assert text.count('A detection does not establish malicious activity by itself.') == 1
    assert 'not confidence or probability of compromise' in text and 'DETECTION != COMPROMISE' in text
    assert 'Rules with displayed matches: 3' in text and 'Candidate evaluations (across rules): 3' in text
    for severity, code in [('high', '31'), ('medium', '33'), ('low', '36')]:
        assert '\x1b[' + code + 'm' + severity in colored
    result['detections'] = result['detections'][:1]
    result['truncated'] = result['rule_coverage'][0]['truncated'] = True
    limited = display.render_detections(result)
    assert 'Showing 1 of 3 detections' in limited and 'Candidate evaluation truncated: yes' in limited
    assert 'additional matches may exist' in limited
    result['detections'] = []
    result['total_evaluated_detections'] = 0
    empty = display.render_detections(result)
    assert empty.startswith('No detections matched.') and 'DETECTION != COMPROMISE' in empty
    assert 'Candidate evaluation truncated: yes' in empty


@pytest.mark.parametrize('bounds,message', [({}, None), ({'max_depth': 0}, 'Maximum graph depth reached'),
                                          ({'max_nodes': 1}, 'Maximum graph nodes reached')])
def test_process_hierarchy_and_bounds_preserve_graph(case, bounds, message):
    path, eid = case
    with closing(sqlite3.connect(path)) as db:
        db.row_factory = sqlite3.Row
        result = process_tree(db, eid, **bounds)
    before = deepcopy(result)
    text = display.render_process_tree(result, unicode=True)
    assert result == before and SGR.sub('', display.render_process_tree(result, Palette(True), unicode=True)) == text
    for record in result['nodes']:
        assert 'ID: ' + record['id'] in text
    if not bounds:
        assert 'parent.exe  PID 10' in text and '── child.exe  PID 20 [anchor]' in text
        assert 'Parent relationship: LIKELY' in text
    if message:
        assert message in text
    assert 'PID lookback: 300 seconds; child window: 300 seconds' in text
    assert 'does not establish that they do not exist' in text


def test_process_unresolved_cycle_and_omitted_edges():
    with closing(database()) as db:
        a, b = '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222'
        first = add(db, 1, 1, sysmon=True, data={'ProcessGuid': a, 'ParentProcessGuid': b, 'ProcessId': '10', 'ParentProcessId': '20'})
        add(db, 2, 1, sysmon=True, data={'ProcessGuid': b, 'ParentProcessGuid': a, 'ProcessId': '20', 'ParentProcessId': '10'})
        result = process_tree(db, first['id'])
        text = display.render_process_tree(result, unicode=True)
        assert 'UNRESOLVED' in text and 'Parent relationship:' not in text
        assert 'Contradictory parent records form a cycle' in text
        assert 'does not establish that they do not exist' in text
    ambiguous = dict(status='UNRESOLVED', reason='Select a unique process using --evidence', candidate_evidence_ids=['EVTX:one'], total=2)
    text = display.render_process_tree(ambiguous)
    assert 'Showing 1 of 2 candidate anchors' in text and 'Candidate ID: EVTX:one' in text


def test_confirmed_process_hierarchy_keeps_explicit_status():
    with closing(database()) as db:
        guid = '11111111-1111-1111-1111-111111111111'
        parent = add(db, 1, 1, sysmon=True, data={'ProcessGuid': guid, 'ProcessId': '10', 'Image': 'parent.exe'})
        child = add(db, 2, 1, sysmon=True, time='14:30:10', data={
            'ParentProcessGuid': guid, 'ProcessGuid': '22222222-2222-2222-2222-222222222222',
            'ProcessId': '20', 'ParentProcessId': '10', 'Image': 'child.exe', 'ParentImage': 'parent.exe'})
        result = process_tree(db, child['id'])
        text = display.render_process_tree(result, unicode=True)
        assert '── child.exe  PID 20 [anchor]' in text and 'Parent relationship: CONFIRMED' in text
        assert text.index(parent['id']) < text.index(child['id'])
        assert 'No parent creation record is invented' in text
        assert {r['id'] for r in result['nodes']} == {parent['id'], child['id']}


@pytest.mark.parametrize('command', COMMANDS)
@pytest.mark.parametrize('capable,no_color,no_color_env', [(True, False, False), (True, True, False),
                                                       (False, False, False), (True, False, True)])
def test_human_color_capability_and_environment(case, command, capable, no_color, no_color_env, monkeypatch, capsys):
    path, eid = case
    monkeypatch.setattr(terminal, 'capable', lambda stream: capable)
    monkeypatch.delenv('NO_COLOR', raising=False)
    if no_color_env:
        monkeypatch.setenv('NO_COLOR', '')
    flags = ['--no-color'] if no_color else []
    assert main(['--db', str(path), *selection(command, eid), '--text', *flags]) == 0
    assert ('\x1b' in capsys.readouterr().out) == (capable and not no_color and not no_color_env)


def test_logon_semantic_colors_and_bounded_context_lookup(case):
    path, _ = case
    with closing(sqlite3.connect(path)) as db:
        db.row_factory = sqlite3.Row
        result = logons(db).as_dict()
        queries = []
        db.set_trace_callback(queries.append)
        display.evtx_context(db, result['records'] * 100)
        assert len(queries) == 1 and 'SELECT DISTINCT file_sha256' in queries[0]
    text = display.render_logons(result, Palette(True), width=180)
    for label, role in display.EVENT_LABELS.values():
        assert '\x1b[' + terminal.STYLES[role] + 'm' + label in text


def test_json_does_not_query_presentation_context(case, monkeypatch, capsys):
    path, _ = case
    def forbidden(*args):
        raise AssertionError('JSON must not query human context')
    monkeypatch.setattr(display, 'evtx_context', forbidden)
    for words in (['logons'], ['session', '--logon-id', '0x123']):
        assert main(['--db', str(path), *words, '--json']) == 0
        assert isinstance(json.loads(capsys.readouterr().out), dict)


@pytest.mark.parametrize('command', COMMANDS)
def test_help_describes_modes_without_misleading_default(command, case, capsys):
    _, eid = case
    with pytest.raises(SystemExit) as done:
        build_parser(interactive=True).parse_args(selection(command, eid) + ['--help'])
    assert done.value.code == 0
    text = ' '.join(capsys.readouterr().out.split())
    assert 'Structured JSON output' in text and 'Human-readable text output' in text
    assert 'Interactive shell defaults to human text; direct CLI defaults to JSON.' in text
    assert 'JSON output (default)' not in text
    if command == 'logons':
        assert 'normalized Windows Event Log evidence' in text

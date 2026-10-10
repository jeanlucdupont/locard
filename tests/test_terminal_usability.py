"""Terminal-only behavior using synthetic evidence and fake console input."""
from contextlib import closing, contextmanager
from copy import deepcopy
import io
import json
import os
from types import SimpleNamespace

import pytest

from forensic_assistant import output, terminal, v1_cli
from forensic_assistant.cli import build_parser, main
from forensic_assistant.cli_parser import InvalidArguments
from forensic_assistant.database.db import connect
from forensic_assistant.ingest.evtx import ParsedRecord, ingest_file
from forensic_assistant.interactive import console, creation
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.retrieval import analyst_display, show_display
from forensic_assistant.retrieval.evidence import get_evidence
from forensic_assistant.terminal import Palette, SGR
from test_ingest import xml
from test_interactive_shell import Input
from test_output_ux import Terminal
from v1_fixtures import add, database


@pytest.mark.parametrize('key,top', [('DOWN', 1), ('j', 1), ('\r', 1), ('\n', 1),
                                    (' ', 4), ('PAGEDOWN', 4), ('END', 8), ('G', 8),
                                    ('UP', 0), ('k', 0), ('PAGEUP', 0), ('b', 0), ('HOME', 0), ('g', 0)])
def test_pager_navigation(key, top):
    pager = output.Pager([str(i) for i in range(11)])
    pager.resize(4, 80)
    assert pager.visible == ['0', '1', '2', '3']
    assert pager.footer == 'Lines 1-4 of 11 | Up Down PgUp PgDn Home End Q'
    assert pager.move(key) and pager.top == top
    assert pager.move('HOME') and pager.top == 0
    for _ in range(20):
        pager.move('DOWN')
    assert pager.top == 10 and pager.visible == ['10']
    pager.move('UP')
    assert pager.top == 9
    pager.move('PAGEUP')
    assert pager.top == 5
    pager.move('k')
    assert pager.top == 4
    pager.move('b')
    assert pager.top == 0


@pytest.mark.parametrize('key', ['q', 'Q', '\x1b', '\x03', '\x04', '\x1a', ''])
def test_pager_quit(key):
    pager = output.Pager(['one'])
    pager.resize(3, 80)
    assert not pager.move(key) and pager.top == 0


def test_pager_empty_short_page_wrapping_and_resize():
    pager = output.Pager([])
    pager.resize(0, 0)
    assert pager.visible == [] and pager.footer.startswith('Lines 0-0 of 0')
    assert pager.move('END') and pager.top == 0
    pager = output.Pager(['abcdef', 'two', 'three'])
    pager.resize(10, 80)
    assert pager.visible == pager.original
    pager.resize(2, 80)
    pager.move('PAGEDOWN')
    assert pager.visible == ['three'] and pager.footer.startswith('Lines 3-3 of 3')
    pager.resize(2, 3)
    assert pager.lines == ['abc', 'def', 'two', 'thr', 'ee']
    pager.move('END')
    assert pager.visible == ['ee']
    pager.resize(50, 80)
    assert pager.top == 2 and pager.visible == ['three']


@pytest.mark.parametrize('virtual,expected', [(38, 'UP'), (40, 'DOWN'), (33, 'PAGEUP'), (34, 'PAGEDOWN'),
                                             (36, 'HOME'), (35, 'END'), (27, '\x1b')])
def test_windows_pager_keys_without_console(virtual, expected):
    key = SimpleNamespace(virtual=virtual, char=SimpleNamespace(unicode='\x1b' if virtual == 27 else '\0'), down=True, repeat=2)
    source = console.WindowsKeys.__new__(console.WindowsKeys)
    source.remaining = 0
    source.handle = 0
    source.w = SimpleNamespace(DWORD=lambda: SimpleNamespace(value=0))
    source.ctypes = SimpleNamespace(byref=lambda value: value)
    source.Record = lambda: SimpleNamespace(kind=1, event=SimpleNamespace(key=key))
    def count(handle, value):
        value.value = 1
        return True
    source.kernel = SimpleNamespace(GetNumberOfConsoleInputEvents=count, ReadConsoleInputW=lambda *args: True)
    assert source.poll() == source.poll() == expected


@pytest.mark.parametrize('sequence,expected', [('\x1b[A', 'UP'), ('\x1b[B', 'DOWN'), ('\x1b[5~', 'PAGEUP'),
                                              ('\x1b[6~', 'PAGEDOWN'), ('\x1b[H', 'HOME'), ('\x1b[F', 'END'),
                                              ('\x1b', '\x1b'), ('j', 'j')])
def test_posix_pager_keys(sequence, expected):
    keys = list(sequence)
    assert output.terminal_key(lambda: keys.pop(0), lambda: bool(keys)) == expected


def test_pager_redraw_backwards_short_page_resize_and_cleanup(monkeypatch):
    monkeypatch.setattr(output.sys, 'stdout', Terminal())
    monkeypatch.setattr(output.sys, 'stdin', Terminal())
    sizes = iter([(40, 6), (40, 6), (40, 6), (20, 5), (40, 6)])
    monkeypatch.setattr(output.shutil, 'get_terminal_size', lambda **kw: os.terminal_size(next(sizes)))
    frames, restored = [], []
    monkeypatch.setattr(output, 'redraw_viewport', lambda lines, footer: frames.append((list(lines), footer)) or True)
    @contextmanager
    def keyboard():
        try:
            keys = iter(['PAGEDOWN', 'PAGEDOWN', 'UP', 'HOME', '\x1b'])
            yield lambda: next(keys)
        finally:
            restored.append(True)
    monkeypatch.setattr(output, 'keyboard', keyboard)
    output.page(io.StringIO(''.join(f'row{i}\n' for i in range(10))))
    assert [f[0] for f in frames] == [['row0', 'row1', 'row2', 'row3'], ['row4', 'row5', 'row6', 'row7'],
                                     ['row8', 'row9'], ['row7', 'row8', 'row9'], ['row0', 'row1', 'row2', 'row3']]
    assert frames[2][1].startswith('Lines 9-10 of 10') and restored == [True]


def test_viewport_erases_stale_rows_and_never_writes_controls_to_files(monkeypatch):
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    screen = Terminal()
    assert terminal.redraw_viewport(['long', 'page', 'of', 'text'], 'footer', screen)
    assert terminal.redraw_viewport(['short'], 'footer', screen)
    assert screen.getvalue().endswith('\x1b[Hshort\x1b[K\nfooter\x1b[J')
    file = io.StringIO()
    assert not terminal.redraw_viewport(['text'], 'footer', file) and not file.getvalue()


def test_pager_empty_and_nonterminal_never_read_keys(monkeypatch):
    def forbidden():
        raise AssertionError('No keyboard allowed')
    monkeypatch.setattr(output, 'keyboard', forbidden)
    for stream, text in [(Terminal(), ''), (io.StringIO(), 'one\ntwo\n')]:
        monkeypatch.setattr(output.sys, 'stdout', stream)
        monkeypatch.setattr(output.sys, 'stdin', Terminal())
        output.page(io.StringIO(text))
        assert stream.getvalue() == text


def tree():
    ids = ['EVTX:' + 'a' * 64 + ':' + str(i) for i in range(4)]
    nodes = [dict(id=eid, process_name=name, pid=i, hostname='synthetic', timestamp_utc=None)
             for i, (eid, name) in enumerate(zip(ids, ['root.exe', 'child.exe', 'grandchild.exe', 'sibling.exe']))]
    edges = [dict(source_id=ids[a], target_id=ids[b], status=status, reason='Synthetic supported relationship', limitations=[])
             for a, b, status in [(0, 1, 'CONFIRMED'), (1, 2, 'LIKELY'), (0, 3, 'LIKELY')]]
    return dict(nodes=nodes, relationships=edges, anchor_id=ids[1], limits=[], caution='Synthetic tree only',
                parameters=dict(pid_lookback_seconds=300, child_window_seconds=300, max_nodes=100, max_depth=8))


@pytest.mark.parametrize('unicode,branch,end,bar', [(True, '├── ', '└── ', '│   '), (False, '|-- ', '`-- ', '|   ')])
def test_process_connectors_metadata_and_semantic_styles(unicode, branch, end, bar):
    result = tree()
    before = deepcopy(result)
    text = analyst_display.render_process_tree(result, unicode=unicode)
    assert branch + 'child.exe  PID 1 [anchor]' in text
    assert bar + end + 'grandchild.exe  PID 2' in text
    assert end + 'sibling.exe  PID 3' in text
    assert '\n    ID: ' + result['nodes'][0]['id'] in text
    assert '\n' + bar + '    ID: ' + result['nodes'][1]['id'] in text
    assert bar + '    Parent relationship: CONFIRMED\n' + bar + '        Synthetic supported relationship' in text
    colored = analyst_display.render_process_tree(result, Palette(True), unicode=unicode)
    assert Palette(True)('success', 'CONFIRMED') in colored
    assert Palette(True)('warning', 'LIKELY') in colored
    assert Palette(True)('key', '[anchor]') in colored
    assert SGR.sub('', colored) == text and result == before
    assert all(r['id'] in text for r in result['nodes'])
    assert 'Maximum nodes: 100; maximum graph depth: 8' in text


def test_tree_encoding_fallback(monkeypatch):
    for encoding, connector in [('ascii', '`--'), ('utf-8', '└──')]:
        monkeypatch.setattr(terminal.sys, 'stdout', SimpleNamespace(encoding=encoding))
        assert connector in analyst_display.render_process_tree(tree())


@pytest.mark.parametrize('interactive', [True, False])
def test_bare_tree_targeted_guidance(interactive, capsys):
    parser = build_parser(interactive=interactive)
    with pytest.raises(InvalidArguments if interactive else SystemExit) as exc:
        parser.parse_args(['process-tree'])
    text = str(exc.value) if interactive else capsys.readouterr().err
    assert text.startswith('process-tree requires either:')
    assert '--evidence <process-creation evidence ID>' in text and '--process <name> --around <timestamp>' in text
    assert 'help process-tree' in text


def test_tree_missing_time_and_candidate_messages_do_not_mutate_json():
    with closing(database()) as db:
        args = build_parser().parse_args(['process-tree', '--process', 'absent.exe'])
        with pytest.raises(ValueError, match='Alternatively, use --evidence'):
            v1_cli.dispatch(db, args)
        args.around = '2026-09-15T14:30:00Z'
        result = v1_cli.dispatch(db, args)
        before = deepcopy(result)
        text = analyst_display.render_process_tree(result)
        assert 'No matching process-creation evidence' in text and '--evidence' not in text
        assert 'do not prove the process did not exist' in text
        assert result == before and result['reason'] == 'Select a unique process using --evidence'
    result = dict(status='UNRESOLVED', reason='Select a unique process using --evidence', total=2,
                  candidate_evidence_ids=['EVTX:' + 'a' * 64 + ':1', 'EVTX:' + 'b' * 64 + ':2'])
    text = analyst_display.render_process_tree(result)
    assert 'Multiple candidate process-creation records found.' in text and 'Select one using --evidence <ID>.' in text
    assert all(eid in text for eid in result['candidate_evidence_ids'])


@pytest.mark.parametrize('event_id', [4624, 4634, 4672, 4688])
def test_show_stored_logon_id_accounts_and_json(event_id):
    with closing(database()) as db:
        event = add(db, 1, event_id, data={'TargetLogonId': '0x0000000000018025', 'SubjectLogonId': '0x0000000000018025',
                    'TargetUserName': 'defaultuser0', 'TargetDomainName': 'DESKTOP-SDN1RPT', 'LogonType': '2',
                    'SubjectUserName': 'win-test$', 'SubjectDomainName': 'WORKGROUP',
                    'NewProcessName': r'C:\Windows\System32\process.exe'})
        record = get_evidence(db, event['id'])
        before = deepcopy(record)
        text = show_display.render(record)
        assert 'Logon ID: 0x0000000000018025' in text
        for key in ('username', 'subject_account', 'target_account'):
            if record.get(key):
                assert record[key] in text and record[key].replace('\\', '\\\\') not in text
        if record.get('process_name'):
            assert record['process_name'] in text
        serialized = json.dumps(record)
        assert json.loads(serialized) == record == before
        assert '\\\\' in serialized and '\x1b' not in serialized


def test_show_accounts_controls_unicode_and_no_raw_logon_fallback():
    record = dict(id='EVTX:synthetic:1', source_type='evtx', artifact_type='other',
                  username='DOM\\José\n\x1b[31m', context={'username': 'DOM\\Zoë'},
                  event_data_json=json.dumps([{'name': 'TargetLogonId', 'value': 'secret-raw-only'}]))
    text = show_display.render(record)
    assert 'DOM\\José\\n\\u001b[31m' in text and 'User: DOM\\Zoë' in text
    assert '\x1b' not in text and 'Logon ID:' not in text


def test_multi_file_summary_counts_and_individual_provenance(tmp_path, capsys):
    case = tmp_path / 'case.db'
    progress = creation.IngestionProgress()
    with closing(connect(case)) as db:
        for i in range(12):
            file = tmp_path / f'synthetic-{i}.evtx'
            file.write_bytes(f'synthetic bytes {i}'.encode())
            def reader(path):
                yield ParsedRecord(1, 1, xml(record_id=1))
                yield ParsedRecord(2, 2, xml(record_id=2))
                yield ParsedRecord(None, error='File header verification failed')
                if i < 3:
                    yield ParsedRecord(None, error='Validated chunks exceed declared count')
            result = ingest_file(db, file, reader=reader)
            progress(file, 'evtx', result)
            assert result['status'] == 'partial' and result['inserted'] == 2
        before_errors = [tuple(r) for r in db.execute('SELECT * FROM ingestion_errors ORDER BY id')]
        before_runs = [tuple(r) for r in db.execute('SELECT * FROM ingestion_runs ORDER BY id')]
    progress.finish()
    stored, runs, errors = creation.summarize(case)
    text = capsys.readouterr().out
    assert stored == 24 and runs == {'partial': 12} and errors == 15
    assert 'Evidence: 24 records | 15 errors' in text and 'File outcomes: 12 partial' in text
    assert text.count('File header verification failed') == 1 and '12 occurrences across 12 ingestion attempts' in text
    assert text.count('Validated chunks exceed declared count') == 1 and '3 occurrences across 3 ingestion attempts' in text
    with closing(connect(case)) as db:
        assert [tuple(r) for r in db.execute('SELECT * FROM ingestion_errors ORDER BY id')] == before_errors
        assert [tuple(r) for r in db.execute('SELECT * FROM ingestion_runs ORDER BY id')] == before_runs
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 24


@pytest.mark.parametrize('status,inserted,errors,role', [('complete', 5, 0, 'success'), ('partial', 5, 2, 'warning'),
                                                      ('partial', 0, 1, 'warning'), ('failed', 0, 1, 'error')])
def test_ingestion_fragment_styles(status, inserted, errors, role, capsys):
    seen = []
    def palette(style, text):
        seen.append((style, text))
        return text
    progress = creation.IngestionProgress(palette=palette)
    progress('synthetic.evtx', 'evtx', dict(status=status, inserted=inserted, duplicates=1, errors=errors))
    assert (role, status) in seen
    assert ('success' if inserted else 'secondary_text', f'{inserted} records') in seen
    assert ('error' if errors else 'secondary_text', f'{errors} errors') in seen
    assert all('synthetic.evtx' not in text for _, text in seen)


@pytest.mark.parametrize('count', [1, 2])
def test_case_confirmation_file_pluralization(tmp_path, monkeypatch, count):
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    target = tmp_path / 'case.db'
    monkeypatch.setattr(creation, 'preflight', lambda path: [(evidence / str(i), 'evtx') for i in range(count)])
    reader = Input(str(target), str(evidence), '', '', '', '', 'n')
    assert not creation.create(Shell(State(None), reader))
    assert any(f'Create case and ingest {count} file' + ('s' if count != 1 else '') + '?' in p for p in reader.prompts)
    assert not target.exists()


def test_pager_help_and_detection_wording(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(['process-tree', '--help'])
    text = capsys.readouterr().out
    assert 'Up/Down, PgUp/PgDn, Home/End, Q' in ' '.join(text.split()) and 'Space/Enter/Q' not in text
    from forensic_assistant.command_catalog import COMMANDS
    assert 'Show  evidence' not in COMMANDS['detections']


def test_posix_incomplete_escape_at_eof_is_bounded():
    keys = iter(['\x1b', '[', ''])
    assert output.terminal_key(lambda: next(keys), lambda: True) == 'UNKNOWN'


def test_legacy_redraw_fallback(monkeypatch):
    monkeypatch.setattr(terminal, 'capable', lambda stream: False)
    calls = []
    monkeypatch.setattr(terminal, 'clear_screen', lambda stream: calls.append(stream) or True)
    screen = Terminal()
    assert terminal.redraw_viewport(['plain'], 'footer', screen)
    assert calls == [screen] and screen.getvalue() == 'plain\nfooter'


def test_summary_groups_exact_stage_message_and_counts_attempts(tmp_path, capsys):
    case = tmp_path / 'case.db'
    with closing(connect(case)) as db, db:
        for run in range(2):
            run_id = db.execute("INSERT INTO ingestion_runs(source_file,started_utc,status,error_count) VALUES ('same.evtx','synthetic','partial',2)").lastrowid
            db.executemany('INSERT INTO ingestion_errors(run_id,stage,message) VALUES (?,?,?)',
                           [(run_id, 'parse', 'Repeated'), (run_id, 'parse', 'Repeated')])
        db.execute("INSERT INTO ingestion_errors(run_id,stage,message) VALUES (?, 'normalize','Repeated')", (run_id,))
        db.execute('UPDATE ingestion_runs SET error_count=3 WHERE id=?', (run_id,))
    creation.summarize(case)
    text = capsys.readouterr().out
    assert 'parse: Repeated — 4 occurrences across 2 ingestion attempts' in text
    assert 'normalize: Repeated — 1 occurrence across 1 ingestion attempt' in text
    with closing(connect(case)) as db:
        assert db.execute('SELECT count(*) FROM ingestion_errors').fetchone()[0] == 5


@pytest.mark.parametrize('errors', [False, True])
def test_partial_creation_final_wording_uses_actual_errors(tmp_path, monkeypatch, capsys, errors):
    file = tmp_path / 'synthetic.evtx'
    file.write_bytes(b'synthetic fixture')
    target = tmp_path / 'case.db'
    monkeypatch.setattr(creation, 'preflight', lambda path: [(file, 'evtx')])
    def ingest(db, args, progress):
        def reader(path):
            yield ParsedRecord(1, 1, xml(record_id=1))
            if errors:
                yield ParsedRecord(None, error='Synthetic limitation')
        result = ingest_file(db, file, reader=reader)
        # Exercise a non-error partial outcome independently of current parser policy.
        result['status'] = 'partial'
        with db:
            db.execute("UPDATE ingestion_runs SET status='partial' WHERE id=?", (result['run_id'],))
        progress(file, 'evtx', result)
        return [result]
    monkeypatch.setattr(creation.v2_cli, 'ingest_sources', ingest)
    shell = Shell(State(None), Input(str(target), str(file), '', '', '', '', 'y'))
    assert creation.create(shell)
    text = capsys.readouterr().out
    outcome = 'errors/limitations' if errors else 'limitations'
    assert f'Ingestion completed with {outcome}; committed evidence retained.' in text
    assert shell.active == target


def test_repeated_result_limitations_deferred_and_preserved(capsys):
    progress = creation.IngestionProgress()
    result = dict(status='partial', inserted=1, duplicates=0, errors=0, limitation='Synthetic caveat')
    for i in range(3):
        progress(str(i), 'evtx', result)
    assert 'Synthetic caveat' not in capsys.readouterr().out
    progress.finish()
    text = capsys.readouterr().out
    assert text.count('Synthetic caveat') == 1 and '3 result occurrences' in text
    progress.finish()
    assert not capsys.readouterr().out


def test_service_installation_account_uses_literal_backslashes():
    record = dict(id='EVTX:synthetic:1', source_type='evtx', artifact_type='service',
                  provider='Service Control Manager', channel='System', event_id=7045,
                  event_data_json=json.dumps([{'name': 'AccountName', 'value': r'DOMAIN\service-user'}]))
    text = show_display.render(record)
    assert r'Account: DOMAIN\service-user' in text and r'DOMAIN\\service-user' not in text

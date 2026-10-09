"""Synthetic 6.34 CLI/presentation checks; no manual evidence is accessed."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
import re

import pytest

from forensic_assistant import activity, terminal, v2_cli
from forensic_assistant.artifacts.ingest import discover
from forensic_assistant.artifacts.registry_logs import CLASSIFIER
from forensic_assistant.cli import build_parser, main
from forensic_assistant.command_catalog import COMMANDS
from forensic_assistant.database.db import connect
from forensic_assistant.interactive import completion, creation
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.retrieval import search_display
from forensic_assistant.retrieval.registry_display import DIRTY_WARNING, KEY_CORRUPTION
from forensic_assistant.terminal import Palette, SGR
from test_interactive_shell import Input
from test_evtx_recovery import decode, chunk, file_bytes
from test_userassist import RAW_NAME, binary
from v2_fixtures import registry_file


def test_only_explicit_ingestion_commands_remain(capsys):
    expected = {'ingest-all', 'ingest-browser', 'ingest-evtx', 'ingest-mft', 'ingest-prefetch', 'ingest-registry'}
    assert {name for name in COMMANDS if name.startswith('ingest')} == expected
    assert set(completion.complete('ingest-', 7).candidates) == expected
    assert set(completion.complete('help ingest-', 12).candidates) == expected
    with pytest.raises(SystemExit) as exc:
        main(['ingest', 'unused'])
    assert exc.value.code == 2
    assert not re.search(r'\bingest(?=[,}\s])', build_parser().format_help())
    root = Path(__file__).resolve().parents[1]
    for name in ('README.md', 'addendum.md'):
        assert not re.search(r'`ingest`|cli ingest\s|\.db ingest\s', (root / name).read_text(encoding='utf-8'))


def test_evtx_discovery_preserves_damaged_and_renamed_attempts(tmp_path, decode, capsys):
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    damaged = evidence / 'damaged.EVTX'
    renamed = evidence / 'renamed.bin'
    valid = evidence / 'valid.evtx'
    damaged.write_bytes(b'not an EVTX header')
    renamed.write_bytes(file_bytes([chunk([21])]))
    valid.write_bytes(file_bytes([chunk([22])]))
    (evidence / 'ignore.txt').write_bytes(b'not evidence')
    assert {p for p, kind in discover(evidence, 'evtx')} == {damaged, renamed, valid}
    assert list(discover(damaged, 'evtx')) == [(damaged, 'evtx')]
    before = {p: p.read_bytes() for p in evidence.iterdir()}
    case = tmp_path / 'case.db'
    assert main(['--db', str(case), 'ingest-evtx', str(evidence), '--json']) == 1
    result = json.loads(capsys.readouterr().out)
    assert sum(r['inserted'] for r in result['results']) == 2
    failed = next(r for r in result['results'] if Path(r['source_file']).name == damaged.name)
    # The unchanged parser yields a header diagnostic, producing a partial run.
    assert failed['status'] == 'partial' and failed['inserted'] == 0 and failed['errors'] > 0
    with closing(connect(case)) as db:
        assert db.execute('SELECT count(*) FROM ingestion_runs').fetchone()[0] == 3
        assert {r[0] for r in db.execute('SELECT record_id FROM events')} == {21, 22}
        assert db.execute('SELECT count(*) FROM ingestion_errors').fetchone()[0] > 0
    assert all(p.read_bytes() == data for p, data in before.items())


def test_evtx_discovery_keeps_directory_link_exclusions(tmp_path, monkeypatch):
    link = tmp_path / 'linked.evtx'
    regular = tmp_path / 'ordinary.evtx'
    for path in (link, regular):
        path.write_bytes(b'broken')
    original = Path.is_symlink
    monkeypatch.setattr(Path, 'is_symlink', lambda p: p == link or original(p))
    assert list(discover(tmp_path, 'evtx')) == [(regular, 'evtx')]


def example(kind, index):
    if kind == 'mft':
        from test_mft_presentation import example as fixture
        record = fixture()
    elif kind == 'prefetch':
        from test_prefetch_presentation import record as fixture
        record = fixture()
    else:
        record = dict(source_type=kind, artifact_type={'evtx': 'process', 'registry': 'registry_value',
                      'browser': 'browser_visit'}[kind], timestamp_utc='2020-01-01T00:00:00.000000000Z',
                      context={}, detail={}, warnings=[], event_id=4688, process_name='cmd.exe')
        if kind == 'registry':
            record['detail'] = dict(key_path=r'Software\Example', value_name=f'coreupdater{index}.exe', value_type=1)
        elif kind == 'browser':
            record['detail'] = dict(browser_product='chrome', profile='Default', title='Synthetic', url='https://example.com/')
    record['id'] = kind.upper() + ':' + str(index) * 64 + ':SyntheticOffset:' + str(index)
    record['warnings'] = []
    return record


@pytest.mark.parametrize('kind', ['evtx', 'mft', 'prefetch', 'registry', 'browser'])
@pytest.mark.parametrize('width', [45, 200])
@pytest.mark.parametrize('color', [False, True])
def test_every_search_id_is_full_and_with_its_row(kind, width, color):
    result = dict(records=[example(kind, i) for i in (1, 2)], total=2)
    before = deepcopy(result)
    text = SGR.sub('', search_display.render(result, Palette(color), ids=True, width=width))
    second_row = re.search(r'(?m)^(?:#:\s*2\s*$|2\s+)', text)
    assert second_row, text
    first, second = (r['id'] for r in result['records'])
    assert text.index('ID: ' + first) < second_row.start() < text.index('ID: ' + second)
    assert text.count(first) == text.count(second) == 1
    assert not re.search(r'(?m)^\d+: (EVTX|MFT|PREFETCH|REGISTRY|BROWSER):', text)
    compact = search_display.render(result, ids=False, width=width)
    assert first not in compact and second not in compact
    assert result == before


def test_registry_coreupdater_cli_grouping_and_json_unchanged(tmp_path, capsys):
    import codecs
    hive = registry_file(tmp_path / 'NTUSER.DAT', dirty=True,
                         userassist=[(RAW_NAME, 3, binary()),
                                     (codecs.encode(r'C:\Other\coreupdater.exe', 'rot_13'), 3, binary())],
                         userassist_version=5)
    case = tmp_path / 'case.db'
    assert main(['--db', str(case), 'ingest-registry', str(hive)]) == 0
    capsys.readouterr()
    args = ['--db', str(case), 'search', '--artifact', 'registry', '--value-name-contains', 'coreupdater']
    assert main(args + ['--json']) == 0
    expected = json.loads(capsys.readouterr().out)
    assert len(expected['records']) == 2
    assert main(args + ['--ids']) == 0
    text = capsys.readouterr().out
    first, second = [r['id'] for r in expected['records']]
    assert text.index('ID: ' + first) < text.index('ID: ' + second)
    assert text.count(DIRTY_WARNING) == 1 and 'Dirty does not mean corrupted.' in text
    assert main(args + ['--json']) == 0
    assert json.loads(capsys.readouterr().out) == expected
    assert all(DIRTY_WARNING in r['warnings'] for r in expected['records'])


def test_registry_shared_notes_and_specific_anomalies_stay_separate():
    records = [example('registry', i) for i in (1, 2)]
    for record in records:
        record.update(file_sha256='a' * 64, source_file=r'C:\Evidence\SYSTEM', warnings=[DIRTY_WARNING])
    records[0]['warnings'] += [KEY_CORRUPTION, KEY_CORRUPTION, 'Only first record']
    records[0]['context']['conflicts'] = ['hostname']
    result = dict(records=records, total=2)
    before = deepcopy(result)
    text = search_display.render(result, ids=True, width=200)
    assert text.index(records[0]['id']) < text.index('Only first record') < text.index(records[1]['id'])
    assert text.index(records[0]['id']) < text.index('Conflicting context: hostname') < text.index(records[1]['id'])
    assert text.count('Parser flagged possible key corruption') == 1
    assert text.count(DIRTY_WARNING) == 1 and text.count('Forensic notes') == 1
    assert 'C:\\Evidence' not in text
    records[1]['file_sha256'] = 'b' * 64
    split = search_display.render(result, ids=True, width=200)
    assert split.count(DIRTY_WARNING) == 2 and 'a' * 64 in split and 'b' * 64 in split
    records[1]['file_sha256'] = 'a' * 64
    assert result == before


def test_case_open_precedes_session_and_failed_activation_has_neither(tmp_path, monkeypatch):
    first, other = tmp_path / 'first.db', tmp_path / 'other.db'
    for path in (first, other):
        connect(path).close()
    shell = Shell(State(None), Input())
    shell.activate(first)
    events = activity.inspect(activity.sidecar(first))
    assert events['valid']
    assert [(r['action'], r['sequence']) for r in events['records']] == [('CASE_OPEN', 1), ('SESSION_START', 2)]
    def failed(*args):
        raise OSError('synthetic final open failure')
    monkeypatch.setattr('forensic_assistant.interactive.case.open_existing', failed)
    with pytest.raises(OSError):
        shell.activate(other)
    assert shell.active == first and shell.audit.started
    assert not activity.sidecar(other).exists()
    assert activity.inspect(activity.sidecar(first)) == events


@pytest.mark.parametrize('errors', [False, True])
@pytest.mark.parametrize('color,capable', [(True, True), (False, True), (True, False)])
def test_registry_creation_groups_companions_and_respects_color(tmp_path, capsys, monkeypatch, errors, color, capable):
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    # Alphabetical order intersperses a companion before the final successful hive.
    registry_file(evidence / 'A-HIVE')
    registry_file(evidence / 'Z-HIVE', target=r'C:\Other\app.exe')
    for name in ('A-HIVE.LOG1', 'Z-HIVE.LOG2'):
        (evidence / name).write_bytes(b'regf' + bytes(80))
    if errors:
        (evidence / 'BAD-HIVE').write_bytes(b'regf' + bytes(100))
    original = {p: p.read_bytes() for p in evidence.iterdir()}
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setattr(terminal, 'capable', lambda stream: capable)
    case = tmp_path / 'case.db'
    reader = Input(str(case), str(evidence), '', '', '', '', 'y')
    shell = Shell(State(None), reader, no_color=not color)
    assert creation.create(shell)
    raw = capsys.readouterr().out
    text = SGR.sub('', raw)
    assert ('\x1b[' in raw) == (color and capable)
    assert text.index('Z-HIVE   ') < text.index('Skipped companion transaction logs:')
    assert text.count('Skipped companion transaction logs:') == 1
    assert text.count('Registry transaction-log replay is not supported') == 1
    assert text.count('A-HIVE.LOG1') == text.count('Z-HIVE.LOG2') == 1
    assert 'File outcomes: 2 unsupported' in text
    assert ('completed with errors/limitations' in text) == errors
    if not errors:
        assert 'completed with limitations;' in text and '| 0 errors' in text
    with closing(connect(case)) as db:
        assert db.execute("SELECT count(*) FROM ingestion_runs WHERE status='unsupported'").fetchone()[0] == 2
        count = db.execute('SELECT coalesce(sum(error_count),0) FROM ingestion_runs').fetchone()[0]
        assert (count > 0) == errors
    audit = activity.inspect(activity.sidecar(case), 1000)
    assert audit['valid'] and '\x1b' not in activity.sidecar(case).read_text()
    actions = [e['action'] for e in audit['records']]
    assert actions[0] == 'CASE_CREATE' and actions.index('INGEST') < actions.index('CASE_OPEN') < actions.index('SESSION_START')
    assert all(p.read_bytes() == data for p, data in original.items())
    exported = tmp_path / 'status.json'
    assert main(['--db', str(case), 'status', '--json', '--output', str(exported)]) == 0
    assert '\x1b' not in exported.read_text() and json.loads(exported.read_text())


def test_creation_progress_semantic_styles(capsys):
    seen = []
    def palette(role, text):
        seen.append((role, text))
        return text
    progress = creation.IngestionProgress(palette=palette)
    progress('good', 'registry', dict(status='complete', inserted=10, duplicates=0, errors=0))
    progress('bad', 'registry', dict(status='failed', inserted=0, duplicates=0, errors=1))
    progress('good.LOG1', 'registry', dict(status='unsupported', inserted=0, duplicates=0, errors=0, parser=CLASSIFIER))
    progress.finish()
    assert any(role == 'success' and '10 records' in text for role, text in seen)
    assert any(role == 'error' and '1 errors' in text for role, text in seen)
    assert ('key', 'Skipped companion transaction logs:') in seen
    assert any(role == 'warning' and 'replay is not supported' in text for role, text in seen)

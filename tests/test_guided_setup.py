"""Synthetic Windows trees only; exercise plan approval and shared ingestion."""
from collections import Counter
from contextlib import closing
from pathlib import Path
import hashlib
import os
import subprocess

import pytest

from forensic_assistant import activity, v2_cli
from forensic_assistant.database.db import connect
from forensic_assistant.interactive import creation, discovery, setup
from forensic_assistant.interactive.shell import Shell, Mode
from forensic_assistant.interactive.state import State
from forensic_assistant.investigation_ai.lifecycle import CleanupError
from test_interactive_shell import Input, case
from test_browser_parser import history
from v2_fixtures import mft_file, prefetch_file, registry_file


def tree(root):
    for relative in ('Windows/System32/config', 'Windows/System32/winevt/Logs', 'Windows/Prefetch',
                     'Users/alice/AppData/Local/Microsoft/Windows',
                     'Users/alice/AppData/Local/Google/Chrome/User Data/Default',
                     'Users/alice/AppData/Local/Microsoft/Edge/User Data/Profile 1'):
        (root / relative).mkdir(parents=True)
    mft_file(root / '$MFT')
    for name in ('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY'):
        registry_file(root / 'Windows/System32/config' / name)
    registry_file(root / 'Users/alice/NTUSER.DAT')
    registry_file(root / 'Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat')
    (root / 'Windows/System32/config/SYSTEM.LOG1').write_bytes(b'HvLE' + bytes(84))
    prefetch_file(root / 'Windows/Prefetch/TEST.EXE-1234.pf')
    (root / 'Windows/System32/winevt/Logs/System.evtx').write_bytes(b'damaged synthetic EVTX')
    for path in root.glob('Users/*/AppData/Local/*/*/User Data/*'):
        history(path / 'History').close()
    (root / 'pagefile.sys').write_bytes(b'synthetic unsupported')
    return root


def snapshot(root):
    return {str(p.relative_to(root)): (p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
            for p in root.rglob('*') if p.is_file()}


def prefix(target, *, missing=False, metadata=('', '', '', '')):
    return ['Synthetic case', str(target), *(['yes'] if missing else []), 'LAB-01', *metadata]


def test_targeted_inventory_is_readonly_and_never_walks_arbitrary_tree(tmp_path, monkeypatch):
    root = tree(tmp_path / 'root')
    unrelated = root / 'unrelated/deep/subtree'
    unrelated.mkdir(parents=True)
    mft_file(unrelated / 'extra-mft')
    before = snapshot(root)
    original = Path.iterdir
    def guarded(path):
        assert 'unrelated' not in path.parts
        return original(path)
    monkeypatch.setattr(Path, 'iterdir', guarded)
    monkeypatch.setattr(os, 'walk', lambda *a, **kw: pytest.fail('Full recursive discovery'))
    found = discovery.scan(root)
    assert Counter(i.kind for i in found.candidates) == dict(mft=1, registry=7, prefetch=1, evtx=1, browser=2)
    assert Counter(i.group for i in found.candidates if i.kind == 'registry') == {
        'system hive': 4, 'user hive': 2, 'companion': 1}
    assert {i.group for i in found.candidates if i.kind == 'browser'} == {'Chrome location', 'Edge location'}
    assert any('pagefile.sys' in n and 'Not currently supported' in n for n in found.notes)
    monkeypatch.setattr(Path, 'iterdir', original)
    assert snapshot(root) == before


def test_windows_root_detection_exact_parent_multiple_and_depth_limit(tmp_path):
    first = tree(tmp_path / 'a')
    second = tree(tmp_path / 'b')
    assert discovery.windows_roots(first)[0] == [first]
    assert discovery.windows_roots(tmp_path)[0] == [first, second]
    nested = tmp_path / 'container/deep/more/root'
    tree(nested)
    assert discovery.windows_roots(tmp_path / 'container')[0] == []


@pytest.mark.parametrize('suffix', ['.E01', '.raw', '.dd', '.img', '.vhd', '.vhdx'])
def test_images_rejected_in_scan_and_manual(tmp_path, suffix):
    file = tmp_path / ('disk' + suffix)
    file.write_bytes(b'FILE' + bytes(100))
    for fn in (discovery.windows_roots, lambda p: discovery.manual(p, 'mft')):
        with pytest.raises(ValueError, match='does not currently mount disk images'):
            fn(file)


def test_junction_cannot_be_followed(tmp_path):
    root = tree(tmp_path / 'root')
    link = root / 'Users/loop'
    if os.name == 'nt':
        result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(root)], capture_output=True)
        assert result.returncode == 0, result.stderr
    else:
        link.symlink_to(root, target_is_directory=True)
    try:
        found = discovery.scan(root)
        assert not any('loop' in i.path.parts for i in found.candidates)
        assert any('loop' in n for n in found.notes)
        with pytest.raises(ValueError, match='redirection'):
            discovery.input_path(link)
    finally:
        if os.name == 'nt':
            link.rmdir()  # Remove junction only, never its target.
        else:
            link.unlink()


def test_discovery_limits_fail_explicitly(tmp_path, monkeypatch):
    tree(tmp_path / 'root')
    monkeypatch.setattr(discovery, 'MAX_ENTRIES', 1)
    with pytest.raises(ValueError, match='entry limit'):
        discovery.scan(tmp_path / 'root')
    monkeypatch.setattr(discovery, 'MAX_ROOT_DIRECTORIES', 0)
    with pytest.raises(ValueError, match='root search limit'):
        discovery.windows_roots(tmp_path)


@pytest.mark.parametrize('choice,expected', [('all', {'mft', 'evtx', 'browser'}),
                                           ('mft,evtx', {'mft', 'evtx'}), ('', {'mft', 'evtx', 'browser'})])
def test_category_selection(choice, expected):
    assert setup.select_categories(choice, ['mft', 'evtx', 'browser']) == expected
    with pytest.raises(ValueError):
        setup.select_categories('typo', ['mft'])


def test_collect_requires_root_choice_and_category_confirmation(tmp_path, capsys):
    first = tree(tmp_path / 'evidence/a')
    second = tree(tmp_path / 'evidence/b')
    target = tmp_path / 'case.db'
    shell = Shell(State(None), Input(*prefix(target), '1', str(first.parent), '2', 'review', 'mft,registry', 'yes'))
    plan = setup.collect(shell)
    assert {i.kind for i in plan.items} == {'mft', 'registry'}
    assert all(i.path.is_relative_to(second) for i in plan.items)
    assert plan.metadata == dict(name=None, hostname=None, username=None, volume_root=None)
    assert not target.exists()
    text = capsys.readouterr().out
    assert 'Multiple Windows roots' in text and '3. Generate a report' in text
    assert 'Proposed ingestion' in text and str(second / '$MFT') in text


@pytest.mark.parametrize('cancel', ['n', 'cancel', KeyboardInterrupt(), EOFError()])
def test_cancel_final_confirmation_no_files_created(tmp_path, cancel):
    root = tree(tmp_path / 'root')
    target = tmp_path / 'new/case.db'
    shell = Shell(State(None), Input(*prefix(target, missing=True), '1', str(root), 'mft', cancel))
    assert not setup.create(shell)
    assert not target.parent.exists() and not shell.state.recent


def test_cancel_category_no_files_and_preserves_active_mode(tmp_path):
    root = tree(tmp_path / 'root')
    target = tmp_path / 'new.db'
    shell = Shell(State(None), Input(*prefix(target), '1', str(root), 'cancel'))
    old = case(tmp_path, 'old.db')
    shell.activate(old)
    shell.mode = Mode.AI
    assert not setup.create(shell) and shell.active == old and shell.mode is Mode.AI
    assert not target.exists()


def test_empty_setup_uses_initializer_no_source_and_starts_expert(tmp_path, monkeypatch, capsys):
    target = tmp_path / 'new/case.db'
    shell = Shell(State(None), Input(*prefix(target, missing=True), '3', 'yes'))
    shell.mode = Mode.AI
    original = creation.initialize
    calls = []
    def initialize(*args, **kw):
        calls.append(args[0])
        return original(*args, **kw)
    monkeypatch.setattr(creation, 'initialize', initialize)
    monkeypatch.setattr(v2_cli, 'ingest_sources', lambda *a, **k: pytest.fail('Empty ingestion'))
    assert setup.create(shell) and shell.active == target and shell.mode is Mode.EXPERT
    assert calls == [target] and shell.state.recent == [str(target)]
    with closing(connect(target, existing_only=True)) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 5
        assert db.execute('SELECT count(*) FROM sources').fetchone()[0] == 0
    audit = activity.inspect(activity.sidecar(target), 100)
    assert audit['valid'] and 'Synthetic case' in str(audit) and 'LAB-01' in str(audit)
    assert 'Skipped (empty case)' in capsys.readouterr().out


def test_real_mixed_ingestion_partial_retention_metadata_and_ids(tmp_path, capsys):
    root = tree(tmp_path / 'root')
    before = snapshot(root)
    target = tmp_path / 'case.db'
    shell = Shell(State(None), Input(*prefix(target, metadata=('Examiner source', 'HOST-A', 'AnalystUser', 'C:')),
                                   '1', str(root), 'all', 'chrome', 'Default', 'edge', 'Profile 1', 'yes'))
    assert setup.create(shell)
    assert shell.active == target and shell.mode is Mode.EXPERT
    assert snapshot(root) == before
    with closing(connect(target, existing_only=True)) as db:
        assert {r[0] for r in db.execute('SELECT DISTINCT source_type FROM evidence_records')} == {'mft', 'registry', 'prefetch', 'browser'}
        source = dict(db.execute('SELECT * FROM source_assertions').fetchone())
        assert source['basis'] == 'analyst-supplied'
        assert source['hostname'] == 'host-a' and source['username'] == 'AnalystUser'
        assert db.execute('SELECT count(*) FROM sources').fetchone()[0] == 1
        assert db.execute('SELECT count(*) FROM ingestion_runs').fetchone()[0] == 12
        evtx_run = db.execute('SELECT status,inserted_count,error_count FROM ingestion_runs WHERE source_file=?',
                              (str(root / 'Windows/System32/winevt/Logs/System.evtx'),)).fetchone()
        # The unchanged EVTX pipeline records even a truncated header as partial.
        assert tuple(evtx_run) == ('partial', 0, 1)
        before_ids = {r[0] for r in db.execute('SELECT evidence_id FROM evidence_records WHERE source_type="mft"')}
        from forensic_assistant.cli import build_parser
        result = v2_cli.ingest_sources(db, build_parser().parse_args(['ingest-mft', str(root / '$MFT'), '--source', source['source_id']]))
        assert result[0]['duplicates'] and not result[0]['inserted']
        assert before_ids == {r[0] for r in db.execute('SELECT evidence_id FROM evidence_records WHERE source_type="mft"')}
    text = capsys.readouterr().out
    assert 'evtx: failed' in text and 'Case ready.' in text
    assert 'Completed with limitations' in text
    assert activity.inspect(activity.sidecar(target))['valid']


def test_manual_evtx_registry_reuses_exact_shared_calls(tmp_path, monkeypatch):
    root = tree(tmp_path / 'root')
    target = tmp_path / 'case.db'
    evtx = root / 'Windows/System32/winevt/Logs/System.evtx'
    hive = root / 'Windows/System32/config/SYSTEM'
    calls = []
    original = v2_cli.ingest_sources
    def ingest(db, args, progress):
        calls.append((args.command, args.path))
        return original(db, args, progress)
    monkeypatch.setattr(v2_cli, 'ingest_sources', ingest)
    shell = Shell(State(None), Input(*prefix(target), '2', 'evtx', str(evtx), 'registry', str(hive), '', 'all', 'yes'))
    assert setup.create(shell)
    assert calls == [('ingest-registry', hive), ('ingest-evtx', evtx)]


def test_folder_manual_signatures_and_browser_candidates(tmp_path):
    root = tree(tmp_path / 'root')
    assert len(discovery.manual(root / 'Windows/Prefetch', 'prefetch').candidates) == 1
    assert len(discovery.manual(root / 'Windows/System32/config', 'registry').candidates) == 5
    assert len(discovery.manual(root / 'Users/alice/AppData/Local/Google/Chrome', 'browser').candidates) == 1


def test_excluded_category_never_dispatched(tmp_path, monkeypatch):
    root = tree(tmp_path / 'root')
    target = tmp_path / 'case.db'
    calls = []
    original = v2_cli.ingest_sources
    def ingest(db, args, progress):
        assert args.command == 'ingest-mft'
        calls.append(args.path)
        return original(db, args, progress)
    monkeypatch.setattr(v2_cli, 'ingest_sources', ingest)
    shell = Shell(State(None), Input(*prefix(target), '1', str(root), 'mft', 'yes'))
    assert setup.create(shell) and calls == [root / '$MFT']


@pytest.mark.parametrize('error', [KeyboardInterrupt(), CleanupError('Unconfirmed cleanup')])
def test_interruption_keeps_committed_work_and_old_case(tmp_path, monkeypatch, error, capsys):
    root = tree(tmp_path / 'root')
    target = tmp_path / 'new/case.db'
    shell = Shell(State(None), Input(*prefix(target, missing=True), '1', str(root), 'mft,registry', 'yes'))
    old = case(tmp_path, 'old.db')
    shell.activate(old)
    original = v2_cli.ingest_sources
    def ingest(db, args, progress):
        if args.command == 'ingest-registry':
            raise error
        return original(db, args, progress)
    monkeypatch.setattr(v2_cli, 'ingest_sources', ingest)
    if isinstance(error, CleanupError):
        with pytest.raises(CleanupError):
            setup.create(shell)
    else:
        assert not setup.create(shell)
    assert shell.active == old and shell.state.recent == [str(old)] and target.exists()
    with closing(connect(target, existing_only=True)) as db:
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] > 0
    assert 'not rolled back' in capsys.readouterr().out


def test_failed_category_does_not_prevent_later_success(tmp_path, monkeypatch, capsys):
    root = tree(tmp_path / 'root')
    target = tmp_path / 'case.db'
    original = v2_cli.ingest_sources
    def ingest(db, args, progress):
        if args.command == 'ingest-mft':
            raise OSError('synthetic read failure')
        return original(db, args, progress)
    monkeypatch.setattr(v2_cli, 'ingest_sources', ingest)
    shell = Shell(State(None), Input(*prefix(target), '1', str(root), 'mft,prefetch', 'yes'))
    assert setup.create(shell)
    text = capsys.readouterr().out
    assert 'mft: failed' in text and 'prefetch: complete' in text


def test_readonly_destination_and_repeat_limitations(tmp_path):
    root = tree(tmp_path / 'root')
    for selection in (root, root / '$MFT'):
        with pytest.raises(ValueError, match='outside every evidence directory'):
            setup.outside_evidence(root / 'new.db', [selection])
    progress = setup.Progress()
    for _ in range(5):
        progress(None, 'registry', dict(status='unsupported', inserted=0, duplicates=0, errors=0, limitation='No replay'))
    assert progress.outcome == 'skipped' and progress.limitations == {'No replay': 5}


def test_help_completion_and_shell_entry(tmp_path, monkeypatch, capsys):
    from forensic_assistant.interactive.help import command_help
    from forensic_assistant.interactive.completion import complete
    assert 'mounted/extracted' in command_help('new-case')
    assert 'confirm' in command_help('new-case')
    assert complete('new-c', 5).text.startswith('new-case')
    calls = []
    monkeypatch.setattr(setup, 'create', lambda shell: calls.append(shell) or False)
    old = case(tmp_path)
    shell = Shell(State(None), Input(str(old), 'new-case', 'exit'))
    assert shell.run() == 0 and calls == [shell]
    assert shell.active == old


@pytest.mark.parametrize('answer,activated', [('yes', True), ('n', False)])
def test_zero_record_failure_needs_explicit_activation(tmp_path, answer, activated, capsys):
    root = tree(tmp_path / 'root')
    target = tmp_path / 'case.db'
    shell = Shell(State(None), Input(*prefix(target), '1', str(root), 'evtx', 'yes', answer))
    assert setup.create(shell) == activated
    assert target.exists()
    assert (shell.active == target) == activated
    assert shell.state.recent == ([str(target)] if activated else [])
    assert 'no evidence records were stored' in capsys.readouterr().out


def test_required_audit_failure_stops_further_ingestion(tmp_path, monkeypatch):
    root = tree(tmp_path / 'root')
    target = tmp_path / 'case.db'
    calls = []
    def fail(db, args, progress):
        calls.append(args.command)
        raise activity.AuditError('Synthetic audit failure')
    monkeypatch.setattr(v2_cli, 'ingest_sources', fail)
    shell = Shell(State(None), Input(*prefix(target), '1', str(root), 'mft,prefetch', 'yes'))
    assert not setup.create(shell)
    assert calls == ['ingest-mft'] and shell.active is None and target.exists()


def test_no_late_discovery_or_filename_inference(tmp_path):
    root = tree(tmp_path / 'root')
    target = tmp_path / 'case.db'
    def confirm():
        prefetch_file(root / 'Windows/Prefetch/ADDED-LATER.pf')
        return 'yes'
    shell = Shell(State(None), Input(*prefix(target), '1', str(root), 'prefetch', confirm))
    assert setup.create(shell)
    with closing(connect(target, existing_only=True)) as db:
        assert db.execute('SELECT count(*) FROM ingestion_runs').fetchone()[0] == 1
        assertion = dict(db.execute('SELECT * FROM source_assertions').fetchone())
        assert assertion['hostname'] is assertion['username'] is assertion['volume_root'] is None
        assert assertion['display_name'].startswith('Source ')


def test_duplicate_manual_selection_only_ingested_once(tmp_path):
    root = tree(tmp_path / 'root')
    target = tmp_path / 'case.db'
    shell = Shell(State(None), Input(*prefix(target), '2', 'mft', str(root / '$MFT'),
                                   'mft', str(root / '$MFT'), '', 'all', 'yes'))
    assert setup.create(shell)
    with closing(connect(target, existing_only=True)) as db:
        assert db.execute('SELECT count(*) FROM ingestion_runs').fetchone()[0] == 1


def test_destination_race_preserves_other_file(tmp_path, monkeypatch):
    target = tmp_path / 'case.db'
    initialize = creation.initialize
    def race(path, *args, **kw):
        path.write_bytes(b'other analyst data')
        return initialize(path, *args, **kw)
    monkeypatch.setattr(creation, 'initialize', race)
    shell = Shell(State(None), Input(*prefix(target), '3', 'yes'))
    assert not setup.create(shell)
    assert target.read_bytes() == b'other analyst data'
    assert not activity.sidecar(target).exists()


def test_missing_directory_decline_and_initialization_failure(tmp_path, monkeypatch):
    target = tmp_path / 'new/case.db'
    shell = Shell(State(None), Input('Test', str(target), 'no', 'cancel'))
    assert not setup.create(shell) and not target.parent.exists()
    def fail(*args, **kwargs):
        raise OSError('Synthetic init failure')
    monkeypatch.setattr(creation, 'connect', fail)
    shell = Shell(State(None), Input(*prefix(target, missing=True), '3', 'yes'))
    assert not setup.create(shell) and target.parent.exists() and not target.exists()


def test_discovery_denied_directory_is_reported(tmp_path, monkeypatch):
    root = tree(tmp_path / 'root')
    original = Path.iterdir
    def denied(path):
        if path.name == 'Prefetch':
            raise PermissionError('Synthetic access denial')
        return original(path)
    monkeypatch.setattr(Path, 'iterdir', denied)
    found = discovery.scan(root)
    assert not any(i.kind == 'prefetch' for i in found.candidates)
    assert any('could not be inspected' in note and 'Prefetch' in note for note in found.notes)

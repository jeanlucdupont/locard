"""Managed setup UX tests; generated fixtures, no mounted evidence mutation."""
from collections import Counter
from contextlib import closing
from dataclasses import replace
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensic_assistant import activity, terminal
from forensic_assistant.database.db import connect
from forensic_assistant.interactive import discovery, setup, setup_display, workspace, creation
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.terminal import Palette
from forensic_assistant.ingest.evtx import ingest_file
from test_interactive_shell import Input
from test_guided_setup import tree, snapshot
from test_evtx_recovery import chunk, file_bytes, decode


@pytest.fixture(autouse=True)
def environment(tmp_path, monkeypatch):
    monkeypatch.setattr(workspace, 'cases_root', lambda: tmp_path / 'cases')
    monkeypatch.setattr(workspace, 'elevated', lambda: True)


@pytest.mark.parametrize('name,expected', [
    ('My first case', 'My_first_case'),
    ('INC-2026-0042 - WS104 malware', 'INC-2026-0042_WS104_malware'),
    ('IR: June 15, 2026', 'IR_June_15_2026'), ('__A***  B__', 'A_B'),
    ('résumé 東京-2', 'résumé_東京-2'), ('CON', 'CON_case'), ('a/b\\c', 'a_b_c'),
    ('A-1', 'A-1'), ('LPT1', 'LPT1_case'),
])
def test_sanitization(name, expected):
    assert workspace.sanitize(name) == expected


@pytest.mark.parametrize('name', ['', '???', '..', '__', '---', 'x' * 101])
def test_invalid_case_name(name):
    with pytest.raises(ValueError):
        workspace.sanitize(name)


def test_managed_workspace_and_normal_prompts(tmp_path, capsys):
    reader = Input('', 'My first case', '', '', '3', '')
    shell = Shell(State(None), reader)
    assert setup.create(shell)
    root = tmp_path / 'cases/My_first_case'
    assert shell.active == root / 'case.db' and not hasattr(shell, 'mode')
    assert {p.name for p in root.iterdir()} == {'case.db', 'case.db.audit.jsonl', 'reports', 'exports', 'workspace'}
    assert all(not list((root / name).iterdir()) for name in ('reports', 'exports', 'workspace'))
    assert reader.prompts.count('Case name: ') == 2
    assert 'Analyst name (optional): ' in reader.prompts and 'Organization (optional): ' in reader.prompts
    assert not any(any(word in prompt for word in ('database path', 'identifier', 'Hostname', 'Username', 'volume root', 'Source display'))
                   for prompt in reader.prompts)
    assert not any('Enter cancels' in prompt for prompt in reader.prompts)
    text = capsys.readouterr().out
    assert 'A Locard investigation has three steps:' in text
    assert 'Case created. No evidence ingested.' in text and 'Case ready.' not in text
    assert 'Next steps' not in text and 'Use: report generate' not in text
    assert 'Prefix a natural-language request with !' in text


@pytest.mark.parametrize('answers', [('cancel',), ('Example', 'CANCEL'), ('Example', '', 'Cancel'),
                                    ('Example', '', '', 'cancel'), ('Example', '', '', '3', 'cancel')])
def test_cancel_consistent_and_no_files(tmp_path, answers):
    assert not setup.create(Shell(State(None), Input(*answers)))
    assert not (tmp_path / 'cases').exists()


def test_existing_workspace_and_race_never_reused(tmp_path):
    old = tmp_path / 'cases/Existing'
    old.mkdir(parents=True)
    (old / 'marker').write_bytes(b'original')
    shell = Shell(State(None), Input('Existing', 'Different', '', '', '3', 'yes'))
    assert setup.create(shell) and shell.active.parent.name == 'Different'
    assert (old / 'marker').read_bytes() == b'original'
    with pytest.raises(FileExistsError):
        workspace.initialize(old / 'case.db')
    assert not (old / 'case.db').exists()


def test_startup_one_is_guided_no_g(tmp_path, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(setup, 'create', lambda shell: calls.append(shell) or False)
    shell = Shell(State(None), Input('1', '3'))
    assert shell.run() == 0 and calls == [shell]
    text = capsys.readouterr().out
    assert '[1] Create a case\n[2] Open a case\n[3] Exit' in text
    assert '[G]' not in text and 'Guided case setup (new-case)' not in text


@pytest.mark.parametrize('elevated,answer,cancelled', [(True, None, False), (False, '2', False),
                                                   (False, '1', True), (False, '3', True)])
def test_privilege_guidance_without_elevation(monkeypatch, capsys, elevated, answer, cancelled):
    monkeypatch.setattr(workspace, 'elevated', lambda: elevated)
    calls = []
    def read(prompt):
        calls.append(prompt)
        return answer
    if cancelled:
        with pytest.raises(EOFError):
            setup.access_guidance(read, Palette())
    else:
        setup.access_guidance(read, Palette())
    text = capsys.readouterr().out
    assert bool(calls) == (not elevated)
    if not elevated:
        assert 'does not guarantee access' in text and 'Continue with limited discovery' in text


def test_access_limitations_aggregated_without_path_flood(tmp_path, capsys):
    inventory = discovery.Inventory()
    for n in range(50):
        inventory.inaccessible(tmp_path / f'user{n}', 'User profiles', 'PermissionError')
    rendered = setup.inventory_text(inventory)
    assert 'Inaccessible: 50' in rendered and 'user0' not in rendered
    assert len(rendered.splitlines()) < 6
    assert 'user0' in setup.inventory_text(inventory, details=True)


def test_browser_detection_records_context_only_when_history_exists(tmp_path):
    root = tree(tmp_path / 'root')
    (root / 'Users/alice/AppData/Local/Google/Chrome/User Data/CacheOnly').mkdir()
    items = [i for i in discovery.scan(root).candidates if i.kind == 'browser']
    assert {(i.browser_product, i.owner, i.profile) for i in items} == {
        ('chrome', 'alice', 'Default'), ('edge', 'alice', 'Profile 1')}
    assert all(i.path.name == 'History' for i in items)


@pytest.mark.parametrize('answer,products', [('all', {'chrome', 'edge'}), ('none', set()), ('2', {'edge'})])
def test_explicit_browser_selection(tmp_path, answer, products):
    root = tree(tmp_path / 'root')
    items = discovery.scan(root).candidates
    inputs = iter(['', answer])  # Multiple profiles must reprompt on blank.
    chosen, options = setup.browser_selection(items, lambda prompt: next(inputs), Palette())
    assert {p for _, p, _ in options} == products
    assert sum(i.kind != 'browser' for i in chosen) == 10


def test_browser_subset_ingestion_and_source_assertions(tmp_path):
    root = tree(tmp_path / 'root')
    before = snapshot(root)
    shell = Shell(State(None), Input('Browser case', 'Analyst', 'Organization', '1', str(root),
                                   '2', 'browser', '2', '', 'yes'))
    assert setup.create(shell) and snapshot(root) == before
    with closing(connect(shell.active, existing_only=True)) as db:
        assert {r[0] for r in db.execute('SELECT browser_product FROM browser_contexts')} == {'edge'}
        row = db.execute('SELECT hostname,username,volume_root FROM source_assertions').fetchone()
        assert tuple(row) == (None, None, None)
    entries = activity.inspect(activity.sidecar(shell.active), 100)
    assert entries['valid'] and 'Analyst' in str(entries) and 'Organization' in str(entries)


def test_inaccessible_mounted_mft_is_deferred(tmp_path, monkeypatch, capsys):
    root = tree(tmp_path / 'root')
    original = Path.open
    def denied(path, *args, **kwargs):
        if path == root / '$MFT':
            raise PermissionError('synthetic mounted MFT denial')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', denied)
    monkeypatch.setattr(discovery, 'mounted_mft', lambda path: path == root / '$MFT')
    shell = Shell(State(None), Input('MFT limitation', '', '', '1', str(root), '2', 'mft,prefetch', '', 'yes'))
    assert setup.create(shell)
    with closing(connect(shell.active, existing_only=True)) as db:
        assert db.execute('SELECT count(*) FROM ingestion_runs').fetchone()[0] == 1
        assert {r[0] for r in db.execute('SELECT source_type FROM evidence_records')} == {'prefetch'}
    text = capsys.readouterr().out
    assert 'extract $MFT as a standard file' in text and 'Direct ingestion: unavailable' in text
    assert 'requires extraction' in text and 'Case ready.' not in text
    assert 'Permission denied' not in text


def test_progress_fallback_throttled_and_truthful():
    now = [0.0]
    stream = io.StringIO()
    meter = setup_display.FileProgress('prefetch', 100, Palette(), stream=stream, clock=lambda: now[0])
    meter.update(0, 0)
    for n in range(1, 101):
        now[0] += .01
        meter.update(n, n * 2)
    meter.close()
    text = stream.getvalue()
    assert len(text.splitlines()) == 2
    assert '0 / 100 files  0%' in text and '100 / 100 files  100%' in text
    assert '200 records stored' in text and 'elapsed' in text and 'ETA' not in text
    assert '\x1b' not in text and '\r' not in text


def test_progress_inplace_and_cleanup(monkeypatch):
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    monkeypatch.setattr(setup_display, 'capable', lambda stream: True)
    stream = io.StringIO()
    meter = setup_display.FileProgress('registry', 2, Palette(), stream=stream)
    meter.update(0, 0)
    meter.update(2, 400)
    meter.close()
    assert stream.getvalue().count('\r\x1b[K') == 3
    assert '\n' not in stream.getvalue()


@pytest.mark.parametrize('status,records,duplicates,errors', [('complete', 12, 0, 0), ('partial', 12, 3, 1), ('failed', 0, 0, 1)])
def test_semantic_tokens(status, records, duplicates, errors):
    progress = setup.Progress()
    progress(None, 'evtx', dict(status=status, inserted=records, duplicates=duplicates, errors=errors))
    palette = Palette(True)
    text = setup_display.category_line('evtx', progress, palette)
    assert palette(setup_display.role(status), status) in text
    assert palette('success' if records else 'error', f'{records} records') in text
    assert palette('warning' if duplicates else 'success', f'{duplicates} duplicates') in text
    assert palette('error' if errors else 'success', f'{errors} error' + ('' if errors == 1 else 's')) in text
    outcomes = setup_display.file_outcomes(Counter(complete=2, failed=1, unsupported=3, partial=4), palette)
    for count, state in ((2, 'complete'), (1, 'failed'), (3, 'unsupported'), (4, 'partial')):
        assert palette(setup_display.role(state), f'{count} {state}') in outcomes


def test_evtx_verification_notes_vs_true_parse_errors(tmp_path, decode):
    path = tmp_path / 'synthetic.evtx'
    path.write_bytes(file_bytes([chunk([1, 2]), chunk([3, 4])], declared=1, dirty=True, minor=2))
    with closing(connect(':memory:')) as db:
        result = ingest_file(db, path)
        before = [tuple(r) for r in db.execute('SELECT * FROM ingestion_runs')]
        groups = setup_display.diagnostic_groups(db)
        assert sum(g['count'] for g in groups if g['limitation']) == 2
        assert result['status'] == 'partial' and result['errors'] == 2 and result['inserted'] == 4
        assert [tuple(r) for r in db.execute('SELECT * FROM ingestion_runs')] == before
        bad = tmp_path / 'bad.evtx'
        bad.write_bytes(file_bytes([chunk([7], bad_checksum=True)]))
        failed = ingest_file(db, bad)
        groups = setup_display.diagnostic_groups(db, {failed['run_id']})
        assert groups and not any(g['limitation'] for g in groups)
        assert failed['inserted'] == 0 and failed['errors'] > 0
        p = setup.Progress()
        p(None, 'evtx', result)
        p(None, 'evtx', failed)
        assert p.retained_partial == 1 and p.unsuccessful == 1


@pytest.mark.parametrize('items,outcomes,stored,deferred,expected', [
    ([1], {'mft': 'complete'}, 3, [], 'Case ready.'),
    ([1], {'evtx': 'partial'}, 3, [], 'Case created. Ingestion completed with limitations.'),
    ([], {}, 0, [], 'Case created. No evidence ingested.'),
    ([1], {'evtx': 'complete'}, 0, [], 'Case created. No evidence records stored; review the ingestion outcomes.'),
    ([1], {'registry': 'skipped'}, 0, [], 'Case created. No evidence records stored; review the ingestion outcomes.'),
    ([1], {'evtx': 'failed'}, 0, [], 'Case created, but selected evidence ingestion failed.'),
    ([1], {'prefetch': 'complete'}, 3, [1], 'Case created. Ingestion completed with limitations.'),
])
def test_completion_wording(items, outcomes, stored, deferred, expected):
    plan = SimpleNamespace(items=items, deferred=deferred, limited=False)
    assert setup_display.completion(plan, outcomes, stored) == expected

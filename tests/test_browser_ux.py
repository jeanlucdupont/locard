"""Synthetic browser discovery, attribution, filtering, and presentation regressions."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sqlite3

import pytest

from forensic_assistant import terminal, v2_cli
from forensic_assistant.artifacts import browser
from forensic_assistant.artifacts.ingest import discover
from forensic_assistant.cli import main, build_parser
from forensic_assistant.database import sources
from forensic_assistant.database.db import connect
from forensic_assistant.interactive import creation
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.retrieval.browser_display import SHARED_NOTES
from forensic_assistant.retrieval.evidence import EvidenceQueries
from forensic_assistant.retrieval.presentation import human_error
from forensic_assistant.retrieval.search_display import render
from test_browser_parser import history, T
from test_browser_integration import ingest
from test_interactive_shell import Input, case


def inventory(root):
    return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('wal', [False, True])
def test_browser_discovery_private_copy_and_no_implicit_product(tmp_path, wal):
    source = tmp_path / 'evidence'
    source.mkdir()
    path = source / 'History'
    with closing(history(path, wal=wal)):
        before = inventory(source)
        assert list(discover(source)) == []  # Ordinary ingest-all has no product/profile contract.
        assert creation.preflight(source) == [(path, 'browser')]
        assert inventory(source) == before


@pytest.mark.parametrize('kind', ['text', 'unrelated', 'view', 'missing_primary_key'])
def test_history_filename_is_not_sufficient(tmp_path, kind):
    root = tmp_path / 'evidence'
    root.mkdir()
    path = root / 'History'
    if kind == 'text':
        path.write_text('not a browser database')
    else:
        with closing(sqlite3.connect(path)) as db:
            if kind == 'unrelated':
                db.execute('CREATE TABLE unrelated(id INTEGER)')
            else:
                db.execute('CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT)')
                db.execute('CREATE VIEW visits AS SELECT 1 id,1 url,1 visit_time' if kind == 'view'
                           else 'CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER)')
            db.commit()
    before = inventory(root)
    assert creation.preflight(root) == []
    assert inventory(root) == before


def test_case_creation_browser_profiles_are_explicit_and_distinct(tmp_path):
    root = tmp_path / 'evidence'
    (root / 'chrome').mkdir(parents=True)
    (root / 'edge').mkdir()
    a, b = root / 'chrome' / 'History', root / 'edge' / 'History'
    history(a).close()
    shutil.copyfile(a, b)
    before = inventory(root)
    target = tmp_path / 'case.db'
    # Deliberately opposite directory hints: only explicit analyst choices count.
    reader = Input(str(target), str(root), 'edge', 'Profile 1', 'chrome', 'Default',
                   'Acquired source', 'host-a', '', '', 'yes')
    shell = Shell(State(None), reader)
    assert creation.create(shell) and shell.active == target
    assert inventory(root) == before
    with closing(connect(target)) as db:
        records = EvidenceQueries(db).search(artifact='browser').records
        assert len(records) == 4
        assert {(r['detail']['browser_product'], r['detail']['profile']) for r in records} == {
            ('edge', 'Profile 1'), ('chrome', 'Default')}
        assert all(r['context']['hostname'] == 'host-a' for r in records)
        assert db.execute('SELECT count(*) FROM sources').fetchone()[0] == 1
        assert db.execute('SELECT count(*) FROM browser_record_occurrences').fetchone()[0] == 4
        assert db.execute('SELECT count(*) FROM ingestion_batches').fetchone()[0] == 2
        assert {r['source_file'] for r in records if r['detail']['browser_product'] == 'edge'} == {str(a)}


@pytest.mark.parametrize('answer', ['', EOFError(), KeyboardInterrupt()])
def test_cancel_browser_metadata_leaves_case_and_evidence_unchanged(tmp_path, answer):
    root = tmp_path / 'evidence'
    root.mkdir()
    history(root / 'History').close()
    before = inventory(root)
    old = case(tmp_path, 'old.db')
    target = tmp_path / 'requested' / 'new.db'
    shell = Shell(State(None), Input(str(target), 'yes', str(root), answer))
    shell.activate(old)
    assert not creation.create(shell)
    assert shell.active == old and not target.parent.exists()
    assert inventory(root) == before


def test_empty_case_has_no_source_metadata_or_batches(tmp_path):
    root = tmp_path / 'empty'
    root.mkdir()
    target = tmp_path / 'new.db'
    reader = Input(str(target), str(root), 'e', 'yes')
    shell = Shell(State(None), reader)
    assert creation.create(shell)
    assert not any(p.startswith(('Source name', 'Source hostname', 'Source user', 'Original drive')) for p in reader.prompts)
    with closing(connect(target)) as db:
        for table in ('sources', 'source_assertions', 'ingestion_batches', 'evidence_records'):
            assert db.execute('SELECT count(*) FROM ' + table).fetchone()[0] == 0
    path = tmp_path / 'History'
    history(path).close()
    assert main(['--db', str(target), 'ingest-browser', str(path), '--browser', 'chrome', '--profile', 'Default']) == 0
    with closing(connect(target)) as db:
        assert db.execute('SELECT count(*) FROM sources').fetchone()[0] == 1


@pytest.mark.parametrize('failure', [ValueError('Parser worker timed out'), KeyboardInterrupt()])
def test_discovery_failure_cleans_parent_staging(tmp_path, monkeypatch, failure):
    path = tmp_path / 'History'
    history(path).close()
    staged = []
    def interrupted(kind, source, sha, stage, options, timeout):
        directory = stage.parent / 'private-copy'
        directory.mkdir()
        shutil.copyfile(source, directory / 'History')
        staged.append(stage.parent)
        raise failure
    monkeypatch.setattr('forensic_assistant.artifacts.ingest.worker', interrupted)
    with pytest.raises(type(failure)):
        creation.preflight(path)
    assert staged and all(not p.exists() for p in staged)


@pytest.fixture
def browser_case(tmp_path):
    path = tmp_path / 'History'
    with closing(history(path)) as original:
        original.execute('INSERT INTO visits VALUES (2,1,?,1)', (T+3_000_000,))
        original.execute('UPDATE urls SET title=?', ('GitHub · GitHub — café',))
        original.commit()
    target = tmp_path / 'case.db'
    with closing(connect(target)) as db:
        ingest(db, path, host=None)
    return target


def test_browser_kind_preserves_identity_order_and_timeline(browser_case, capsys):
    with closing(connect(browser_case)) as db:
        before = list(db.iterdump())
        q = EvidenceQueries(db)
        all_rows = q.search(artifact='browser').records
        for kind, count in [('visit', 2), ('download', 1)]:
            rows = q.search(browser_kind=kind).records
            assert len(rows) == count
            assert [r['id'] for r in rows] == [r['id'] for r in all_rows if r['artifact_type'] == 'browser_' + kind]
            assert q.search(browser_kind=kind, url_contains='example.com', profile='Default').total == count
        assert q.search(browser_kind='download', download_path_contains='.exe').total == 1
        timeline = q.search(timeline=True, browser_kind='download').records
        assert len(timeline) == 2 and len({r['id'] for r in timeline}) == 1
        for kwargs in ({'browser_kind': 'bad'}, {'browser_kind': 'visit', 'artifact': 'evtx'}):
            with pytest.raises(ValueError):
                q.search(**kwargs)
        assert list(db.iterdump()) == before
    assert main(['--db', str(browser_case), 'search', '--artifact', 'browser', '--browser-kind', 'visit', '--json']) == 0
    assert len(json.loads(capsys.readouterr().out)['records']) == 2
    from forensic_assistant.interactive.completion import complete
    prefix = 'search --'
    assert '--browser-kind' in complete(prefix, len(prefix)).candidates


@pytest.mark.parametrize('width', [50, 180])
@pytest.mark.parametrize('color', [False, True])
def test_browser_rows_group_details_ids_and_deduplicate_only_shared(browser_case, width, color):
    with closing(connect(browser_case)) as db:
        result = EvidenceQueries(db).search(artifact='browser').as_dict()
    records = result['records']
    for index, row in enumerate(records):
        row['warnings'].append('Specific anomaly ' + str(index))
    records[0]['warnings'].append('unsafe\x1b[31m\ntext')
    original = deepcopy(result)
    text = terminal.SGR.sub('', render(result, terminal.Palette(color), ids=True, width=width))
    assert 'Row 1:' not in text and 'Browser: Chrome' not in text
    assert 'GitHub · GitHub — café' in text and r'\u00b7' not in text
    assert '\x1b' not in text and 'unsafe\\u001b' in text
    starts = [text.index('ID: ' + r['id']) for r in records]
    assert starts == sorted(starts)
    for index, row in enumerate(records):
        end = starts[index+1] if index+1 < len(starts) else text.index('Forensic notes')
        assert text.index('Specific anomaly ' + str(index)) in range(starts[index], end)
        assert text.count(row['id']) == 1
    for note in SHARED_NOTES:
        if any(note in r['warnings'] for r in records):
            assert text.count(note) == 1
    assert result == original


def test_human_errors_preserve_literal_paths_and_error_codes(tmp_path, capsys):
    path = r'\\server\share\missing café\file'
    error = FileNotFoundError(2, 'Not found', path)
    text = human_error(error)
    assert text == '[Errno 2] Not found: ' + path
    error.filename2 = r'C:\target\file'
    assert human_error(error).endswith(' -> ' + error.filename2)
    error.winerror = 3
    assert human_error(error).startswith('[WinError 3]')
    assert '\x1b' not in human_error(OSError(2, 'bad\x1b[31m', 'x\nname'))
    shell = Shell(State(None), Input(str(tmp_path / 'new.db'), str(tmp_path / 'missing'), ''))
    assert not creation.create(shell)
    assert str(tmp_path / 'missing') in capsys.readouterr().out


def test_around_missing_host_and_investigation_cautions_unchanged(browser_case, capsys):
    from forensic_assistant.correlation.investigation import investigate
    from forensic_assistant.retrieval.analysis_display import render_investigation
    with closing(connect(browser_case)) as db:
        row = EvidenceQueries(db).search(browser_kind='visit').records[0]
        original = list(db.iterdump())
        result = investigate(db, row['id'], timestamp_slot='Browser.VisitTime')
        before = deepcopy(result)
        text = render_investigation(result)
        assert 'Same-host summary unavailable' in text and 'Temporal search not performed' in text
        assert text.count(SHARED_NOTES[-2]) == 1
        assert 'Browser-recorded activity; not proof' not in text
        assert result == before and list(db.iterdump()) == original
    assert main(['--db', str(browser_case), 'around', row['id'], '--timestamp-slot', 'Browser.VisitTime']) == 2
    error = capsys.readouterr().err
    assert 'Host context missing or conflicting' in error
    assert 'Locard:' not in error and '"' not in error


def test_source_update_human_and_complete_json(browser_case, capsys):
    with closing(connect(browser_case)) as db:
        sid = sources.listing(db)['sources'][0]['source_id']
    base = ['--db', str(browser_case), 'source', 'update', sid]
    assert main(base + ['--hostname', 'Host-A', '--user', 'alice', '--yes']) == 0
    text = capsys.readouterr().out
    assert 'Source updated.' in text and 'Hostname: unknown -> host-a' in text
    assert 'User:' in text and 'Previous assertion retained.' in text
    assert '"scope"' not in text and '"applied"' not in text
    assert main(base + ['--hostname', 'host-b']) == 0
    assert 'Preview only' in capsys.readouterr().out
    assert main(base + ['--hostname', 'host-b', '--yes', '--json']) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {'applied', 'result', 'scope'}
    assert data['result']['hostname'] == 'host-b' and data['scope']['source']['hostname'] == 'host-a'
    assert data['result']['supersedes'] == data['scope']['source']['assertion_id']


def test_probe_copy_is_inside_parent_owned_staging(tmp_path, monkeypatch):
    from forensic_assistant.artifacts import browser_probe
    path = tmp_path / 'History'
    history(path).close()
    staging = tmp_path / 'staging'
    staging.mkdir()
    original_copy = browser_probe.copy_snapshot
    copies = []
    def checked_copy(source, destination):
        assert destination.is_relative_to(staging)
        copies.append(destination)
        return original_copy(source, destination)
    monkeypatch.setattr(browser_probe, 'copy_snapshot', checked_copy)
    assert browser_probe.check(path, staging) == {'supported': True}
    assert copies and not list(staging.iterdir())


def test_mixed_case_creation_reuses_ingestion(tmp_path):
    from v2_fixtures import mft_file
    root = tmp_path / 'evidence'
    root.mkdir()
    history(root / 'History').close()
    mft_file(root / 'mft')
    before = inventory(root)
    target = tmp_path / 'case.db'
    shell = Shell(State(None), Input(str(target), str(root), 'chrome', 'Default', '', '', '', '', 'yes'))
    assert creation.create(shell) and shell.active == target
    assert inventory(root) == before
    with closing(connect(target)) as db:
        assert {r[0] for r in db.execute('SELECT DISTINCT source_type FROM evidence_records')} == {'browser', 'mft'}
        assert db.execute('SELECT count(*) FROM sources').fetchone()[0] == 1


def test_investigation_keeps_specific_browser_observations(browser_case):
    from forensic_assistant.retrieval.analysis_display import investigation_notes
    from forensic_assistant.retrieval.analysis_display import View
    with closing(connect(browser_case)) as db:
        record = EvidenceQueries(db).search(browser_kind='visit').records[0]
    record['observation'] = 'Record-specific observation remains visible'
    original = deepcopy(record)
    view = View(None)
    investigation_notes(view, [record])
    assert record == original
    assert record['observation'] in '\n'.join(view.lines)

"""Synthetic cases only. CSV convenience must not weaken evidence/provenance."""
import argparse
import csv
import io
import json
import os
from contextlib import closing
from pathlib import Path
import shutil

import pytest

from forensic_assistant import dump_cli as dump
from forensic_assistant.cli import main, build_parser
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant.interactive.completion import complete
from forensic_assistant.investigation_ai.case import open_readonly
from forensic_assistant import v2_cli, activity
from test_interactive_shell import case
from test_browser_parser import history
from v2_fixtures import mft_file, prefetch_file, registry_file, evtx_process


class Output:
    def __init__(self): self.lines = []
    def write(self, text): self.lines.append(text)


def export(path, kind='all', force=False):
    output = Output()
    dump.run(argparse.Namespace(db=str(path), dump_type=kind, force=force, command='dump'), output)
    return '\n'.join(output.lines)


def read(path, kind):
    with (path.parent / 'dump' / (kind + '.csv')).open(encoding='utf-8', newline='') as stream:
        reader = csv.DictReader(stream)
        assert reader.fieldnames == list(dump.COMMON + dump.FIELDS[kind])
        return list(reader)


@pytest.fixture(scope='module')
def mixed_template(tmp_path_factory):
    root = tmp_path_factory.mktemp('dump-template')
    path = case(root)
    with closing(connect(path)) as db:
        for kind, evidence in [('mft', mft_file(root / 'MFT', names=('café,"test.exe', 'ALIAS.EXE'), allocated=False)),
                               ('prefetch', prefetch_file(root / 'x.pf')),
                               ('registry', registry_file(root / 'hive', dirty=True, target='=unsafe,\n雪'))]:
            args = build_parser().parse_args(['ingest', kind, str(evidence), '--hostname', 'source-host', '--user', 'analyst', '--volume-root', 'C:'])
            result = v2_cli.ingest_sources(db, args)
            assert sum(r['inserted'] for r in result) > 0, result
        evtx_process(db)
        source = root / 'History'
        history(source).close()
        for product, profile in [('chrome', 'Default'), ('edge', 'Profile 1')]:
            args = build_parser().parse_args(['ingest', 'browser', str(source), '--browser', product, '--profile', profile, '--hostname', product + '-host'])
            assert sum(r['inserted'] for r in v2_cli.ingest_sources(db, args)) == 2
    return path


@pytest.fixture
def mixed(tmp_path, mixed_template):
    path = tmp_path / 'case.db'
    shutil.copyfile(mixed_template, path)
    return path


@pytest.mark.parametrize('kind', (*dump.TYPES, 'all'))
def test_surface_and_fixed_choices(kind):
    args = build_parser().parse_args(['dump', kind, '--force'])
    assert args.dump_type == kind and args.force


@pytest.mark.parametrize('tail', [['unknown'], ['../mft'], ['mft', 'name.csv'],
    ['mft', '--output', 'elsewhere'], ['mft', '--append', 'elsewhere'], ['mft', '--page']])
def test_bad_arguments_create_nothing(tmp_path, tail):
    with pytest.raises(SystemExit) as exc:
        main(['--db', str(tmp_path / 'missing.db'), 'dump', *tail])
    assert exc.value.code == 2
    assert not list(tmp_path.iterdir())


def test_bare_help_completion_and_zero(tmp_path, capsys):
    assert main(['--db', str(tmp_path / 'missing'), 'dump']) == 0
    assert 'dump <type> [--force]' in capsys.readouterr().out
    assert not list(tmp_path.iterdir())
    assert complete('dump ', 5).candidates == ('all', 'browser', 'evtx', 'mft', 'prefetch', 'registry')
    assert complete('dump m', 6).text == 'dump mft '
    path = case(tmp_path)
    before = path.read_bytes()
    assert 'No retained browser records' in export(path, 'browser')
    assert 'No retained supported records' in export(path)
    assert not (tmp_path / 'dump').exists() and path.read_bytes() == before


def test_all_content_counts_and_integrity(mixed):
    before = mixed.read_bytes()
    sentinel = mixed.parent / 'case.db.semantic'
    sentinel.write_bytes(b'index unchanged')
    text = export(mixed)
    assert 'Dump created: mft.csv' in text
    with closing(open_readonly(mixed)) as db:
        for kind in dump.TYPES:
            data = read(mixed, kind)
            expected = [r[0] for r in db.execute('SELECT evidence_id FROM evidence_records WHERE source_type=? ORDER BY evidence_id', (kind,))]
            assert [r['evidence_id'] for r in data] == expected
            assert len(data) == len(expected)
    mft = next(r for r in read(mixed, 'mft') if r['record_number'] == '6')
    assert mft['sequence_number'] == '1' and mft['allocated'] == '0'
    assert len(json.loads(mft['names_json'])) == 2
    assert 'café' in mft['names_json']
    si, fn = json.loads(mft['si_timestamps_json']), json.loads(mft['fn_timestamps_json'])
    assert len(si) == 4 and len(fn) == 8
    assert all('MFT SI' in t['source'] for t in si)
    assert all('MFT FN' in t['source'] for t in fn)
    assert si[0]['timestamp_utc'] != fn[0]['timestamp_utc']
    assert json.loads(mft['hostname']) == ['source-host']
    assert json.loads(mft['username']) == ['analyst']
    assert json.loads(mft['volume_root']) == ['C:']
    pf = read(mixed, 'prefetch')[0]
    assert pf['executable'] == 'PAYLOAD.EXE' and pf['run_count'] == '17'
    assert pf['last_run_time'] == json.loads(pf['run_times_json'])[0]['timestamp_utc']
    assert json.loads(pf['candidate_paths_json'])[0]['original'] == r'C:\Temp\PAYLOAD.EXE'
    reg = next(r for r in read(mixed, 'registry') if r['value_name'] == 'Example')
    assert reg['key_path'].endswith('Run') and reg['value_type'] == '1'
    assert json.loads(reg['value_data_json']) == '=unsafe,\n雪'
    assert reg['kind'] == 'registry_value' and reg['hive_dirty'] == '1'
    assert json.loads(reg['key_time']) and json.loads(reg['hive_warnings_json'])
    event = read(mixed, 'evtx')[0]
    assert event['event_id'] == '4688' and event['timestamp'] and event['provider'] and event['channel']
    assert event['record_id'] and json.loads(event['event_data_json'])
    browser = read(mixed, 'browser')
    assert len(browser) == 4 and {r['record_kind'] for r in browser} == {'history', 'download'}
    for row in browser:
        assert json.loads(row['hostname']) == [row['browser'] + '-host']
        assert row['profile'] == ('Default' if row['browser'] == 'chrome' else 'Profile 1')
        assert json.loads(row['occurrences_json'])[0]['context_id'] == row['browser_context_id']
        if row['record_kind'] == 'history':
            assert row['title'] == 'Example' and row['visit_count'] == '2'
        else:
            assert row['download_path'].endswith('tool.exe') and len(json.loads(row['url_chain_json'])) == 3
    assert mixed.read_bytes() == before and sentinel.read_bytes() == b'index unchanged'
    assert {p.name for p in (mixed.parent / 'dump').iterdir()} == {k + '.csv' for k in dump.TYPES}


def test_force_determinism_and_preflight_all(mixed):
    export(mixed, 'mft')
    first = (mixed.parent / 'dump/mft.csv').read_bytes()
    dbbefore = mixed.read_bytes()
    with pytest.raises(ValueError, match='Use --force'):
        export(mixed)
    assert not (mixed.parent / 'dump/browser.csv').exists()
    export(mixed, force=True)
    assert (mixed.parent / 'dump/mft.csv').read_bytes() == first
    other = {p.name: p.read_bytes() for p in (mixed.parent / 'dump').iterdir() if p.name != 'mft.csv'}
    export(mixed, 'mft', force=True)
    assert other == {p.name: p.read_bytes() for p in (mixed.parent / 'dump').iterdir() if p.name != 'mft.csv'}
    assert mixed.read_bytes() == dbbefore


@pytest.mark.parametrize('value', ['=1+1', '+cmd', '-cmd', '@cmd', '  =1', "'original", '\tdata', '\nline'])
def test_reversible_formula_protection(value):
    assert dump.cell(value) == "'" + value
    assert dump.cell(value)[1:] == value
    assert dump.cell({'text': value}) == json.dumps({'text': value}, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def test_csv_quotes_newlines_and_bounds():
    data = ['café,雪', 'a"b', 'a\nb', None, '', 0]
    stream = io.StringIO(newline='')
    csv.writer(stream).writerow([dump.cell(v) for v in data])
    assert next(csv.reader(io.StringIO(stream.getvalue(), newline=''))) == ['café,雪', 'a"b', 'a\nb', '', '', '0']
    with pytest.raises(ValueError, match='no data was truncated'):
        dump.cell('x' * (dump.MAX_CELL + 1))


def test_unrecognized_file_and_database_alias_rejected(mixed):
    root = mixed.parent / 'dump'
    root.mkdir()
    target = root / 'mft.csv'
    target.write_text('important existing analyst file')
    with pytest.raises(ValueError, match='not a recognized'):
        export(mixed, 'mft', True)
    assert target.read_text() == 'important existing analyst file'
    target.unlink()
    os.link(mixed, target)
    before = mixed.read_bytes()
    with pytest.raises(ValueError):
        export(mixed, 'mft', True)
    assert mixed.read_bytes() == before


def test_recorded_source_target_rejected_before_directory_creation(mixed):
    with closing(connect(mixed)) as db, db:
        sha = db.execute('SELECT file_sha256 FROM evidence_records LIMIT 1').fetchone()[0]
        db.execute('INSERT INTO source_locations VALUES (?,?)', (sha, str(mixed.parent / 'dump/mft.csv')))
    with pytest.raises(ValueError, match='recorded source evidence'):
        export(mixed, 'mft')
    assert not (mixed.parent / 'dump').exists()


def test_symlink_destination_rejected(mixed):
    outside = mixed.parent / 'outside'
    outside.mkdir()
    try:
        (mixed.parent / 'dump').symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip('Symlink creation unavailable to this account')
    with pytest.raises(ValueError, match='redirection'):
        export(mixed, 'mft')
    assert not list(outside.iterdir())


@pytest.mark.parametrize('failure', [OSError('synthetic write failure'), KeyboardInterrupt()])
def test_staging_failure_cleans_temporary_and_preserves_old_files(mixed, monkeypatch, failure):
    export(mixed, 'mft')
    before = (mixed.parent / 'dump/mft.csv').read_bytes()
    original = dump.rows
    def broken(db, kind):
        yield next(original(db, kind))
        raise failure
    monkeypatch.setattr(dump, 'rows', broken)
    with pytest.raises(type(failure)):
        export(mixed, 'mft', True)
    assert (mixed.parent / 'dump/mft.csv').read_bytes() == before
    assert not list((mixed.parent / 'dump').glob('.locard-dump-*'))


def test_publication_failure_reports_completed_files(mixed, monkeypatch):
    original = dump.os.link
    def fail_second(src, target):
        if Path(target).name == 'evtx.csv':
            raise OSError('synthetic publication failure')
        return original(src, target)
    monkeypatch.setattr(dump.os, 'link', fail_second)
    output = Output()
    with pytest.raises(OSError):
        dump.run(argparse.Namespace(db=str(mixed), dump_type='all', force=False, command='dump'), output)
    assert list((mixed.parent / 'dump').iterdir()) == [mixed.parent / 'dump/browser.csv']
    assert 'already published files remain: browser.csv' in '\n'.join(output.lines)


def test_new_target_race_does_not_overwrite(mixed, monkeypatch):
    original = dump.os.link
    def rival(src, target):
        Path(target).write_text('rival file')
        return original(src, target)
    monkeypatch.setattr(dump.os, 'link', rival)
    with pytest.raises(FileExistsError):
        export(mixed, 'mft')
    assert (mixed.parent / 'dump/mft.csv').read_text() == 'rival file'


def test_conflicting_sources_remain_explicit(mixed):
    with closing(connect(mixed)) as db, db:
        sha = db.execute("SELECT file_sha256 FROM evidence_records WHERE source_type='mft' LIMIT 1").fetchone()[0]
        sid = sources.create(db, name='Second', hostname='other-host')
        sources.assign(db, sid, [sha], reason='Synthetic ambiguity')
    export(mixed, 'mft')
    row = read(mixed, 'mft')[0]
    assert set(json.loads(row['hostname'])) == {'source-host', 'other-host'}
    assert len(json.loads(row['source_id'])) == 2


def test_cli_uses_existing_audit_and_readonly_database(mixed, capsys):
    before = mixed.read_bytes()
    assert main(['--db', str(mixed), 'dump', 'prefetch']) == 0
    assert 'prefetch.csv' in capsys.readouterr().out
    audit = activity.inspect(activity.sidecar(mixed), 100)
    assert audit['valid']
    writes = [r for r in audit['records'] if r['action'] == 'OUTPUT_WRITE']
    assert {r['outcome'] for r in writes} == {'pending', 'success'}
    assert all(r['path'] == 'dump/prefetch.csv' and r['row_count'] == 1 for r in writes)
    assert mixed.read_bytes() == before


def test_wal_snapshot_and_streaming_pages(mixed, monkeypatch):
    # A competing writer may commit; the export retains its initial snapshot.
    with closing(connect(mixed)) as writer:
        writer.execute('PRAGMA journal_mode=WAL')
        original = dump.rows
        def concurrent(db, kind):
            assert db.execute('PRAGMA database_list').fetchone()[2] == str(mixed)
            with pytest.raises(Exception):
                db.execute("UPDATE evidence_records SET hostname='bad'")
            with writer:
                sources.create(writer, name='Concurrent analyst source')
            yield from original(db, kind)
        monkeypatch.setattr(dump, 'rows', concurrent)
        export(mixed, 'mft')
        assert writer.execute("SELECT count(*) FROM source_assertions WHERE display_name='Concurrent analyst source'").fetchone()[0] == 1
    assert len(read(mixed, 'mft')) == 3


def test_large_registry_uses_bounded_pages(mixed, monkeypatch):
    with closing(connect(mixed)) as db, db:
        template = dict(db.execute("SELECT * FROM evidence_records WHERE artifact_type='registry_key' LIMIT 1").fetchone())
        columns = ','.join(template)
        for index in range(3000):
            template['evidence_id'] = f'REGISTRY:synthetic:{index:06}'
            db.execute('INSERT INTO evidence_records (' + columns + ') VALUES (' + ','.join('?' for _ in template) + ')', tuple(template.values()))
            db.execute('INSERT INTO registry_keys VALUES (?,?,NULL,?)', (template['evidence_id'], 'ROOT\\Synthetic', index))
    monkeypatch.setattr(dump, 'PAGE', 32)
    original = dump.groups
    def bounded(db, sql, params, key='evidence_id'):
        assert len(params) <= 64  # membership UNION repeats the hash parameters
        return original(db, sql, params, key)
    monkeypatch.setattr(dump, 'groups', bounded)
    export(mixed, 'registry')
    assert len(read(mixed, 'registry')) > 3000


def test_keyset_query_has_no_category_wide_sort(mixed):
    # Observe the actual production SELECT, rather than a copied query string.
    with closing(open_readonly(mixed)) as db:
        statements = []
        db.set_trace_callback(statements.append)
        list(dump.rows(db, 'registry'))
        select = next(s for s in statements if s.startswith('SELECT * FROM evidence_records'))
        plan = [r[3] for r in db.execute('EXPLAIN QUERY PLAN ' + select)]
        assert not any('TEMP B-TREE' in p for p in plan), plan
        assert any('evidence_id>?' in p for p in plan), plan


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory handle protection')
def test_windows_directory_swap_is_prevented_and_handles_released(mixed, monkeypatch):
    original = dump.rows
    root = mixed.parent / 'dump'
    def attempt_swap(db, kind):
        with pytest.raises(OSError):
            root.rename(mixed.parent / 'moved')
        yield from original(db, kind)
    monkeypatch.setattr(dump, 'rows', attempt_swap)
    export(mixed, 'mft')
    root.rename(mixed.parent / 'moved')  # No handle survives command cleanup.


def test_legacy_case_and_zero_skip(tmp_path):
    from schema_fixtures import legacy
    from forensic_assistant.artifacts.ingest import ingest_artifact
    path = tmp_path / 'old.db'
    with closing(legacy(path, version=3)) as db:
        result = ingest_artifact(db, prefetch_file(tmp_path / 'legacy.pf'), 'prefetch', hostname='legacy-host')
        assert result['inserted'] == 1
    before = path.read_bytes()
    assert 'Skipped browser: no retained records' in export(path)
    row = read(path, 'prefetch')[0]
    assert json.loads(row['source_id']) == []
    assert json.loads(row['legacy_contexts_json'])[0]['hostname'] == 'legacy-host'
    assert path.read_bytes() == before


def test_interactive_dispatch_and_help(mixed, tmp_path, capsys):
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    from test_interactive_shell import Input
    shell = Shell(reader=Input(str(mixed), 'help dump', 'dump mft', 'exit'),
                  state=State(tmp_path / 'ui-state.json'), no_color=True)
    assert shell.run() == 0
    text = capsys.readouterr().out
    assert 'dump browser' in text and 'mft.csv' in text
    assert len(read(mixed, 'mft')) == 3


@pytest.mark.parametrize('payload', ['[]', '{}'])
def test_malformed_browser_context_fails_cleanly_without_publication(mixed, payload, capsys):
    with closing(connect(mixed)) as db, db:
        db.execute("UPDATE evidence_records SET original_json=? WHERE source_type='browser'", (payload,))
    before = mixed.read_bytes()
    assert main(['--db', str(mixed), 'dump', 'browser']) == 2
    assert 'Invalid normalized browser context' in capsys.readouterr().err
    assert not list((mixed.parent / 'dump').iterdir())
    assert mixed.read_bytes() == before


def test_partial_ingestion_status_is_preserved(mixed):
    with closing(connect(mixed)) as db, db:
        db.execute("UPDATE ingestion_runs SET status='partial',error_count=1")
    before = mixed.read_bytes()
    export(mixed)
    assert mixed.read_bytes() == before
    assert all(o['status'] == 'partial' for r in read(mixed, 'browser') for o in json.loads(r['occurrences_json']))

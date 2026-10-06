"""Registry classification and presentation using synthetic/disposable evidence."""
import copy
import json
from contextlib import closing

import pytest

from forensic_assistant import v2_cli
from forensic_assistant.cli import build_parser, main
from forensic_assistant.database.db import connect
from forensic_assistant.artifacts import ingest, registry, registry_logs
from forensic_assistant.retrieval.evidence import EvidenceQueries, get_evidence
from forensic_assistant.retrieval import registry_display as display, search_display, show_display, status_display
from forensic_assistant.terminal import Palette, SGR
from v2_fixtures import registry_file


@pytest.fixture
def case(tmp_path):
    hive = registry_file(tmp_path / 'SYSTEM', dirty=True)
    with closing(connect(':memory:')) as db:
        assert ingest.ingest_artifact(db, hive, 'registry')['status'] == 'complete'
        key = db.execute("SELECT key_id FROM registry_values WHERE value_name='Example'").fetchone()[0]
        value = db.execute("SELECT evidence_id FROM registry_values WHERE value_name='Example'").fetchone()[0]
        yield db, hive, key, value


@pytest.mark.parametrize('suffix', ['.LOG1', '.log2', '.LoG1'])
def test_companions_never_reach_parser(tmp_path, suffix):
    hive = registry_file(tmp_path / 'Administrator_NTUSER.DAT')
    log = tmp_path / ('administrator_ntuser.dat' + suffix)
    log.write_bytes(b'regf' + bytes(80))
    before = log.read_bytes()
    assert list(ingest.discover(log, 'registry')) == [(log, 'registry')]
    with closing(connect(':memory:')) as db:
        result = ingest.ingest_artifact(db, log, 'registry', runner=lambda *a: pytest.fail('No worker for companion'))
        assert result['status'] == 'unsupported' and result['errors'] == result['inserted'] == 0
        assert result['companion_hive'] == str(hive)
        assert 'not verified' in result['companion_basis'] and result['replay_performed'] is False
        assert result['parser'] == registry_logs.CLASSIFIER
        metadata = json.loads(db.execute('SELECT parameters_json FROM artifact_runs').fetchone()[0])
        assert metadata['limitation'] == registry_logs.LIMITATION
        assert db.execute('SELECT file_sha256 FROM ingestion_runs').fetchone()[0]
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM ingestion_errors').fetchone()[0] == 0
    with pytest.raises(ValueError, match='replay is not supported'):
        list(registry.parse(log, 'synthetic'))
    assert log.read_bytes() == before


def test_unmatched_and_mixed_ingestion_source_membership(tmp_path):
    primary = registry_file(tmp_path / 'SYSTEM')
    for name in ('SYSTEM.LOG1', 'absent.LOG2'):
        (tmp_path / name).write_bytes(b'regf' + bytes(80))
    with closing(connect(':memory:')) as db:
        args = build_parser().parse_args(['ingest-registry', str(tmp_path)])
        results = v2_cli.ingest_sources(db, args)
        assert [r['status'] for r in results].count('complete') == 1
        assert [r['status'] for r in results].count('unsupported') == 2
        assert next(r for r in results if r['source_file'].endswith('absent.LOG2'))['companion_hive'] is None
        assert sum(r['inserted'] for r in results) > 0
        assert 'AttributeError' not in json.dumps(results)
        batches = db.execute('SELECT source_id,status FROM ingestion_batches').fetchall()
        assert len(batches) == 1 and batches[0]['status'] == 'partial'
        assert db.execute('SELECT count(*) FROM ingestion_runs WHERE batch_id IS NOT NULL').fetchone()[0] == 3
        assert db.execute('SELECT count(*) FROM registry_hives').fetchone()[0] == 1
        assert all(r['parser'] != registry_logs.CLASSIFIER for r in results if r['status'] == 'complete')


def test_only_companion_batch_is_not_successful_or_parser_failure(tmp_path):
    log = tmp_path / 'orphan.LOG2'
    log.write_bytes(b'HvLE' + bytes(80))
    with closing(connect(':memory:')) as db:
        args = build_parser().parse_args(['ingest-registry', str(log)])
        results = v2_cli.ingest_sources(db, args)
        assert results[0]['status'] == 'unsupported'
        assert db.execute('SELECT status FROM ingestion_batches').fetchone()[0] == 'unsupported'
        assert db.execute('SELECT count(*) FROM registry_keys').fetchone()[0] == 0


def test_companion_integrity_rechecked(tmp_path, monkeypatch):
    log = tmp_path / 'SYSTEM.LOG1'
    log.write_bytes(b'regf' + bytes(80))
    real = registry_logs.describe
    def changed(path):
        result = real(path)
        log.write_bytes(log.read_bytes() + b'changed')
        return result
    monkeypatch.setattr(registry_logs, 'describe', changed)
    with closing(connect(':memory:')) as db:
        result = ingest.ingest_artifact(db, log, 'registry')
        assert result['status'] == 'changed' and result['errors'] == 1
        assert db.execute('SELECT file_sha256 FROM ingestion_runs').fetchone()[0] is None
        assert db.execute('SELECT count(*) FROM evidence_files').fetchone()[0] == 0


def test_key_exact_contains_and_structured_immutability(case):
    db, _, key, value = case
    path = get_evidence(db, key)['detail']['key_path']
    q = EvidenceQueries(db)
    exact = q.search(artifact='registry', registry_key=path.swapcase())
    assert {r['id'] for r in exact.records} == {key, value, db.execute("SELECT evidence_id FROM registry_values WHERE value_name='Binary'").fetchone()[0]}
    assert q.search(registry_key=path + '\\').total == 0
    assert q.search(registry_key_contains='currentversion\\run').total == 3
    assert q.search(registry_key_contains='%').total == 0
    assert q.search(registry_key_contains='_').total == 0
    assert q.search(registry_key_contains="' OR 1=1 --").total == 0
    assert q.search(registry_key='').total == 1  # exact root, not a wildcard
    with pytest.raises(ValueError, match='Registry key filters'):
        q.search(artifact='mft', registry_key=path)
    with pytest.raises(ValueError, match='must not be empty'):
        q.search(registry_key_contains='')
    assert q.search(path='payload.exe').total == 1  # existing filesystem target contract
    assert q.search(path=path).total == 0  # no Registry reinterpretation of --path
    args = build_parser().parse_args(['search', '--artifact', 'registry', '--key', path, '--json'])
    actual, _ = v2_cli.dispatch(db, args)
    assert actual['records'] == exact.records
    assert actual['limit'] == 20


def test_key_search_across_distinct_hives_and_non_ascii_policy(case, tmp_path):
    db, _, key, _ = case
    other = registry_file(tmp_path / 'NTUSER.DAT', target=r'C:\Other\example.exe')
    assert ingest.ingest_artifact(db, other, 'registry')['status'] == 'complete'
    path = get_evidence(db, key)['detail']['key_path']
    results = EvidenceQueries(db).search(registry_key=path)
    assert results.total == 6 and len({r['file_sha256'] for r in results.records}) == 2
    with db:
        db.execute('UPDATE registry_keys SET key_path=? WHERE evidence_id=?', ('Software\\\u00c9xample', key))
    assert EvidenceQueries(db).search(registry_key='software\\\u00c9xample').total == 3
    assert EvidenceQueries(db).search(registry_key='software\\\u00e9xample').total == 0


def test_literal_key_metacharacters(case):
    db, _, key, _ = case
    with db:
        db.execute('UPDATE registry_keys SET key_path=? WHERE evidence_id=?', (r'A\literal%_!\x', key))
    q = EvidenceQueries(db)
    assert q.search(registry_key_contains='%_!').total == 3
    assert q.search(registry_key=r'A\LITERAL%_!\x').total == 3
    assert q.search(registry_key=r'A\literal%_!\..\x').total == 0


def test_dirty_warning_once_per_hive_and_context(case):
    db, _, key, _ = case
    result = EvidenceQueries(db).search(artifact='registry').as_dict()
    before = copy.deepcopy(result)
    shown = search_display.render(result, width=180)
    assert shown.count(display.DIRTY_WARNING) == 1
    assert 'KIND' in shown and 'Key' in shown and 'Value' in shown and '(key)' not in shown
    assert 'REG_SZ' in shown and 'REG_BINARY' in shown
    assert all(display.DIRTY_WARNING in r['warnings'] for r in result['records'])
    another = copy.deepcopy(result['records'][0])
    another['file_sha256'] = 'f' * 64
    result['records'].append(another)
    assert search_display.render(result).count(display.DIRTY_WARNING) == 2
    result['records'].pop()
    assert result == before


@pytest.mark.parametrize('code,name', list(enumerate(display.TYPE_NAMES)) + [(42, 'Unknown (42)')])
def test_type_names(code, name):
    assert display.type_name(code) == name


@pytest.mark.parametrize('code,data,expected', [
    (1, r'\\server\share\file.txt', r'\\server\share\file.txt'),
    (2, r'%SystemRoot%\System32\MsObjs.dll', r'%SystemRoot%\System32\MsObjs.dll'),
    (7, [r'C:\one', r'\\server\two'], r'[C:\one; \\server\two]'),
    (3, {'encoding': 'base64', 'data': 'AP8='}, '<binary, 2 bytes>'),
    (4, 42, '42'), (11, 1234567890123, '1234567890123'),
    (42, r'\x1b', '<data available in --json/--raw>')])
def test_value_data_rendering(code, data, expected):
    assert display.data_text(code, data) == expected


def test_string_escape_safety_and_bounds():
    raw = r'\\server\share\regex\w+' + '\x1b[31m\n\t'
    text = display.data_text(1, raw)
    assert '\x1b' not in text and '\n' not in text and r'\u001b[31m\n\t' in text
    assert r'\\server\share\regex\w+' in text
    assert 'truncated' in display.data_text(1, 'x' * 10000)
    assert 'truncated' in display.data_text(7, ['x'] * 100)


def test_key_and_value_show_preserve_identity_and_json(case):
    db, _, key, value = case
    original = get_evidence(db, key)
    values = display.projected_values(db, key)
    shown = show_display.render(original, registry_values=values)
    assert 'Registry key' in shown and 'Last write:' in shown
    assert 'Example' in shown and 'REG_SZ' in shown and r'C:\Temp\payload.exe' in shown
    assert 'Binary' in shown and '<binary, 4 bytes>' in shown
    assert shown.count(display.DIRTY_WARNING) == 1
    assert 'SHA-256' not in shown and 'Host: unknown' in shown
    assert original == get_evidence(db, key) and 'values' not in original['detail']
    for eid in original['detail']['value_ids']:
        assert get_evidence(db, eid)['id'] == eid
    record = get_evidence(db, value)
    before = copy.deepcopy(record)
    text = show_display.render(record)
    assert 'Registry value' in text and 'Type: REG_SZ' in text
    assert 'Timestamp belongs to the containing key' in text and text.count(display.DIRTY_WARNING) == 1
    assert record['timestamps'][0]['inherited_from_key'] is True
    assert record == before
    assert r'C:\\Temp\\payload.exe' in json.dumps(record)


def test_key_values_bound_default_value_and_large_data(case):
    db, _, key, value = case
    from forensic_assistant.database.artifacts import register
    original = dict(db.execute('SELECT * FROM evidence_records WHERE evidence_id=?', (value,)).fetchone())
    with db:
        db.execute('UPDATE registry_values SET value_name=? WHERE evidence_id=?', ('', value))
        for i in range(72):
            eid = original['evidence_id'] + f':synthetic-{i}'
            register(db, dict(original, evidence_id=eid))
            db.execute('INSERT INTO registry_values VALUES (?,?,?,?,?,?,?)',
                       (eid, key, f'Extra {i:03}', 2, b'', json.dumps('x' * 10000), 9000 + i))
    projection = display.projected_values(db, key)
    assert projection['total'] == 74 and len(projection['values']) == 20
    assert all(v['value_data'] is None for v in projection['values'] if v['json_size'] > 4096)
    text = show_display.render(get_evidence(db, key), registry_values=projection)
    assert '(Default)' in text and 'Showing 20 of 74 values' in text and 'omitted' in text
    assert len(get_evidence(db, key)['detail']['value_ids']) == 74


def test_status_human_json_sources_and_historical_logs(case, tmp_path, capsys):
    db, _, key, _ = case
    log = tmp_path / 'SYSTEM.LOG1'
    log.write_bytes(b'regf' + bytes(80))
    v2_cli.ingest_sources(db, build_parser().parse_args(['ingest-registry', str(log)]))
    with db:
        db.execute("INSERT INTO ingestion_runs(source_file,started_utc,status,error_count) VALUES ('old.LOG2','then','partial',1)")
        run = db.execute('SELECT max(id) FROM ingestion_runs').fetchone()[0]
        db.execute("INSERT INTO artifact_runs VALUES (?,'registry','libregf-python','test','1',NULL,'{}')", (run,))
        db.execute("INSERT INTO ingestion_batches VALUES ('unfinished',(SELECT source_id FROM sources LIMIT 1),'now',NULL,'test','test','running')")
    args = build_parser().parse_args(['status', '--json'])
    expected, _ = v2_cli.dispatch(db, args)
    before = copy.deepcopy(expected)
    details = status_display.context(db)
    text = status_display.render(expected, 'synthetic.db', details)
    assert 'CASE STATUS' in text and 'Total evidence records:' in text
    assert 'Complete: 1' in text and 'Partial: 0' in text and 'Failed: 0' in text
    assert 'Companion log attempts: unsupported: 1' in text
    assert 'Historical companion log attempts: partial: 1' in text
    assert 'Analyst host: unknown' in text and 'Unfinished batches: 1' in text
    assert text.count('Registry transaction-log replay is not supported') == 1
    assert 'Dirty Registry hives: 1' in text and 'not successful hive parsing' in text
    assert len(text.splitlines()) < 45 and not text.startswith('{')
    assert SGR.sub('', status_display.render(expected, 'synthetic.db', details, Palette(True))) == text
    assert expected == before
    path = tmp_path / 'case.db'
    with closing(connect(path)) as target:
        db.backup(target)
    assert main(['--db', str(path), 'status', '--json']) == 0
    assert json.loads(capsys.readouterr().out) == expected
    assert main(['--db', str(path), 'status']) == 0
    assert 'CASE STATUS' in capsys.readouterr().out
    assert main(['--db', str(path), 'show', key]) == 0
    assert 'Example' in capsys.readouterr().out


def test_status_failed_partial_and_legacy_metadata(case):
    db, _, _, _ = case
    with db:
        for outcome in ('failed', 'partial', 'interrupted'):
            db.execute('INSERT INTO ingestion_runs(source_file,started_utc,status,error_count) VALUES (?,?,?,?)',
                       ('synthetic', 'then', outcome, 1))
        db.execute('PRAGMA user_version=3')
    expected, _ = v2_cli.dispatch(db, build_parser().parse_args(['status', '--json']))
    text = status_display.render(expected, 'synthetic.db', status_display.context(db))
    assert 'Partial: 1' in text and 'Failed: 1' in text and 'interrupted: 1' in text
    assert 'Legacy source and batch membership unknown' in text
    assert 'Unfinished batches: unknown' in text

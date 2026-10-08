from contextlib import closing
from functools import partial
import json
from types import SimpleNamespace
import pytest
from forensic_assistant.cli import main, build_parser
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant import v2_cli, source_cli
from forensic_assistant.retrieval.evidence import EvidenceQueries, get_evidence
from forensic_assistant.semantic.documents import fingerprint
from v2_fixtures import prefetch_file, evtx_process


def options(path, **kw):
    return SimpleNamespace(
        command='ingest-all',
        path=path,
        source=None,
        hostname=None,
        user=None,
        volume_root=None,
        parser_timeout=300,
        record_size=None,
        **kw
    )


def test_auto_source_per_invocation_metadata_and_duplicates(tmp_path):
    directory = tmp_path / 'input'
    directory.mkdir()
    prefetch_file(directory / 'one.pf', name='ONE.EXE')
    prefetch_file(directory / 'two.pf', name='TWO.EXE')
    with closing(connect(':memory:')) as db:
        args = options(directory)
        args.hostname = 'HostA'
        args.user = 'UserA'
        args.volume_root = 'c:'
        first = v2_cli.ingest_sources(db, args)
        rows = sources.listing(db)['sources']
        assert len(rows) == 1
        a = rows[0]
        sid = a['source_id']
        assert a['hostname'] == 'hosta' and a['username'] == 'UserA' and a['volume_root'] == 'C:'
        assert a['creation_basis'] == 'automatic' and a['display_name'].startswith('Source ')
        assert a['files'] == 2 and a['batches'] == 1 and a['evidence_count'] == 2
        assert db.execute('SELECT count(DISTINCT batch_id) FROM ingestion_runs').fetchone()[0] == 1
        ids = [r[0] for r in db.execute('SELECT evidence_id FROM evidence_records')]
        v2_cli.ingest_sources(db, args)
        assert sources.listing(db)['total'] == 2  # Same host/path still creates a distinct source.
        assert [r[0] for r in db.execute('SELECT evidence_id FROM evidence_records')] == ids
        assert len(get_evidence(db, ids[0])['context']['source_ids']) == 2
        assert get_evidence(db, ids[0])['host_key'] is None
        args = options(directory)
        args.source = sid
        v2_cli.ingest_sources(db, args)
        assert sources.summary(db, sid)['batches'] == 2 and sources.listing(db)['total'] == 2
        assert all(r['batch_id'] for r in db.execute('SELECT batch_id FROM ingestion_runs'))


def test_unknown_then_corrected_hostname_and_source_search(tmp_path, capsys):
    artifact = prefetch_file(tmp_path / 'one.pf')
    case = tmp_path / 'case.db'
    assert main(['--db', str(case), 'ingest-prefetch', str(artifact)]) == 0
    capsys.readouterr()
    with closing(connect(case)) as db:
        sid = sources.listing(db)['sources'][0]['source_id']
        eid = db.execute('SELECT evidence_id FROM evidence_records').fetchone()[0]
        assert sources.current(db, sid)['hostname'] is None
        original = bytes(db.execute('SELECT raw_file FROM prefetch_records').fetchone()[0])
    around = ['--db', str(case), 'around', eid, '--timestamp-slot', 'run:0']
    assert main(around) == 2
    capsys.readouterr()
    update = ['--db', str(case), 'source', 'update', sid, '--hostname', 'HostA']
    assert main(update) == 0
    assert json.loads(capsys.readouterr().out)['applied'] is False
    assert main(update + ['--yes']) == 0
    capsys.readouterr()
    assert main(around) == 0
    capsys.readouterr()
    assert main([
        '--db',
        str(case),
        'source',
        'update',
        sid,
        '--hostname',
        'HostB',
        '--user',
        'analyst',
        '--volume-root',
        'd:',
        '--name',
        'Lab',
        '--yes'
    ]) == 0
    capsys.readouterr()
    with closing(connect(case)) as db:
        q = EvidenceQueries(db)
        assert q.search(source_id=sid, hostname='hostb', username='analyst').total == 1
        assert q.search(source_id=sid, hostname='hosta').total == 0
        assert get_evidence(db, eid)['host_key'] == 'hostb'
        assert bytes(db.execute('SELECT raw_file FROM prefetch_records').fetchone()[0]) == original
        assert db.execute('SELECT hostname FROM evidence_records').fetchone()[0] is None
        assert len(sources.detail(db, sid)['assertion_history']['records']) == 3


@pytest.mark.parametrize(
    'command',
    ['ingest', 'ingest-evtx', 'ingest-all', 'ingest-prefetch', 'ingest-mft', 'ingest-registry']
)
def test_existing_commands_without_source_create_empty_batch(tmp_path, capsys, command):
    directory = tmp_path / 'empty'
    directory.mkdir()
    case = tmp_path / 'case.db'
    assert main(['--db', str(case), command, str(directory)]) == 1
    with closing(connect(case)) as db:
        src = sources.listing(db)['sources'][0]
        assert src['creation_basis'] == 'automatic'
        assert all(src[k] is None for k in ('hostname', 'username', 'volume_root'))
        assert db.execute('SELECT status FROM ingestion_batches').fetchone()[0] == 'empty'


def test_partial_cancel_and_discovery_failure_auditable(tmp_path, monkeypatch):
    directory = tmp_path / 'files'
    directory.mkdir()
    prefetch_file(directory / 'a.pf')
    (directory / 'z').write_bytes(b'regf' + bytes(100))
    with closing(connect(':memory:')) as db:
        results = v2_cli.ingest_sources(db, options(directory))
        assert {r['status'] for r in results} == {'complete', 'partial'}
        assert db.execute('SELECT status FROM ingestion_batches').fetchone()[0] == 'partial'
        original = v2_cli.discover
        def interrupted(*args):
            yield next(original(*args))
            raise KeyboardInterrupt()
        monkeypatch.setattr(v2_cli, 'discover', interrupted)
        with pytest.raises(KeyboardInterrupt):
            v2_cli.ingest_sources(db, options(directory))
        assert db.execute("SELECT count(*) FROM ingestion_batches WHERE status='cancelled' AND finished_utc IS NOT NULL").fetchone()[0] == 1
        assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0] > 0
        monkeypatch.setattr(v2_cli, 'discover', original)
        with pytest.raises(ValueError):
            v2_cli.ingest_sources(db, options(tmp_path / 'missing'))
        assert db.execute("SELECT count(*) FROM ingestion_batches WHERE status='failed'").fetchone()[0] == 1


def test_source_artifact_conflict_and_separation(tmp_path):
    artifact = prefetch_file(tmp_path / 'one.pf')
    with closing(connect(':memory:')) as db:
        v2_cli.ingest_sources(db, options(artifact))
        sid = sources.listing(db)['sources'][0]['source_id']
        eid = db.execute('SELECT evidence_id FROM evidence_records').fetchone()[0]
        with db:
            sources.update(db, sid, hostname='analyst-host')
        evtx_process(db, host='artifact-host')
        evsha = db.execute("SELECT file_sha256 FROM evidence_records WHERE source_type='evtx'").fetchone()[0]
        with db:
            sources.assign(db, sid, [evsha], reason='Explicit synthetic selection')
        assert get_evidence(db, eid)['host_key'] == 'analyst-host'
        assert get_evidence(db, eid)['context']['conflicts'] == []
        ev_id = db.execute("SELECT evidence_id FROM evidence_records WHERE source_type='evtx'").fetchone()[0]
        assert get_evidence(db, ev_id)['host_key'] is None
        assert 'hostname' in get_evidence(db, ev_id)['context']['conflicts']
        assert sources.summary(db, sid)['host_conflict'] is True
        assert db.execute('SELECT hostname FROM events').fetchone()[0] == 'artifact-host'


def test_unassigned_file_retrospective_assignment(tmp_path):
    from forensic_assistant.artifacts.ingest import ingest_artifact
    path = tmp_path / 'legacy.db'
    with closing(connect(path)) as db:
        ingest_artifact(db, prefetch_file(tmp_path / 'old.pf'), 'prefetch')
        old = fingerprint(db)
        sha = db.execute('SELECT sha256 FROM evidence_files').fetchone()[0]
        eid = db.execute('SELECT evidence_id FROM evidence_records').fetchone()[0]
    # Reading unassigned evidence does not manufacture source membership.
    with closing(connect(path)) as db:
        assert fingerprint(db) == old and get_evidence(db, eid)['host_key'] is None
    with closing(connect(path)) as db:
        assert sources.listing(db)['total'] == 0
        assert sources.coverage(db)['unassigned_files'] == 1
        with db:
            sid = sources.create(db, name='Retrospective lab', hostname='lab')
            aid = sources.assign(db, sid, [sha], reason='Analyst selected this hash')
        assert get_evidence(db, eid)['host_key'] == 'lab'
        assert db.execute('SELECT count(*) FROM ingestion_batches').fetchone()[0] == 0
        assert db.execute('SELECT batch_id FROM ingestion_runs').fetchone()[0] is None
        assert sources.detail(db, sid)['retrospective_assignments']['records'][0]['assignment_id'] == aid


def test_confirmed_update_rejects_intervening_state_change(tmp_path):
    with closing(connect(':memory:')) as db:
        with db:
            sid = sources.create(db)
        args = build_parser().parse_args(['source', 'update', sid, '--hostname', 'lab'])
        preview = source_cli.dispatch(db, args)
        with db:
            sources.create(db)
        args.yes = True
        args.confirmation_fingerprint = preview['confirmation_fingerprint']
        with pytest.raises(ValueError, match='changed'):
            source_cli.dispatch(db, args)
        assert sources.current(db, sid)['hostname'] is None


def test_source_output_json_and_plain_export(tmp_path, capsys):
    path = tmp_path / 'case.db'
    out = tmp_path / 'sources.txt'
    with closing(connect(path)) as db:
        with db:
            sid = sources.create(db, name='Synthetic \x1b[31m label')
    assert main(['--db', str(path), 'source', 'list', '--json', '--output', str(out)]) == 0
    data = json.loads(out.read_text())
    assert data['sources'][0]['source_id'] == sid
    assert '\x1b' not in out.read_text()
    assert main(['--db', str(path), 'source', 'show', sid, '--limit', '1', '--json']) == 0
    assert json.loads(capsys.readouterr().out)['source_id'] == sid


def test_around_spans_same_host_sources_without_merging_provenance(tmp_path, capsys):
    case = tmp_path / 'case.db'
    with closing(connect(case)) as db:
        for exe in ('FIRST.EXE', 'SECOND.EXE'):
            args = options(prefetch_file(tmp_path / exe, name=exe))
            args.hostname = 'same-host'
            v2_cli.ingest_sources(db, args)
        ids = [r[0] for r in db.execute('SELECT evidence_id FROM evidence_records ORDER BY evidence_id')]
        for s in sources.listing(db)['sources']:
            with db:
                sources.update(db, s['source_id'], display_name='Same label')
    assert main(['--db', str(case), 'around', ids[0], '--timestamp-slot', 'run:0', '--seconds', '60']) == 0
    result = json.loads(capsys.readouterr().out)
    assert {r['id'] for r in result['records']} == set(ids)
    memberships = {tuple(r['context']['source_ids']) for r in result['records']}
    assert len(memberships) == 2 and all(len(m) == 1 for m in memberships)


def test_source_update_invalidates_derived_state_without_rewriting_it(tmp_path):
    from test_v4_worker import make_case, config
    from test_v3_index import FakeModel
    from forensic_assistant.semantic.index import build, status
    from forensic_assistant.reporting.bundle import generate, validate
    from forensic_assistant.investigation_ai.runner import ForensicWorker, WorkerError
    case = tmp_path / 'case.db'
    event = make_case(case)
    root = tmp_path / 'index'
    report = tmp_path / 'report'
    with closing(connect(case)) as db:
        with db:
            sid = sources.create(db)
        build(db, root, FakeModel())
    generate(case, report, evidence_ids=[event['id']])
    before = {p.name: p.read_bytes() for p in report.iterdir()}
    with ForensicWorker(config(case)) as worker:
        original = worker.call('check')
        assert original['schema'] == 5
        with closing(connect(case)) as db:
            with db:
                sources.update(db, sid, hostname='assigned-later')
            assert status(db, root)['state'] == 'stale'
        with pytest.raises(WorkerError, match='EVIDENCE_STATE_CHANGED'):
            worker.call('check', fingerprint=original['fingerprint'])
    result = validate(report, case=case)
    assert result['file_integrity'] == 'PASS' and result['case_fingerprint'] == 'FAIL'
    assert before == {p.name: p.read_bytes() for p in report.iterdir()}


def test_interactive_source_update_decline_then_confirm(tmp_path):
    from test_interactive_shell import Input
    from forensic_assistant.interactive.shell import Shell
    from forensic_assistant.interactive.state import State
    path = tmp_path / 'case.db'
    with closing(connect(path)) as db:
        with db:
            sid = sources.create(db)
    command = f'source update {sid} --hostname changed --yes'
    shell = Shell(State(None), Input(str(path), command, 'n', 'exit'))
    assert shell.run() == 0
    with closing(connect(path)) as db:
        assert sources.current(db, sid)['hostname'] is None
    shell = Shell(State(None), Input(str(path), command, 'yes', 'exit'))
    assert shell.run() == 0
    with closing(connect(path)) as db:
        assert sources.current(db, sid)['hostname'] == 'changed'


def test_legacy_replay_uses_recorded_schema(tmp_path):
    from schema_fixtures import legacy
    from forensic_assistant.database.db import register_source
    from test_ingest import SHA
    from v1_fixtures import process
    from test_v4_worker import config
    from test_v4_controller import Scripted, final
    from forensic_assistant.investigation_ai.controller import run
    from forensic_assistant.investigation_ai.replay import replay
    path = tmp_path / 'legacy.db'
    root = tmp_path / 'runs'
    with closing(legacy(path)) as db:
        with db:
            register_source(db, SHA, 1, 'synthetic.evtx')
        process(db, 1, '20')
    result = run(config(path), 'PowerShell', root, client=Scripted([final]))
    assert replay(config(path), root, result['investigation_id'])['termination'] == 'REPLAY_MATCH'


def test_source_conflict_report_retains_closed_contract_and_redaction(tmp_path):
    from test_v4_worker import make_case
    from forensic_assistant.reporting.bundle import generate, inspect, validate
    case = tmp_path / 'case.db'
    event = make_case(case)
    with closing(connect(case)) as db:
        sha = db.execute('SELECT file_sha256 FROM evidence_records WHERE evidence_id=?', (event['id'],)).fetchone()[0]
        with db:
            sid = sources.create(db, name='Private source label', hostname='conflicting-host')
            sources.assign(db, sid, [sha], reason='Explicit selection')
    output = tmp_path / 'report'
    generate(case, output, evidence_ids=[event['id']], redaction='identifiers')
    report, _ = inspect(output)
    conflict = next(c for c in report['data']['claims'] if c['category'] == 'CONFLICT')
    assert set(conflict['assertion']) == {'kind', 'fields', 'assertions', 'resolution'}
    assert conflict['assertion']['assertions']
    assert validate(output, case=case)['evidence_grounding'] == 'PASS'
    assert all(b'Private source label' not in p.read_bytes() for p in output.iterdir())

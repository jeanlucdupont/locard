"""Synthetic hardening checks, including the production process supervisor."""
from contextlib import closing
import hashlib
import http.server
import json
import os
import threading
import time

import pytest

from forensic_assistant import activity
from forensic_assistant.database.db import connect
from forensic_assistant.investigation_ai import contracts, controller, tools, supervision
from forensic_assistant.investigation_ai.state import Budget, State
from forensic_assistant.investigation_ai.transcript import Transcript, load
from forensic_assistant.investigation_ai.storage import DirectoryGuard, local_path
from forensic_assistant.llm.client import LocalClient
from forensic_assistant.retrieval.evidence import EvidenceQueries
from test_v4_controller import Scripted, tool, final
from test_v4_worker import make_case, config
from test_browser_parser import history
from test_browser_integration import ingest
from test_mixed_temporal import mixed_case


@pytest.mark.parametrize('approval', [False, True])
def test_audit_sequence_privacy_and_transcript_agree(tmp_path, approval):
    path = tmp_path / 'case.db'
    event = make_case(path)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    session = activity.Session(path)
    with activity.bind(session):
        result = controller.run(config(path), 'PowerShell private analyst question', tmp_path / 'runs',
                                budget=Budget(steps=1), client=Scripted([tool('show_evidence', {'evidence_id': event['id']})]),
                                approval=lambda p, s: approval)
    entries = [json.loads(line) for line in session.path.read_text().splitlines()]
    text = session.path.read_text()
    assert 'private analyst question' not in text and event['id'] not in text
    assert 'powershell.exe' not in text
    assert all(e['investigation_id'] == result['investigation_id'] for e in entries)
    actions = [e['action'] for e in entries]
    assert actions == ['INVESTIGATION_START', 'TOOL_PROPOSED',
                       *(['TOOL_APPROVED', 'TOOL_EXECUTED'] if approval else ['TOOL_REJECTED']),
                       'INVESTIGATION_TERMINATION']
    calls = [e for e in entries if e['action'].startswith('TOOL_')]
    assert {e['tool_call_number'] for e in calls} == {1}
    manifest, events = load(tmp_path / 'runs', result['investigation_id'])
    assert manifest['tool_calls'][0]['status'] == ('executed' if approval else 'rejected')
    assert any(e['kind'] == ('accepted' if approval else 'rejected') and e['data']['tool_call_number'] == 1 for e in events)
    assert activity.inspect(session.path)['valid']
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


def test_failed_tool_audited_without_error_payload(tmp_path):
    from test_investigation_assessment import RecordingWorker, EID
    from forensic_assistant.investigation_ai.runner import WorkerError
    class Failed(RecordingWorker):
        def call(self, name, arguments=None, **kw):
            if name == 'show_evidence':
                raise WorkerError('sensitive registry data')
            return super().call(name, arguments, **kw)
    path = tmp_path / 'case.db'
    make_case(path)
    session = activity.Session(path)
    with activity.bind(session):
        result = controller.run({}, 'Inspect', tmp_path / 'runs', worker_factory=Failed,
                                client=Scripted([tool('show_evidence', {'evidence_id': EID})]))
    assert result['termination'] == 'TOOL_FAILURE'
    text = session.path.read_text()
    assert 'TOOL_FAILED' in text and 'sensitive registry data' not in text


def test_empty_browser_inventory_is_not_advertised(tmp_path):
    path = tmp_path / 'case.db'
    make_case(path)
    client = Scripted([tool('search_evidence', {'artifact': 'browser'})])
    result = controller.run(config(path), 'PowerShell', tmp_path / 'runs', client=client, dry_run=True)
    assert result['state']['accepted_calls'] == 0
    packet = json.loads(client.calls[0][1]['content'])
    assert packet['controller']['browser_available'] is False
    assert 'browser' not in contracts.schema(['search_evidence'], False)['oneOf'][0]['properties']['arguments']['properties']['artifact']['enum']
    assert 'browser' in contracts.TOOLS['search_evidence'][1]['properties']['artifact']['enum']


def test_browser_ids_profiles_hosts_and_source_assertions_remain_separate(tmp_path):
    path = tmp_path / 'History'
    history(path).close()
    with closing(connect(tmp_path / 'case.db')) as db:
        ingest(db, path, 'chrome', 'Default', 'host-a')
        ingest(db, path, 'edge', 'Profile 1', 'host-b')
        before = list(db.iterdump())
        result = tools.execute(db, 'search_evidence', {'artifact': 'browser'}, {})
        contracts.validate_output(result)
        assert len(result['records']) == 4
        assert len({r['id'] for r in result['records']}) == 4
        assert {r['profile'] for r in result['records']} == {'Default', 'Profile 1'}
        assert {r['source_context']['hostname'] for r in result['records']} == {'host-a', 'host-b'}
        assert all(r['source_context']['source_ids'] and r['source_context']['basis'] == 'analyst-supplied' for r in result['records'])
        raw_records = EvidenceQueries(db).search(artifact='browser', limit=10).records
        separated = tools.envelope(db, 'investigate_evidence', {
            'records': raw_records,
            'relationships': [{'relationship': 'same_filename', 'status': 'corroborated',
                               'evidence_ids': [r['id'] for r in raw_records]}]})
        assert not separated['relationships']
        assert any('Cross-source relationships omitted' in v for v in separated['limitations'])
        assert len(separated['records']) == 4
        initial = tools.initial(db, 'Did tool.exe get downloaded and then executed?', {'semantic_enabled': False})
        assert initial['plan']['browser_available'] and initial['records']
        state = State(Budget())
        state.ingest(result)
        _, data, _ = state.prompt('Inspect download', ['show_evidence'], [])
        state.disclose(data)
        record = data['records'][0]
        answer = dict(observed=[{'evidence_id': record['id'], 'field': '/browser_product'}],
                      relationships=[], detections=[], hypotheses=[], unknowns=[])
        rendered = state.render(answer)['observed'][0]
        assert rendered['source_context'] == record['source_context']
        assert rendered['evidence_ids'] == [record['id']]
        answer['observed'][0]['field'] = '/source_context/hostname'
        with pytest.raises(ValueError, match='unexposed'):
            state.render(answer)
        assert list(db.iterdump()) == before


def test_browser_prefetch_registry_keep_cross_source_attribution(mixed_case, tmp_path):
    db, pfid, uaid, sids = mixed_case
    path = tmp_path / 'History'
    history(path).close()
    ingest(db, path)
    records = EvidenceQueries(db).search(limit=50).records
    result = tools.envelope(db, 'investigate_evidence', {'records': records})
    assert {r['source_type'] for r in result['records']} >= {'browser', 'registry', 'prefetch'}
    assert all(r['source_context']['source_ids'] for r in result['records'])
    assert any('analyst assertions' in value for value in result['limitations'])
    # A model selecting no findings cannot erase the retained deterministic warnings.
    state = State(Budget())
    state.ingest(result)
    assert state.limits


def test_ambiguous_anchor_refused_not_first_source_selected(mixed_case, monkeypatch):
    from forensic_assistant.database import sources
    db, pfid, uaid, sids = mixed_case
    with db:
        other = sources.create(db, name='other', hostname='host-a')
        sha = db.execute('SELECT file_sha256 FROM evidence_records WHERE evidence_id=?', (pfid,)).fetchone()[0]
        # Reuse the public retrospective assignment path via existing fixture behavior.
        from forensic_assistant.database.sources import assign
        assign(db, other, [sha], reason='synthetic test')
    monkeypatch.setattr(EvidenceQueries, 'search', lambda *a, **k: pytest.fail('Ambiguous anchor must not search neighbors'))
    result = tools.execute(db, 'around', {'evidence_id': pfid, 'timestamp_slot': 'run:0'}, {'known_ids': [pfid]})
    assert result['records'] == []
    assert 'Multiple source occurrences; cannot select an unambiguous source' in result['limitations']


@pytest.mark.parametrize('path', ['../outside', r'\\server\share\runs', 'runs/../outside'])
def test_transcript_traversal_network_rejected(path):
    with pytest.raises(ValueError):
        local_path(path)


def test_transcript_derived_atomic_and_collision_safe(tmp_path):
    transcript = Transcript(tmp_path / 'runs', {})
    transcript.append('initial', {'bounded': True})
    manifest = json.loads((transcript.path / 'manifest.json').read_text())
    assert manifest['derived_data'] and manifest['event_count'] == 1
    assert not (transcript.path / 'manifest.tmp').exists()
    with pytest.raises(FileExistsError):
        Transcript(tmp_path / 'runs', {}, investigation_id=transcript.id)
    transcript.finish({'termination': 'USER_SCOPE_REACHED'})
    assert load(tmp_path / 'runs', transcript.id)[0]['status'] == 'USER_SCOPE_REACHED'


def test_windows_junction_rejected_and_active_directory_cannot_move(tmp_path):
    if os.name != 'nt':
        pytest.skip('Windows reparse/handle gate')
    import subprocess
    target = tmp_path / 'target'
    target.mkdir()
    junction = tmp_path / 'junction'
    made = subprocess.run(['cmd', '/c', 'mklink', '/J', str(junction), str(target)], capture_output=True)
    assert made.returncode == 0
    try:
        with pytest.raises(ValueError, match='redirection'):
            Transcript(junction, {})
        assert not list(target.iterdir())
    finally:
        junction.rmdir()
    transcript = Transcript(target, {})
    with pytest.raises(OSError):
        transcript.path.rename(target / 'moved')
    transcript.finish({'termination': 'USER_SCOPE_REACHED'})


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True


@pytest.fixture
def local_model():
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            self.server.requests += 1
            messages = request['messages']
            if self.server.delay:
                time.sleep(self.server.delay)
            if self.server.propose:
                record = json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']['records'][0]
                response = tool('show_evidence', {'evidence_id': record['id']})
            else:
                response = final(messages)
            raw = json.dumps({'choices': [{'message': {'content': json.dumps(response)}, 'finish_reason': 'stop'}]}).encode()
            try:
                self.send_response(200)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except OSError:
                pass
    server = Server(('127.0.0.1', 0), Handler)
    server.delay = 0
    server.requests = 0
    server.propose = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(2)


@pytest.mark.parametrize('approve', [False, True])
def test_production_supervisor_approval_roundtrip(tmp_path, local_model, approve):
    path = tmp_path / 'case.db'
    make_case(path)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    seen = []
    def decide(proposal, seconds):
        seen.append(proposal)
        return approve
    result = supervision.run(config(path), 'PowerShell', tmp_path / 'runs',
                             budget=Budget(steps=1, calls=2, seconds=15), approval=decide,
                             client=LocalClient(f'http://127.0.0.1:{local_model.server_port}'))
    assert len(seen) == 1, result
    assert result['state']['accepted_calls'] == int(approve)
    assert result['termination'] == ('BUDGET_EXHAUSTED' if approve else 'USER_REJECTED')
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    manifest, _ = load(tmp_path / 'runs', result['investigation_id'])
    assert manifest['tool_calls'][0]['tool'] == seen[0]['tool']


def test_supervisor_model_deadline_and_bounded_cleanup(tmp_path, local_model):
    path = tmp_path / 'case.db'
    make_case(path)
    # Allow Windows process startup, then prove the delayed model is actually reached.
    # This is a test budget, not a production-default change.
    local_model.delay = 10
    seconds = 5
    started = time.monotonic()
    result = supervision.run(config(path), 'PowerShell', tmp_path / 'runs',
                             budget=Budget(seconds=seconds), client=LocalClient(f'http://127.0.0.1:{local_model.server_port}'))
    assert local_model.requests == 1
    assert result['termination'] == 'MAX_SECONDS', result
    assert time.monotonic() - started < seconds + supervision.CLEANUP_SECONDS + 1


def blocked_transcript_child(connection, gate, request):
    from forensic_assistant.investigation_ai import transcript
    transcript.Transcript._manifest = lambda self: time.sleep(30)
    supervision._child(connection, gate, request)


def test_supervisor_interrupts_blocked_transcript_io(tmp_path, monkeypatch):
    path = tmp_path / 'case.db'
    make_case(path)
    monkeypatch.setattr(supervision, '_child', blocked_transcript_child)
    started = time.monotonic()
    # Explicit transport keeps this test focused on blocked transcript I/O.
    result = supervision.run(config(path), 'PowerShell', tmp_path / 'runs',
                             client=LocalClient(), budget=Budget(seconds=1))
    assert result['termination'] == 'STARTUP_TIMEOUT'
    assert time.monotonic() - started < 1 + supervision.CLEANUP_SECONDS + 1
    assert result['transcript_complete'] is False


def test_cleanup_failure_cannot_return_to_shell(tmp_path, local_model, monkeypatch):
    from forensic_assistant.investigation_ai.lifecycle import CleanupError
    original = supervision._stop
    def uncertain(*args):
        original(*args)
        return False
    monkeypatch.setattr(supervision, '_stop', uncertain)
    path = tmp_path / 'case.db'
    make_case(path)
    with pytest.raises(CleanupError) as error:
        supervision.run(config(path), 'PowerShell', tmp_path / 'runs', dry_run=True,
                        client=LocalClient(f'http://127.0.0.1:{local_model.server_port}'))
    assert error.value.result['termination'] == 'USER_SCOPE_REACHED'
    assert error.value.result['cleanup']['status'] == 'CLEANUP_LIMITATION'


def test_normalized_arguments_match_audited_hash(tmp_path):
    from forensic_assistant.investigation_ai.transcript import digest
    path = tmp_path / 'case.db'
    make_case(path)
    result = controller.run(config(path), 'PowerShell', tmp_path / 'runs', budget=Budget(steps=1),
                            client=Scripted([tool('search_evidence', {'process': 'powershell.exe', 'limit': 1})]))
    manifest, events = load(tmp_path / 'runs', result['investigation_id'])
    accepted = next(e for e in events if e['kind'] == 'accepted')
    assert manifest['tool_calls'][0]['arguments_sha256'] == digest(accepted['data']['proposal']['arguments'])


def test_deterministic_limitations_survive_empty_final_and_overflow():
    state = State(Budget())
    for i in range(35):
        state.limit('Deterministic limit ' + str(i))
    assert len(state.limits) == 30
    assert 'omitted' in state.limits[-1]


def test_mft_prefetch_evtx_projection_preserves_context(tmp_path):
    from forensic_assistant.artifacts.ingest import ingest_artifact
    from v2_fixtures import mft_file, prefetch_file
    path = tmp_path / 'case.db'
    make_case(path)
    with closing(connect(path)) as db:
        for kind, artifact in [('mft', mft_file(tmp_path / 'synthetic.mft')),
                               ('prefetch', prefetch_file(tmp_path / 'synthetic.pf'))]:
            assert ingest_artifact(db, artifact, kind, hostname='PC.example')['status'] == 'complete'
        browser_path = tmp_path / 'History'
        history(browser_path).close()
        assert ingest(db, browser_path, host='PC.example')['status'] == 'complete'
        rows = EvidenceQueries(db).search(limit=50).records
        result = tools.envelope(db, 'investigate_evidence', {'records': rows})
        assert {r['source_type'] for r in result['records']} >= {'evtx', 'mft', 'prefetch', 'browser'}
        assert all('source_context' in r and 'basis' in r['source_context'] for r in result['records'])
        assert all(contracts.EID.fullmatch(r['id']) for r in result['records'])

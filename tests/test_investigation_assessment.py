"""Assessment gates for the existing bounded engine; no additional tools."""
import hashlib
import json

import pytest

from forensic_assistant.investigation_ai import contracts, controller, tools
from forensic_assistant.investigation_ai.runner import ForensicWorker, WorkerError
from forensic_assistant.investigation_ai.state import Budget
from forensic_assistant.investigation_ai.transcript import Transcript, load
from test_v4_controller import Scripted, final, tool
from test_v4_worker import config, make_case


NAMES = {'search_evidence', 'timeline', 'show_evidence', 'around', 'process_tree',
         'session', 'detections', 'investigate_evidence', 'semantic_search'}
EID = 'EVTX:' + 'a' * 64 + ':Offset:1'


def envelope():
    return tools.envelope(None, 'initial_retrieval', {'records': [
        {'id': EID, 'kind': 'process', 'process_name': 'synthetic.exe'}]})


class RecordingWorker:
    def __init__(self, config):
        self.calls = []
        self.closed = False

    def call(self, name, arguments=None, **kwargs):
        self.calls.append(name)
        return {'result': envelope(), 'fingerprint': 'f' * 64, 'database_changes': 0,
                'schema': 5, 'elapsed_seconds': 0, 'semantic_available': False}

    def close(self):
        self.closed = True


def test_exact_allowlist():
    assert set(contracts.TOOLS) == NAMES
    assert set(contracts.catalog()) == NAMES


@pytest.mark.parametrize('name', ['shell', 'sql', 'dump', 'ingest-all', 'report',
                                 'investigate-ai', 'source', 'semantic setup', 'http', '__import__'])
def test_forbidden_operation_cannot_reach_dispatch(name, monkeypatch):
    monkeypatch.setattr(tools, 'EvidenceQueries', lambda db: pytest.fail('dispatch reached'))
    with pytest.raises(ValueError, match='Unknown forensic tool'):
        tools.execute(None, name, {}, {})


@pytest.mark.parametrize('key', ['sql', 'where', 'table', 'expression', 'command',
                                'output', 'endpoint', 'model_path', 'database'])
def test_execution_parameters_are_not_model_inputs(key):
    with pytest.raises(ValueError, match='unknown parameter'):
        contracts.arguments('search_evidence', {'process': 'sample.exe', key: '../outside'})


@pytest.mark.parametrize('raw', ['not JSON', '{"action":"tool","action":"final"}',
                                '{"x":NaN}', ' ' * 16385])
def test_model_boundary_fails_closed(raw):
    with pytest.raises(ValueError):
        contracts.request(raw, NAMES)


@pytest.mark.parametrize('field,maximum', [('steps', 16), ('calls', 12), ('seconds', 600)])
def test_budget_bounds(field, maximum):
    for value in (0, maximum + 1, True):
        with pytest.raises(ValueError):
            Budget(**{field: value})
    assert getattr(Budget(**{field: maximum}), field) == maximum


def test_step_and_call_limits_include_retries(tmp_path):
    for budget, actions, expected in (
        (Budget(steps=2), [tool('shell', {})] * 3, 0),
        (Budget(calls=1), [tool('search_evidence', {'process': 'one'}),
                          tool('search_evidence', {'process': 'two'})], 1),
    ):
        worker = RecordingWorker({})
        client = Scripted(actions)
        result = controller.run({}, 'Inspect', tmp_path, budget=budget, client=client,
                                worker_factory=lambda _: worker)
        assert result['termination'] == 'BUDGET_EXHAUSTED'
        assert len(client.calls) == 2
        assert result['state']['accepted_calls'] == expected
        assert len([n for n in worker.calls if n not in ('initial', 'check')]) == expected
        assert worker.closed


@pytest.mark.parametrize('expire_at', ['model'])
def test_deadline_prevents_subsequent_execution(tmp_path, monkeypatch, expire_at):
    now = [0.0]
    monkeypatch.setattr(controller.time, 'monotonic', lambda: now[0])
    worker = RecordingWorker({})
    def proposal(messages):
        if expire_at == 'model':
            now[0] = 11.0
        return tool('search_evidence', {'process': 'one'})
    def approve(proposal, remaining):
        now[0] = 11.0
        return True
    result = controller.run({}, 'Inspect', tmp_path, budget=Budget(seconds=10),
                            client=Scripted([proposal]), approval=approve,
                            worker_factory=lambda _: worker)
    assert result['termination'] == 'MAX_SECONDS'
    assert worker.calls == ['initial']
    assert result['state']['accepted_calls'] == 0


@pytest.mark.parametrize('approve', [False, True])
def test_approval_precedes_dispatch_and_denial_stops(tmp_path, approve):
    worker = RecordingWorker({})
    approvals = []
    def consent(proposal, seconds):
        assert worker.calls == ['initial']
        assert proposal['tool'] == 'show_evidence' and seconds > 0
        approvals.append(proposal)
        return approve
    result = controller.run({}, 'Inspect', tmp_path, budget=Budget(steps=1),
                            client=Scripted([tool('show_evidence', {'evidence_id': EID})]),
                            approval=consent, worker_factory=lambda _: worker)
    assert len(approvals) == 1
    assert ('show_evidence' in worker.calls) is approve
    assert result['state']['accepted_calls'] == int(approve)


def test_dry_run_never_asks_approval_or_dispatches_proposal(tmp_path):
    worker = RecordingWorker({})
    client = Scripted([tool('show_evidence', {'evidence_id': EID})])
    result = controller.run({}, 'Inspect', tmp_path, client=client, dry_run=True,
                            approval=lambda *a: pytest.fail('dry-run approval'),
                            worker_factory=lambda _: worker)
    assert worker.calls == ['initial', 'check']
    assert len(client.calls) == 1 and result['state']['accepted_calls'] == 0
    _, events = load(tmp_path, result['investigation_id'])
    assert 'dry_run_proposal' in [e['kind'] for e in events]
    assert not any(e['kind'] in ('accepted', 'result') for e in events)


def test_failed_call_counts_and_is_terminal(tmp_path):
    class Failed(RecordingWorker):
        def call(self, name, arguments=None, **kwargs):
            if name == 'show_evidence':
                self.calls.append(name)
                raise WorkerError('Synthetic bounded failure')
            return super().call(name, arguments, **kwargs)
    worker = Failed({})
    client = Scripted([tool('show_evidence', {'evidence_id': EID})])
    result = controller.run({}, 'Inspect', tmp_path, client=client, worker_factory=lambda _: worker)
    assert result['termination'] == 'TOOL_FAILURE'
    assert result['state']['accepted_calls'] == 1 and len(client.calls) == 1
    assert worker.calls == ['initial', 'show_evidence', 'check'] and worker.closed
    assert 'Traceback' not in json.dumps(result)


def test_explicit_bounds_preserve_ids_and_mark_omissions():
    rows = [{'id': EID.replace('Offset:1', f'Offset:{i}'), 'process_name': 'x' * 400}
            for i in range(60)]
    result = tools.envelope(None, 'search_evidence', {'records': rows, 'limits': ['x' * 400] * 9})
    contracts.validate_output(result)
    assert len(result['records']) == 50 and result['truncated']
    assert result['records'][0]['id'] == rows[0]['id']
    assert result['records'][0]['truncated_fields']
    assert any('Limitation text was truncated' in text for text in result['limitations'])
    record = tools.compact({'id': EID, 'warnings': ['x' * 201] * 5})
    assert 'warnings' in record['truncated_fields']
    assert len(record['warnings']) == 4


def test_transcript_collision_never_overwrites(tmp_path, monkeypatch):
    import forensic_assistant.investigation_ai.transcript as module
    first = Transcript(tmp_path, {})
    first.finish({'termination': 'USER_SCOPE_REACHED'})
    before = {p.name: p.read_bytes() for p in first.path.iterdir()}
    monkeypatch.setattr(module.uuid, 'uuid4', lambda: type('Fixed', (), {'hex': first.id})())
    with pytest.raises(FileExistsError):
        Transcript(tmp_path, {})
    assert {p.name: p.read_bytes() for p in first.path.iterdir()} == before
    with pytest.raises(ValueError, match='Invalid investigation ID'):
        load(tmp_path, '../outside')


def test_real_worker_readonly_hash_and_no_bytecode(tmp_path):
    path = tmp_path / 'case.db'
    event = make_case(path)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    with ForensicWorker(config(path)) as worker:
        assert '-I' in worker.process.args and '-B' in worker.process.args
        result = worker.call('initial', question='PowerShell')
        result = worker.call('show_evidence', {'evidence_id': event['id']},
                             fingerprint=result['fingerprint'], known_ids=[event['id']])
        assert result['database_changes'] == 0
        with pytest.raises(WorkerError):
            worker.call('search_evidence', {'sql': 'DELETE FROM events'})
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    assert result['result']['records'][0]['id'] == event['id']


def test_complete_readonly_investigation_does_not_change_database(tmp_path):
    path = tmp_path / 'case.db'
    make_case(path)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    result = controller.run(config(path), 'PowerShell', tmp_path / 'runs', client=Scripted([final]))
    assert result['termination'] == 'ANSWER_SUPPORTED'
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


@pytest.mark.parametrize('endpoint', ['https://example.test', 'http://192.0.2.1',
                                     'http://example.test', 'http://127.0.0.1@192.0.2.1'])
def test_remote_endpoint_rejected_before_connection(endpoint):
    from forensic_assistant.llm.client import LocalClient
    with pytest.raises(ValueError, match='loopback'):
        LocalClient(endpoint)

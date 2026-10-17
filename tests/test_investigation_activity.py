import json
import logging

import pytest

from forensic_assistant.investigation_ai import controller
from forensic_assistant.investigation_ai.rejection import diagnostic
from forensic_assistant.investigation_ai.state import Budget
from forensic_assistant.investigation_ai.transcript import load
from test_investigation_assessment import RecordingWorker, EID
from test_v4_controller import Scripted, tool
from test_investigation_hardening import local_model


@pytest.mark.parametrize('proposal,category', [
    (tool('shell-PAYLOAD', {'secret': 'PAYLOAD'}), 'UNKNOWN_TOOL'),
    (tool('search_evidence', {'process': 'PAYLOAD', 'limit': 999}), 'INVALID_ARGUMENT'),
    (tool('search_evidence', {'process': 'PAYLOAD', 'secret': 'PAYLOAD'}), 'UNKNOWN_ARGUMENT'),
    (tool('show_evidence', {'evidence_id': 'EVTX:' + 'b' * 64 + ':Offset:1'}), 'UNEXPOSED_EVIDENCE_ID'),
    ({'action': 'final', 'answer': dict(observed=[dict(evidence_id=EID, field='/PAYLOAD')],
        relationships=[], detections=[], hypotheses=[], unknowns=[])}, 'GROUNDING_VIOLATION'),
    ('PAYLOAD', 'MALFORMED_PROPOSAL'),
])
def test_rejections_safe_linked_and_not_executed(tmp_path, caplog, proposal, category):
    worker = RecordingWorker({})
    with caplog.at_level(logging.DEBUG, logger='forensic_assistant.investigation_ai'):
        result = controller.run({}, 'Inspect', tmp_path, budget=Budget(steps=1),
            client=Scripted([proposal]), worker_factory=lambda _: worker)
    assert worker.calls == ['initial', 'check']
    assert result['state']['steps'] == result['state']['rejected_requests'] == 1
    assert result['state']['accepted_calls'] == 0
    manifest, events = load(tmp_path, result['investigation_id'])
    record = next(e['data']['diagnostic'] for e in events if e['kind'] == 'rejected')
    assert record['category'] == category
    assert record['investigation_id'] == result['investigation_id']
    assert record['step'] == record['proposal_sequence'] == 1
    assert record['tool_call_number'] == (1 if isinstance(proposal, dict) and proposal['action'] == 'tool' else None)
    assert len(record['arguments_sha256']) == 64
    assert 'PAYLOAD' not in json.dumps(record) and 'PAYLOAD' not in caplog.text
    assert record['category'] in caplog.text
    if manifest.get('tool_calls'):
        assert manifest['tool_calls'][0]['status'] == 'rejected'


def test_real_observed_counter_pattern_remains(tmp_path, caplog):
    worker = RecordingWorker({})
    invalid = dict(action='final', answer=dict(observed=[dict(evidence_id=EID, field='/invented')],
                    relationships=[], detections=[], hypotheses=[], unknowns=[]))
    with caplog.at_level(logging.DEBUG, logger='forensic_assistant.investigation_ai'):
        result = controller.run({}, 'Inspect', tmp_path, budget=Budget(steps=3),
            client=Scripted([tool('show_evidence', {'evidence_id': EID}), invalid, invalid]),
            approval=lambda *_: True, worker_factory=lambda _: worker)
    assert result['termination'] == 'BUDGET_EXHAUSTED'
    assert {key: result['state'][key] for key in ('steps', 'requested_calls', 'accepted_calls', 'rejected_requests')} == dict(
        steps=3, requested_calls=1, accepted_calls=1, rejected_requests=2)
    assert worker.calls == ['initial', 'show_evidence', 'check']
    assert caplog.text.count("'category': 'GROUNDING_VIOLATION'") == 2
    assert 'rejected_requests=2' in caplog.text


@pytest.mark.parametrize('dry_run', [True, False])
def test_real_worker_phase_delivery_and_approval(tmp_path, dry_run):
    from test_v4_worker import make_case, config
    path = tmp_path / 'case.db'
    event = make_case(path)
    phases = []
    def approval(*_):
        assert phases[-1] == 'approval'
        return True
    result = controller.run({**config(path), '_status': phases.append}, 'PowerShell', tmp_path / 'runs',
        budget=Budget(steps=1), dry_run=dry_run, approval=approval,
        client=Scripted([tool('show_evidence', {'evidence_id': event['id']})]))
    assert all(p in phases for p in ('preparing', 'fingerprint', 'initial_retrieval', 'exposure', 'model', 'validation', 'finalizing'))
    assert ('operation' in phases) is (not dry_run)
    assert ('approval' in phases) is (not dry_run)
    assert result['state']['accepted_calls'] == (0 if dry_run else 1)


def test_repeat_still_stops(tmp_path, caplog):
    worker = RecordingWorker({})
    proposal = tool('show_evidence', {'evidence_id': EID})
    with caplog.at_level(logging.DEBUG, logger='forensic_assistant.investigation_ai'):
        result = controller.run({}, 'Inspect', tmp_path, client=Scripted([proposal, proposal]),
                                worker_factory=lambda _: worker)
    assert result['termination'] == 'TOOL_LOOP'
    assert worker.calls.count('show_evidence') == 1
    assert 'REPEATED_TOOL_CALL' in caplog.text


@pytest.mark.parametrize('reason,category', [
    ('Multiple source occurrences; cannot select an unambiguous source', 'SOURCE_AMBIGUITY'),
    ('Host context missing or conflicting; cannot select same-host temporal neighbors', 'HOST_AMBIGUITY'),
])
def test_ambiguity_is_execution_failure_not_new_proposal_rejection(tmp_path, caplog, reason, category):
    from forensic_assistant.investigation_ai.runner import WorkerError
    class Worker(RecordingWorker):
        def call(self, name, *a, **kw):
            if name == 'around':
                raise WorkerError(reason)
            return super().call(name, *a, **kw)
    with caplog.at_level(logging.DEBUG, logger='forensic_assistant.investigation_ai'):
        result = controller.run({}, 'Inspect', tmp_path,
            client=Scripted([tool('around', {'evidence_id': EID})]), worker_factory=Worker)
    assert result['termination'] == 'TOOL_FAILURE'
    assert result['state']['accepted_calls'] == 1 and result['state']['rejected_requests'] == 0
    assert category in caplog.text and 'worker_execution' in caplog.text


def test_diagnostics_never_echo_arbitrary_error_or_tool():
    args = dict(action='tool', tool='evil\nPAYLOAD', arguments={'secret': 'PAYLOAD'})
    first = diagnostic('a' * 32, 2, 1, args, 'proposal_validation', 'bad IP PAYLOAD')
    assert first == diagnostic('a' * 32, 2, 1, args, 'proposal_validation', 'bad IP PAYLOAD')
    assert 'PAYLOAD' not in json.dumps(first)
    assert first['tool'] == 'unknown' and first['stage'] == 'argument_validation'


def test_supervisor_relays_only_terminal_phases(tmp_path, local_model):
    from forensic_assistant.investigation_ai import supervision
    from forensic_assistant.llm.client import LocalClient
    from test_v4_worker import make_case, config
    path = tmp_path / 'case.db'
    make_case(path)
    phases = []
    def approval(*_):
        assert phases[-1] == 'approval'
        return True
    result = supervision.run(config(path), 'PowerShell', tmp_path / 'runs',
        budget=Budget(steps=1), approval=approval, status=phases.append,
        client=LocalClient(f'http://127.0.0.1:{local_model.server_port}'))
    assert result['state']['accepted_calls'] == 1
    assert phases.index('fingerprint') < phases.index('model') < phases.index('approval') < phases.index('operation')
    assert 'finalizing' in phases


def test_foreign_case_id_stays_unexposed_not_claimed_to_be_foreign(tmp_path):
    from test_v4_worker import make_case
    from forensic_assistant.database.db import connect
    from v1_fixtures import process
    make_case(tmp_path / 'foreign.db')
    db = connect(tmp_path / 'foreign.db')
    try:
        foreign = process(db, 2, '30')['id']
    finally:
        db.close()
    assert foreign != EID
    worker = RecordingWorker({})
    result = controller.run({}, 'Inspect', tmp_path / 'runs', budget=Budget(steps=1),
        client=Scripted([tool('show_evidence', {'evidence_id': foreign})]), worker_factory=lambda _: worker)
    _, events = load(tmp_path / 'runs', result['investigation_id'])
    diagnostic = next(e['data']['diagnostic'] for e in events if e['kind'] == 'rejected')
    assert diagnostic['category'] == 'UNEXPOSED_EVIDENCE_ID'
    assert worker.calls == ['initial', 'check']

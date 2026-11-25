"""Actual spawned startup, synthetic SQLite and provider; no network requests."""
from copy import deepcopy
from dataclasses import asdict
import json

import pytest

from forensic_assistant.investigation_ai import autonomous, supervision, context_inspection as context
from forensic_assistant.investigation_ai.state import Budget, ContextBudget, execution_budget
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.llm.client import LocalClient
from forensic_assistant import assessment_handoff
from test_context_inspection import case
from test_assessment import accepted
from forensic_assistant.assessment_store import AssessmentStore
from forensic_assistant.briefing_store import digest
from test_autonomous_stage_a import grant
from test_follow_up_discovery import discovery_grant, final


@pytest.fixture
def saved(tmp_path):
    path = tmp_path/'case.db'
    g = case(path)
    revision = accepted(path, values=())
    store = AssessmentStore(path)
    plan = dict(case=store.identity, revision=revision['revision'], digest=revision['digest'], start=g['start'], end=g['end'], source_id=g['source_ids'][0], leads=[])
    records = {eid: dict(artifact='evtx', source_context={'source_ids':g['source_ids']}, match={'timestamps':[dict(timestamp_utc='2026-09-30T12:00:00Z', slot='recorded', meaning='synthetic metadata')], 'timestamps_truncated':True}) for eid in g['evidence_ids']}
    value = dict(id='a'*32, kind='case_assessment', case=store.identity, created=g['start'], status='COMPLETE_WITH_LIMITATIONS', plan=plan, authorization={'plan_digest':digest(plan)}, records=records, timeline=[], rows=[])
    store.save_assessment(value)
    return path, value


def synthetic_child(connection, gate, request):
    # Keep the real controller, budget reconstruction, handoff, journal and worker.
    class Provider:
        provider_name = 'openai'
        model_name = 'synthetic'
        def complete(self, messages, schema=None):
            assert sum(len(m['content'].encode('utf-8')) for m in messages) <= 24576
            return json.dumps(final(messages))
    def restore(*args):
        if request['config'].get('_test_failure') == 'provider':
            raise ValueError('private provider detail')
        return Provider()
    supervision.LocalClient = restore
    supervision.ModelBackend.restore = staticmethod(restore)
    if request['config'].get('_test_failure') == 'budget':
        request['budget']['prompt_bytes'] = 5600
    supervision._child(connection, gate, request)


def configured(saved):
    path, assessment = saved
    handoff = assessment_handoff.authorize(assessment_handoff.prepare(path, assessment['id'], 'Inspect recorded activity'), lambda _: True)
    rows = [dict(id=e, source_type=e.split(':')[0].lower()) for e in assessment['records']]
    g = discovery_grant(grant(path, rows))
    g.update(contract=context.CAPACITY_CONTRACT, context_inspection=deepcopy(context.LIMITS), tools=['show_evidence', 'follow_up', 'inspect_context'])
    g['limits']['prompt_bytes'] = 24576
    g['source_ids'] = sorted({s for r in assessment['records'].values() for s in r['source_context']['source_ids']})
    return dict(case_path=str(path), _stage_a=g, _stage_a_handoff=handoff, semantic_enabled=False)


def test_spawned_context_budget_handoff_readview_and_analysis(saved, tmp_path, monkeypatch):
    config = configured(saved)
    before = saved[0].read_bytes()
    monkeypatch.setattr(supervision, '_child', synthetic_child)
    phases = []
    from forensic_assistant.ai import settings
    from forensic_assistant.ai.backend import ModelBackend
    client = ModelBackend(config={**settings.defaults(), 'provider':'openai', 'model':'synthetic', 'cloud_acknowledged':True})
    result = supervision.run(config, config['_stage_a']['objective'], tmp_path/'runs', client=client, prepared_backend={'synthetic':True}, status=phases.append)
    assert result['validated_batches'] == len(config['_stage_a']['evidence_ids'])
    assert {'budget_validation', 'handoff_validation', 'transcript_init', 'read_transaction'} <= set(phases)
    assert result['termination'] == 'AUTHORIZED_PLAN_EXHAUSTED'
    manifest, events = load(tmp_path/'runs', result['investigation_id'])
    assert manifest['budgets']['prompt_bytes'] == 24576
    assert autonomous.reconstruct(tmp_path/'runs', result['investigation_id'])['findings'] == result['findings']
    assert saved[0].read_bytes() == before


@pytest.mark.parametrize('failure,reason', [('budget','BUDGET_CONTRACT_MISMATCH'), ('provider','PROVIDER_START_FAILURE'), ('handoff','HANDOFF_VALIDATION_FAILED')])
def test_spawned_safe_failure_categories(saved, tmp_path, monkeypatch, failure, reason):
    config = configured(saved)
    config['_test_failure'] = failure
    if failure == 'handoff': config['_stage_a_handoff']['authorization'] = 'invalid'
    monkeypatch.setattr(supervision, '_child', synthetic_child)
    result = supervision.run(config, config['_stage_a']['objective'], tmp_path/'runs', client=LocalClient())
    assert result['termination'] == reason
    assert result['startup_diagnostic']['cleanup_confirmed']
    assert not result['startup_diagnostic']['read_view_established']
    assert 'private provider detail' not in json.dumps(result)


def test_grant_budget_roundtrip_and_strict_mismatch(saved):
    config = configured(saved)
    assert type(execution_budget(config, serialized=asdict(ContextBudget()))) is ContextBudget
    for supplied in (Budget(), Budget(prompt_bytes=5600)):
        with pytest.raises(ValueError, match='BUDGET_CONTRACT_MISMATCH'):
            execution_budget(config, supplied=supplied)
    for wire in ({}, {**asdict(ContextBudget()), 'prompt_bytes':5600}, {**asdict(ContextBudget()), 'seconds':301}):
        with pytest.raises(ValueError, match='BUDGET_CONTRACT_MISMATCH'):
            execution_budget(config, serialized=wire)
    config['_stage_a']['contract'] = context.CONTRACT
    config['_stage_a']['limits']['prompt_bytes'] = 5600
    assert type(execution_budget(config, serialized=asdict(Budget()))) is Budget
    with pytest.raises(ValueError, match='BUDGET_CONTRACT_MISMATCH'):
        execution_budget(config, serialized=asdict(ContextBudget()))
    from forensic_assistant.investigation_ai import follow_up
    config['_stage_a']['contract'] = follow_up.CONTRACT
    config['_stage_a']['tools'] = ['show_evidence', 'follow_up']
    config['_stage_a'].pop('context_inspection')
    assert type(execution_budget(config, serialized=asdict(Budget()))) is Budget
    with pytest.raises(ValueError, match='BUDGET_CONTRACT_MISMATCH'):
        execution_budget(config, serialized=asdict(ContextBudget()))


def test_authorized_start_passes_selected_budget(saved, monkeypatch):
    config = configured(saved)
    monkeypatch.setattr(autonomous, 'prepare', lambda *a, **kw: (config['_stage_a'], {}))
    captured = {}
    def capture(*a, **kw): captured.update(kw)
    monkeypatch.setattr(supervision, 'run', capture)
    autonomous.start(config['_stage_a_handoff'], saved[1], object(), lambda _: True, follow_up=True)
    assert type(captured['budget']) is ContextBudget
    assert captured['budget'].prompt_bytes == 24576

"""Neutral recorded operations: synthetic histories, no provider or live case."""
from copy import deepcopy
from unittest.mock import patch

import pytest

from forensic_assistant.investigation_ai import (
    recorded, d2, synthesis, organization, question_assessment, packets, findings,
)
from forensic_assistant.investigation_ai.transcript import load
from forensic_assistant.reporting import recorded as reports
from test_explanation_live import execute
from test_explanation_replay_status import empty_run
from test_organization import rehash


@pytest.fixture(scope='module')
def source(tmp_path_factory):
    root = tmp_path_factory.mktemp('neutral-recorded')
    result, *_ = execute(root)
    return root/'runs', result['investigation_id']


@pytest.fixture(autouse=True)
def no_provider(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('provider entered during recorded reconstruction')
    monkeypatch.setattr('forensic_assistant.ai.backend.ModelBackend.complete', forbidden)


def test_public_defensive_projections_and_legacy_equivalence(source, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('case database opened')
    monkeypatch.setattr('sqlite3.connect', forbidden)
    root, run_id = source
    before = [(root/run_id/n).read_bytes() for n in ('manifest.json', 'events.jsonl')]
    history = recorded.open_history(*source)
    manifest, events = load(*source)
    assert history.binding() == dict(source=recorded._anchor(manifest, events), view=manifest['evidence_state'])
    facts = history.factual_state()
    assert facts == synthesis.reconstruct(*source)
    assert facts['validated_batches'] == 6
    assert history.organization_state() == organization.reconstruct(*source)
    assert history.question_assessment() == question_assessment._assess(manifest['question'], run_id, history.relationship_state())
    assert history.explanation_pages() and history.explanation_pages()[-1]['next_cursor'] is None
    saved = deepcopy(facts)
    facts['clauses'].clear()
    assert history.factual_state() == saved
    binding = history.binding(); binding['view'].clear()
    assert history.binding()['view'] == manifest['evidence_state']
    assert before == [(root/run_id/n).read_bytes() for n in ('manifest.json', 'events.jsonl')]


def test_restoration_reuse_and_complete_dependencies(source):
    history = recorded.open_history(*source)
    with patch.object(packets, '_rehydrate', wraps=packets._rehydrate) as restore:
        all_support = history.restore_all_support()
        count = restore.call_count
        assert count == len(history.factual_state()['clauses'])
        ids = list(all_support)
        bundles = history.restore_support(ids)
        assert bundles and history.restore_all_support() == all_support
        for edge in history.relationship_state()['relationships']:
            bundle = history.restore_support([edge['id']])[0]
            assert set(edge['endpoints']) <= set(bundle['clauses'])
        assert restore.call_count == count
    interpretations = [c for c in history.factual_state()['clauses'] if c['type'] == 'deterministic_interpretation']
    assert interpretations
    for clause in interpretations:
        bundle = history.restore_support([clause['id']])[0]
        assert bundle['interpretations'] and bundle['qualifications']
        assert bundle['leaves']  # Original premises, not a bare interpretation ID.
    all_support.clear()
    assert history.restore_all_support()


def test_operation_counts_and_independent_verification(source, tmp_path):
    with patch.object(recorded, 'load', wraps=recorded.load) as loads:
        history = recorded.open_history(*source)
        assert loads.call_count == 2  # Initial integrity and closing source anchor.
        history.factual_state(); history.relationship_state(); history.binding()
        assert loads.call_count == 2
        history.verify()
        assert loads.call_count == 3
    w = findings.create(tmp_path/'review.findings', *source, actor='Synthetic')
    ids = [c['id'] for c in history.factual_state()['clauses'] if c['type'] == 'observation']
    for revision in range(3):
        w.register(actor='Synthetic', expected_revision=revision, kind='analyst_hypothesis',
                   statement='Possible association, not established.', supporting_ids=ids[:1], contrary_ids=ids[1:2])
    with patch.object(recorded, 'load', wraps=recorded.load) as loads:
        assert len(w.export()['findings']) == 3
        assert loads.call_count == 4  # Open + binding boundary + export completion.
    with patch.object(recorded, 'load', wraps=recorded.load) as loads:
        projection = reports.build(*source)
        assert loads.call_count == 4  # Open + source boundary + completed projection.
    assert reports.build(*source, generation=projection['generation']) == projection


@pytest.mark.parametrize('kind', ['manifest', 'event', 'view'])
def test_stale_context_rejected(tmp_path, kind):
    result = empty_run(tmp_path, 'structure')
    source = tmp_path/'runs', result['investigation_id']
    history = recorded.open_history(*source)
    manifest, events = load(*source)
    if kind == 'manifest':
        manifest['status'] = 'synthetic-change'
    elif kind == 'view':
        manifest['evidence_state']['view_id'] = 'f'*32
    else:
        events[-1]['data']['synthetic_change'] = True
    rehash(source[0]/source[1], manifest, events)
    with pytest.raises(ValueError):
        history.verify()


def test_empty_and_incomplete(tmp_path):
    result = empty_run(tmp_path, 'structure')
    source = tmp_path/'runs', result['investigation_id']
    history = recorded.open_history(*source)
    assert history.factual_state()['clauses'] == []
    assert history.binding()['view'] and history.restore_all_support() == {}
    manifest, events = load(*source)
    events = [e for e in events if e['kind'] != 'terminal']
    manifest['status'] = 'running'
    rehash(source[0]/source[1], manifest, events)
    partial = recorded.open_history(*source)
    assert not partial.report_state()['execution']['terminal_present']


def test_corrupt_chain(tmp_path):
    result = empty_run(tmp_path, 'structure')
    source = tmp_path/'runs', result['investigation_id']
    path = source[0]/source[1]/'events.jsonl'
    raw = path.read_bytes()
    path.write_bytes(raw.replace(b'"hash":"', b'"hash":"f', 1))
    with pytest.raises(ValueError):
        recorded.open_history(*source)


def test_cached_projection_tampering_rejected(source):
    h = recorded.open_history(*source)
    h.restore_all_support()
    h._restored.clear()
    with pytest.raises(ValueError, match='TRUSTED_STATE_CHANGED'):
        h.restore_all_support()


def test_d2_adapter_has_identical_packets(source):
    neutral = recorded.open_history(*source)
    adapted = d2._History.adapt(neutral)
    direct = d2.open_history(*source)
    assert adapted.preview(exploratory=True) == direct.preview(exploratory=True)
    assert adapted.binding() == neutral.binding()

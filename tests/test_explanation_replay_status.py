"""Empty accepted state and diagnostic-only projections; synthetic providers only."""
from copy import deepcopy
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from forensic_assistant.investigation_ai import explanation_live as x, explanation_status as status
from forensic_assistant.investigation_ai import autonomous, relationships, synthesis
from forensic_assistant.investigation_ai.transcript import load, digest, JournalPublicationError
from test_explanation_live import synthetic
from test_synthesis_consumer import setup
from test_organization import rehash


def empty_run(path, failure):
    config, worker, client, seen, closed = setup(path)
    config['_live_explanation'] = True
    actions = list(client.actions)
    def fail(messages):
        if failure == 'interrupt':
            raise KeyboardInterrupt()
        if failure == 'delta':
            value = actions[1](messages)
            value['answer']['observed'][0]['field'] = '/invented'
            return value
        return {}
    client.actions = iter([actions[0], fail])
    result = autonomous.run(config, config['_stage_a']['objective'], path/'runs',
                            client=client, worker_factory=worker)
    assert closed and len(client.calls) == 2
    return result


@pytest.mark.parametrize('failure', ['structure', 'delta', 'interrupt'])
def test_zero_batch_registered_replay(tmp_path, failure, monkeypatch):
    result = empty_run(tmp_path, failure)
    expected = 'ANALYST_CANCELLED' if failure == 'interrupt' else 'VALIDATION_FAILURE'
    assert result['termination'] == expected and result['validated_batches'] == 0
    assert not result['findings']['observed'] and not result['findings']['interpretations']
    root, rid = tmp_path/'runs', result['investigation_id']
    before = [(root/rid/name).read_bytes() for name in ('manifest.json', 'events.jsonl')]
    manifest, events = load(root, rid)
    assert all(any(e['kind'] == kind for e in events) for kind in
               ('organization_final', 'organization_checkpoint', 'explanation_checkpoint', 'terminal'))
    def forbidden(*a, **kw):
        pytest.fail('Unexpected provider/database access')
    monkeypatch.setattr('sqlite3.connect', forbidden)
    monkeypatch.setattr('forensic_assistant.ai.backend.ModelBackend.complete', forbidden)
    rebuilt = x.reconstruct(root, rid)
    org = x.c1.reconstruct(root, rid)
    assert not rebuilt['clauses'] and not any(e['kind'] in ('finding', 'relationship') for e in org['entities'])
    assert digest(rebuilt['state']) == result['explanation']['digest']
    assert rebuilt['status']['currentness'] == 'current'
    assert rebuilt['status']['forensic_completeness'] == 'not_established'
    assert rebuilt['execution_outcome'] == expected
    session, replayed = x.session(root, rid)
    assert 'Recorded investigation outcome: '+expected in x.render(x.page(session, replayed))
    from forensic_assistant.investigation_ai.presentation import render
    human = render(result)
    assert 'Partial/stale' not in human and 'complete checkpoints committed' in human
    assert org['coverage'].get('observations', 0) == 0 and org['coverage'].get('interpretations', 0) == 0
    original = next(e for e in org['entities'] if e.get('role') == 'original_question')
    assert original['original_assessment'] == result['question_decomposition']['original_assessment']
    assert original['original_assessment']['status'] == 'NOT_ASSESSABLE'
    empty = relationships._build(synthesis._Reducer().finish())
    assert empty['relationships'] == [] and empty['factual']['clauses'] == []
    # Separate interpreters; no shared reducer/cache, no provider or case access.
    code = ('import sys;from unittest.mock import patch;'
            'from forensic_assistant.investigation_ai.explanation_live import reconstruct;'
            'from forensic_assistant.investigation_ai.transcript import digest;'
            'p=patch("sqlite3.connect",side_effect=AssertionError("database"));p.start();'
            'q=patch("forensic_assistant.ai.backend.ModelBackend.complete",side_effect=AssertionError("provider"));q.start();'
            'print(digest(reconstruct(sys.argv[1],sys.argv[2])))')
    outputs = [subprocess.check_output([sys.executable, '-B', '-c', code, str(root), rid]) for _ in range(2)]
    assert outputs[0] == outputs[1]
    assert before == [(root/rid/name).read_bytes() for name in ('manifest.json', 'events.jsonl')]


@pytest.mark.parametrize('cut', ['terminal', 'organization_final'])
def test_zero_batch_missing_finalization(tmp_path, cut):
    result = empty_run(tmp_path, 'structure');root = tmp_path/'runs';rid = result['investigation_id']
    manifest, events = load(root, rid)
    index = next(i for i,e in enumerate(events) if e['kind'] == cut)
    rehash(root/rid, manifest, events[:index])  # Disposable synthetic journal only.
    rebuilt = x.reconstruct(root, rid)
    assert rebuilt['incomplete'] and not rebuilt['terminal_present'] and not rebuilt['clauses']
    assert rebuilt['execution_outcome'] is None
    assert rebuilt['status']['processing'] != 'complete'
    if cut == 'organization_final':
        assert not rebuilt['status']['final_assessment_available']
        assert rebuilt['status']['currentness'] == 'unavailable'


def live_fixture(extra_questions=0):
    session, reducer, facts, make_receipt = synthetic()
    for n in range(extra_questions):
        key = digest(['synthetic-question', n])
        reducer.entities[key] = dict(id=key, kind='question', role='analysis_proposal',
            text='Unverified synthetic question', introduced_by={'contract':'synthetic'}, dependencies=[])
    receipt = make_receipt()
    reducer.revision = receipt['revision']
    organizer = SimpleNamespace(reducer=reducer, sources=reducer.sources, last_receipt=receipt,
                                disabled=False, finalization={'status':'checkpoint_committed'})
    transcript = SimpleNamespace(id=receipt['run_id'], count=receipt['event']['sequence']+1,
        chain=receipt['event']['hash'], size=1000, manifest=session.manifest,
        publication={'status':'confirmed'}, events=[])
    def append(kind, data):
        event = dict(sequence=transcript.count, kind=kind, data=data, previous=transcript.chain)
        event['hash'] = digest(event)
        transcript.events.append(event);transcript.count += 1;transcript.chain = event['hash']
        transcript.size += x.d1._size(event)+1
    def uncertain(stage):
        transcript.publication['status'] = 'uncertain'
        raise JournalPublicationError(stage)
    transcript.append = append;transcript._uncertain = uncertain
    return x.Live(transcript, organizer, facts), receipt


def test_oversized_receipt_with_no_operations_is_not_global_exhaustion():
    live, receipt = live_fixture(extra_questions=120)
    live.update(receipt, deadline=float('inf'))
    row = live.diagnostics['attempts'][-1];details = row['details']
    assert row['outcome'] == 'admission_rejected' and row['reason'] == 'event_byte_limit'
    assert row['prepared_operations'] == row['committed_operations'] == 0
    assert details['event_bytes'] > 8192
    assert details['global_bytes'] + details['event_bytes'] + details['future_reserved_bytes'] < x.MAX_BYTES
    assert not live.transcript.events and live.reducer.state['revision'] == 0
    status.validate(live.diagnostics)


@pytest.mark.parametrize('cause', ['event_byte_limit', 'local_journal_allocation_limit',
                                  'global_journal_reservation', 'journal_event_slot_limit'])
def test_independent_admission_diagnostics(cause, monkeypatch):
    live, receipt = live_fixture();before = deepcopy(live.reducer.state)
    if cause == 'event_byte_limit':
        size = x.d1._size
        monkeypatch.setattr(x.d1, '_size', lambda v: 8192 if isinstance(v, dict) and
            v.get('kind') == 'explanation_checkpoint' else size(v))
    elif cause == 'local_journal_allocation_limit':
        live.journal_bytes = 65536
    elif cause == 'global_journal_reservation':
        live.transcript.size = x.MAX_BYTES
    else:
        live.transcript.count = 256
        receipt['event']['sequence'] = 255
    live.update(receipt, deadline=float('inf'))
    assert live.reducer.state == before and not live.transcript.events
    row = live.diagnostics['attempts'][-1]
    assert row['reason'] == cause and row['outcome'] == 'admission_rejected'
    assert row['event_size_basis'] == 'measured' and row['committed_operations'] == 0
    assert row['details']['event_limit'] == 8192 and row['details']['global_limit'] == 4*1024*1024
    assert live.stops == ['journal_reservation']  # Legacy meaning is not rewritten.
    status.validate(live.diagnostics)


@pytest.mark.parametrize('limit,reason', [('operations','operation_limit'), ('visits','dependency_visit_limit')])
def test_prefix_limit_is_not_failed_publication(limit, reason, monkeypatch):
    live, receipt = live_fixture();monkeypatch.setitem(x.LIMITS, limit, 0)
    live.update(receipt, deadline=float('inf'))
    row = live.diagnostics['attempts'][-1]
    assert live.transcript.events and row['outcome'] == 'committed_prefix' and row['reason'] == reason
    assert live.reducer.state['pending'] and live.summary()['status']['processing'] == 'resource_limited'


def test_byte_prefix_and_complete_publication(monkeypatch):
    live, receipt = live_fixture()
    monkeypatch.setitem(x.LIMITS, 'event_bytes', 4000)
    live.update(receipt, deadline=float('inf'))
    row = live.diagnostics['attempts'][-1]
    assert row['outcome'] == 'committed_prefix' and row['reason'] == 'event_byte_limit'
    assert row['committed_operations'] > 0 and row['details']['event_bytes'] <= 8192
    status.validate(live.diagnostics)
    monkeypatch.undo()
    live, receipt = live_fixture()
    # A small synthetic source graph fits completely without modifying the selector.
    live.update(receipt, deadline=float('inf'))
    assert live.diagnostics['attempts'][-1]['outcome'] == 'committed_complete'


def test_unavailable_size_and_bounded_telemetry():
    live, receipt = live_fixture()
    for _ in range(20):
        live.update(receipt, deadline=0)
    assert len(live.diagnostics['attempts']) == 9 and live.diagnostics['omitted_attempts'] == 11
    row = live.diagnostics['attempts'][0]
    assert row['reason'] == 'processing_time_limit' and row['event_size_basis'] == 'unavailable'
    assert row['details'] is None and row['candidate_operations_considered'] is None
    status.validate(live.diagnostics)
    assert len(json.dumps(live.diagnostics).encode()) <= 8192
    assert 'reported_value' not in json.dumps(live.diagnostics)


def test_processing_overrun_is_explicit_without_changing_limit(monkeypatch):
    live, receipt = live_fixture()
    # Reject before preparation, then simulate time passing through finally.
    clock = iter([100.0, 101.1])
    monkeypatch.setattr(x.time, 'monotonic', lambda: next(clock))
    live.update(receipt, deadline=0)
    assert live.disabled and live.diagnostics['time_limit_exceeded']
    assert live.diagnostics['attempts'][0]['reason'] == 'processing_time_limit'
    assert x.LIMITS['seconds'] == 1.0 and not live.transcript.events
    status.validate(live.diagnostics)


@pytest.mark.parametrize('failure', ['append', 'fatal_append', 'commit'])
def test_uncertain_publication_remains_fatal(failure, monkeypatch):
    live, receipt = live_fixture()
    def fail(*a, **kw):
        if failure == 'fatal_append':
            raise JournalPublicationError('synthetic')
        raise OSError('synthetic')
    monkeypatch.setattr(live.reducer if failure == 'commit' else live.transcript,
                        'commit' if failure == 'commit' else 'append', fail)
    with pytest.raises(JournalPublicationError):
        live.update(receipt, deadline=float('inf'))
    assert live.reducer.state['revision'] == 0
    assert live.diagnostics['attempts'][-1]['outcome'] == 'publication_uncertain'
    assert live.diagnostics['attempts'][-1]['committed_operations'] == 0


def test_exact_frontier_currentness_and_independent_completeness():
    _, _, _, make_receipt = synthetic();receipt = make_receipt(6)
    state = dict(revision=5, frontier={'receipt':receipt}, pending=[], omitted=[], stop=None,
                 items={str(n):{} for n in range(60)}, coverage={'final_assessment_available':True,
                 'final_assessment_represented':True})
    view = status.project(state, deepcopy(receipt), False, finalized=True)
    assert view['currentness'] == 'current' and view['processing'] == 'complete' and view['upstream'] == 'partial'
    text = '\n'.join(status.lines(view))
    assert 'current at C1 revision 6' in text and '60 accepted; 0 pending; 0 omitted' in text
    assert 'Upstream organization: partial.' in text and 'Forensic completeness: not established.' in text
    for key in ('digest', 'event', 'source_frontier', 'read_view'):
        newer = deepcopy(receipt)
        if key == 'digest':newer[key] = 'a'*64
        elif key == 'read_view':newer[key]['view_id'] = 'b'*32
        else:newer[key]['hash'] = 'f'*64
        assert status.project(state, newer, False, finalized=True)['currentness'] == 'stale'
    assert status.project(state, None, None, finalized=False)['currentness'] == 'unavailable'


def test_diagnostic_contract_rejects_unbounded_or_sensitive_content():
    live, receipt = live_fixture();live.update(receipt, deadline=0)
    for change in ('version', 'extra', 'rows'):
        value = deepcopy(live.diagnostics)
        if change == 'version':value['contract'] = 'unknown'
        elif change == 'extra':value['attempts'][0]['evidence'] = 'not permitted'
        else:value['attempts'] *= 10
        with pytest.raises(ValueError):status.validate(value)

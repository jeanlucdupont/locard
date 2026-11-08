"""Stage A: synthetic scope authorization, relevance and bounded exposure."""
from contextlib import closing
from copy import deepcopy
import json
import pytest

from forensic_assistant.database.db import connect
from forensic_assistant.retrieval.temporal_scope import resolve, validate_proposal
from forensic_assistant.retrieval.planner import plan_question
from forensic_assistant.retrieval.evidence import EvidenceQueries
from forensic_assistant.investigation_ai import tools, controller
from forensic_assistant.investigation_ai.state import State, Budget, encoded
from forensic_assistant.investigation_ai.transcript import load
from test_evtx_content import add, DATA, SCOPE
from test_v4_controller import Scripted, tool

QUESTION = ('Investigate Microsoft Defender Event ID 1121 on September 30, 2026, '
            'between 14:05:40 and 14:06:10 UTC. Find original EVTX EventData mentioning '
            'baje.ps1. Determine what Defender recorded about attempted PowerShell execution.')


@pytest.mark.parametrize('question,hint,kind,start,end', [
    ('Events between 2026-09-30T14:05:40Z and 2026-09-30T14:06:10Z', None, 'explicit', '14:05:40', '14:06:10'),
    (QUESTION, None, 'explicit', '14:05:40', '14:06:10'),
    ('Events between 16:05:40 and 16:06:10 +02:00 on September 30, 2026', None, 'explicit', '14:05:40', '14:06:10'),
    ('Events between 16:05:40+02:00 and 16:06:10+02:00 on September 30, 2026', None, 'explicit', '14:05:40', '14:06:10'),
    ('Events on September 30, 2026', None, 'explicit', '00:00:00', '23:59:59'),
    ('Events on 2026-09-30', None, 'explicit', '00:00:00', '23:59:59'),
    ('Events between 14:05:40 and 14:06:10', '2026-09-30', 'explicit', '14:05:40', '14:06:10'),
    ('Events', '2026-09-30', 'explicit', '00:00:00', '23:59:59'),
    ('Events at 2026-09-30T14:05:40Z', None, 'exploratory', '14:00:40', '14:10:40'),
])
def test_temporal_forms(question, hint, kind, start, end):
    scope = resolve(question, hint)
    assert scope['kind'] == kind
    assert scope['start'].startswith('2026-09-30T' + start)
    assert scope['end'].startswith('2026-09-30T' + end)


@pytest.mark.parametrize('question,hint', [
    ('Events on September 30, 2026 between 14:05 and 14:06', None),
    ('Events at 2026-09-30T14:05:40', None),
    ('Events on 09/10/2026', None),
    ('Events on September 30', None),
    ('Events on 2026-09-30', '2026-06-03'),
    ('Events between 2026-09-30T00:00:00Z and 2026-10-02T00:00:00Z', None),
    ('Events between 14:06 and 14:05 UTC on 2026-09-30', None),
    ('Events on September 30, 2026 CST', None),
    ('Events between 14:05+02:00 and 14:06+01:00 on 2026-09-30', None),
    ('What happened before the event on September 30, 2026?', None),
])
def test_ambiguity_does_not_invent_authorization(question, hint):
    scope = resolve(question, hint)
    assert scope['kind'] == 'unresolved' and scope['limitation']
    assert 'start' not in scope


def test_contextual_date_and_earlier_evidence():
    assert resolve('September 30, 2026')['kind'] == 'inferred'
    assert resolve('What is on this drive? Reference September 30, 2026.')['kind'] == 'inferred'
    assert resolve('Compare events at 2026-09-30T14:05:40Z and 2026-09-30T14:06:10Z')['kind'] == 'unresolved'
    scope = resolve('What happened before the event on September 30, 2026?')
    assert scope['reference_date'] == '2026-09-30'
    validate_proposal(scope, 'search_evidence', dict(start='2026-09-29T00:00:00Z', end='2026-09-30T00:00:00Z'))


def test_known_date_never_scans_dates():
    with closing(connect(':memory:')) as db:
        statements = []
        db.set_trace_callback(statements.append)
        for q, hint in [(QUESTION, None), ('PowerShell at 14:05:40', '2026-09-30')]:
            plan_question(q, EvidenceQueries(db), hint)
        assert not any('SELECT DISTINCT substr(timestamp_utc' in s for s in statements)
        p = plan_question(QUESTION, EvidenceQueries(db))
        assert p.filters['end'].startswith('2026-09-30T14:06:10') and p.operation == 'search'


def test_explicit_date_remains_authoritative_with_default_anchor_window():
    scope = resolve('PowerShell at 00:01', '2026-09-30')
    assert scope['kind'] == 'explicit' and scope['start'].startswith('2026-09-30T00:00:00')
    assert scope['initial_start'] == scope['start']
    assert scope['initial_end'].startswith('2026-09-30T00:06:00')
    validate_proposal(scope, 'search_evidence', dict(start='2026-09-30T12:00:00Z', end='2026-09-30T13:00:00Z'))
    with pytest.raises(ValueError, match='Temporal scope conflict'):
        validate_proposal(scope, 'search_evidence', dict(start='2026-06-03T00:00:00Z', end='2026-06-03T00:01:00Z'))


@pytest.mark.parametrize('name,args', [
    ('search_evidence', dict(start='2026-06-03T14:05:40Z', end='2026-06-03T14:06:10Z')),
    ('timeline', dict(start='2026-09-30T14:05:40Z')),
    ('around', {}), ('process_tree', {}), ('session', {}),
    ('investigate_evidence', {}), ('detections', {}), ('semantic_search', {}),
])
def test_scope_cannot_be_expanded(name, args):
    with pytest.raises(ValueError, match='Temporal scope'):
        validate_proposal(resolve(QUESTION), name, args)


class MemoryWorker:
    """Real adapters, synthetic query-only database, fake containment transport."""
    def __init__(self, db, config):
        self.db, self.config, self.calls, self.closed = db, config, [], False
    def call(self, name, arguments=None, **kw):
        self.calls.append(name)
        result = (tools.initial(self.db, kw['question'], self.config) if name == 'initial' else
                  {} if name == 'check' else tools.execute(self.db, name, arguments, {'known_ids': kw['known_ids']}))
        return dict(result=result, fingerprint='f'*64, database_changes=0, schema=5, elapsed_seconds=0, semantic_available=False)
    def close(self):
        self.closed = True


def observed(messages):
    rows = json.loads(messages[1]['content'])['UNTRUSTED FORENSIC EVIDENCE']['records']
    record = next(r for r in rows if r.get('event_id') == 1121)
    i = next(i for i, field in enumerate(record['original_event_data']) if field['name'] == 'Target Commandline')
    return dict(action='final', answer=dict(observed=[dict(evidence_id=record['id'], field=f'/original_event_data/{i}/value')],
               relationships=[], detections=[], hypotheses=[], unknowns=[]))


def test_full_loop_empty_initial_rejection_cursor_and_grounding(tmp_path, monkeypatch):
    from forensic_assistant.retrieval import evtx_content
    monkeypatch.setattr(evtx_content, 'CANDIDATES', 2)
    with closing(connect(':memory:')) as db:
        for i in range(2): add(db, i, data=[('Text', 'unrelated')])
        expected = add(db, 2)
        db.execute('PRAGMA query_only=ON')
        before = db.total_changes
        scope = resolve(QUESTION)
        args = dict(artifact='evtx', event_id=1121, evtx_text='baje.ps1', start=scope['start'], end=scope['end'])
        wrong = {**args, 'start': '2026-06-03T14:05:40Z', 'end': '2026-06-03T14:06:10Z'}
        def continuation(messages):
            packet = json.loads(messages[1]['content'])['controller']
            assert packet['planning_only'] and not packet['evtx_content_search']['complete']
            return tool('search_evidence', {**args, 'evtx_after': packet['evtx_content_search']['next_cursor']})
        client = Scripted([tool('search_evidence', wrong), tool('search_evidence', args), continuation, observed])
        worker = MemoryWorker(db, {})
        approvals = []
        result = controller.run({}, QUESTION, tmp_path / 'runs', client=client,
                                approval=lambda p, _: approvals.append(p) or True, worker_factory=lambda _: worker)
        assert result['termination'] == 'ANSWER_SUPPORTED'
        assert len(approvals) == 2 and all(p['arguments']['start'] == scope['start'] for p in approvals)
        assert worker.calls == ['initial', 'search_evidence', 'search_evidence', 'check'] and worker.closed
        assert result['findings']['observed'][0]['evidence_ids'] == [expected]
        assert 'baje.ps1' in result['findings']['observed'][0]['reported_value']
        assert db.total_changes == before and max(result['metrics']['prompt_bytes']) <= 5600
        m, events = load(tmp_path / 'runs', result['investigation_id'])
        assert m['temporal_scope'] == scope and m['policy_version'] == 'v4-3'
        assert 'Temporal scope conflict' in next(e['data']['reason'] for e in events if e['kind'] == 'rejected')
        first = next(e['data']['content'] for e in events if e['kind'] == 'exposure')
        assert first['records'] == []
        # This fake transport is deliberately fingerprint-backed, exercising the
        # historical reporting adapter without weakening the read-view refusal.
        from forensic_assistant.reporting.transcripts import load as report_load
        loaded = report_load(tmp_path / 'runs', result['investigation_id'])
        assert loaded['findings'] == result['findings']
        manifest_path = tmp_path / 'runs' / result['investigation_id'] / 'manifest.json'
        m['temporal_scope'] = {'kind': 'none'}
        manifest_path.write_text(json.dumps(m), encoding='utf-8')
        with pytest.raises(ValueError, match='temporal scope'):
            report_load(tmp_path / 'runs', result['investigation_id'])


def test_budget_history_large_duplicates_and_exposure():
    with closing(connect(':memory:')) as db:
        eid = add(db, data=DATA + [('Repeated', 'A'*900), ('Repeated', 'B'*900)])
        result = tools.execute(db, 'search_evidence', dict(SCOPE, evtx_text='baje.ps1'), {})
        state = State(Budget()); state.scope = resolve(QUESTION)
        state.records['historical'] = {'id': 'historical', 'noise': 'x'*4000}
        state.ingest(result)
        state.path = [{'operation': 'search_evidence'}]*6
        state.steps = 7; state.accepted = 6
        feedback = {'category': 'INVALID_ARGUMENT', 'reason': 'x'*300, 'correction': 'y'*300}
        messages, exposed, size = state.prompt(QUESTION, state.applicable(False, []), [], feedback)
        assert size == sum(len(m['content'].encode()) for m in messages) <= 5600
        assert eid in {r['id'] for r in exposed['records']} and 'historical' not in {r['id'] for r in exposed['records']}
        from forensic_assistant.investigation_ai.projection import is_record_projection
        assert is_record_projection(exposed['records'][0], state.records[eid])
        if exposed['records'][0] != state.records[eid]:
            assert state.prompt_diagnostics['projected_records'] > 0
            assert any('omitted fields were not disclosed' in note for note in state.limits)
        assert json.loads(messages[1]['content'])['controller']['completed_tools'] == ['search_evidence']
        state.disclose(exposed)
        answer = observed(messages)['answer']
        assert state.render(answer)['observed']
        answer['observed'][0]['field'] = '/raw_xml'
        with pytest.raises(ValueError, match='unexposed'): state.render(answer)


def test_no_fitting_evidence_allows_planning_not_facts():
    state = State(Budget()); eid = 'EVTX:' + 'a'*64 + ':Offset:1'
    state.records[eid] = {'id': eid, 'original_event_data': [{'name': 'x', 'ordinal': 0, 'value': 'x'*6000, 'truncated': False}]}
    messages, exposed, size = state.prompt('Inspect', ['search_evidence'], [])
    assert exposed['records'] == [] and size <= 5600
    assert json.loads(messages[1]['content'])['controller']['planning_only']
    state.disclose(exposed)
    with pytest.raises(ValueError, match='unexposed'):
        state.render(dict(observed=[dict(evidence_id=eid, field='/original_event_data/0/value')],
                          relationships=[], detections=[], hypotheses=[], unknowns=[]))


def test_empty_planning_still_rejects_fabricated_facts_and_stops(tmp_path):
    with closing(connect(':memory:')) as db:
        worker = MemoryWorker(db, {})
        fabricated = dict(action='final', answer=dict(
            observed=[dict(evidence_id='EVTX:'+'a'*64+':Offset:1', field='/process_name')],
            relationships=[], detections=[], hypotheses=[], unknowns=[]))
        result = controller.run({}, QUESTION, tmp_path / 'runs', client=Scripted([fabricated]*3),
                                worker_factory=lambda _: worker)
        assert result['termination'] == 'TOO_MANY_REJECTIONS'
        assert result['state']['final_grounding_rejections'] == 3
        assert worker.calls == ['initial', 'check'] and not result['findings']['observed']


def test_empty_planning_model_steps_remain_bounded(tmp_path):
    with closing(connect(':memory:')) as db:
        worker = MemoryWorker(db, {})
        invalid = tool('search_evidence', {'sql': 'SELECT anything'})
        result = controller.run({}, QUESTION, tmp_path / 'runs', client=Scripted([invalid]*2),
                                budget=Budget(steps=2), worker_factory=lambda _: worker)
        assert result['termination'] == 'BUDGET_EXHAUSTED'
        assert result['state']['steps'] == 2 and result['state']['accepted_calls'] == 0
        assert worker.calls == ['initial', 'check']


from test_browser_ux import browser_case


def test_initial_browser_relevance_and_provenance(browser_case):
    with closing(connect(browser_case)) as db:
        before = db.total_changes
        result = tools.initial(db, 'Did powershell.exe execute on September 30, 2026?', {})
        assert result['records'] == [] and result['plan']['browser_available']
        result = tools.initial(db, 'Inspect browser downloads', {})
        assert result['records'] and all(r['artifact_type'] == 'browser_download' for r in result['records'])
        original = EvidenceQueries(db).search(artifact='browser', browser_kind='download', limit=20)
        assert result['records'] == [tools.compact(r) for r in original.records]
        assert all(r['source_context'] for r in result['records'])
        assert not tools.initial(db, 'Did missing.exe get downloaded?', {})['records']
        assert not tools.initial(db, 'Inspect browser downloads hostname missing-host', {})['records']
        assert db.total_changes == before


from test_mixed_temporal import mixed_case


def test_scoped_mixed_initial_and_limit(mixed_case):
    db, _, _, _ = mixed_case
    before = db.total_changes
    result = tools.initial(db, 'Inspect records on 2020-01-01', {})
    assert {r['source_type'] for r in result['records']} >= {'prefetch', 'registry'}
    assert all(r['source_context'] for r in result['records'])
    for i in range(25): add(db, i)
    before = db.total_changes
    result = tools.initial(db, 'Inspect Event ID 1121 on 2026-09-30', {})
    assert len(result['records']) == 20 and result['truncated']
    assert db.total_changes == before

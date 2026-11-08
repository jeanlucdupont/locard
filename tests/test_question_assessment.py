"""S3 deterministic rules, historical grounding and no false semantic authority."""
from copy import deepcopy
import json

import pytest

from forensic_assistant.investigation_ai import question_assessment as q, relationships as r, synthesis as s
from test_synthesis_relationships import clause, factual, temporal
from test_factual_clauses import reduced, VIEW

ASR = 'Does the examined evidence include a validated Defender ASR blocking interpretation?'


def assess(question, *clauses, **limits):
    return q._assess(question, 'a' * 32, temporal(*clauses), **limits)


@pytest.mark.parametrize('question,observation', [
    ('Does the examined Browser evidence record a download to "C:\\\\sample.zip"?',
     clause(r'C:\sample.zip', family='browser', pointer='/target_path')),
    ('Does the examined filesystem metadata record path "C:\\\\sample.zip"?',
     clause(r'C:\sample.zip', pointer='/objects/0')),
    ('Is event ID 1121 present in the inspected EVTX records?',
     clause(1121, family='evtx', pointer='/event_id')),
])
def test_direct_recorded_presence(question, observation):
    result = assess(question, observation)
    assert result['status'] == 'SUPPORTED_WITHIN_SCOPE'
    assert result['propositions'][0]['direct_clauses'] == [observation['id']]
    assert result['question'] == question
    assert result['propositions'][0]['new_evidence_search'] == 'not_searched'
    assert 'No new evidence search' in q.render(result)


def test_recognized_asr_and_qualifications():
    state = r._build(reduced())
    result = q._assess(ASR, 'b' * 32, state)
    assert result['status'] == 'SUPPORTED_WITHIN_SCOPE'
    direct = result['propositions'][0]['direct_clauses']
    assert len(direct) == 1
    interpretation = next(c for c in state['factual']['clauses'] if c['id'] in direct)
    assert interpretation['interpretation_ids']
    assert 'does not establish successful' in q.render(result)
    assert result['evidence'] == state


@pytest.mark.parametrize('question', ['Did "script.ps1" execute?', 'Did "download.zip" cause "PowerShell activity"?'])
def test_context_never_establishes_execution_or_causality(question):
    result = q._assess(question, 'a' * 32, r._build(reduced()))
    assert result['status'] == 'UNRESOLVED'
    row = result['propositions'][0]
    assert not row['direct_clauses'] and not row['contradictory_clauses']
    assert row['contextual_clauses'] and row['support_search'] == 'unsupported'
    assert 'outcome or its negation' in row['gaps'][0]


def test_exact_field_equality_and_contradiction_preserve_type():
    c = clause(1121, family='evtx', pointer='/event_id')
    for expected, status in [('1121', 'SUPPORTED_WITHIN_SCOPE'), ('1122', 'CONTRADICTED'), ('"1121"', 'CONTRADICTED')]:
        result = assess(f'Does clause {c["id"]} report {expected}?', c)
        assert result['status'] == status
        assert result['propositions'][0]['contradictory_clauses'] == ([c['id']] if status == 'CONTRADICTED' else [])


def test_comparable_conflict_does_not_pick_one_field_value():
    a = clause('A', family='evtx', pointer='/original_event_data/0/value', name='Target')
    b = clause('B', family='evtx', pointer='/original_event_data/0/value', name='Target')
    result = assess(f'Does clause {a["id"]} report "A"?', a, b)
    assert result['status'] == 'UNRESOLVED'
    assert result['propositions'][0]['conflicting_supports']
    assert not result['propositions'][0]['direct_clauses']


def test_missing_presence_is_not_negative():
    result = assess('Is event ID 1121 present in the inspected EVTX records?', clause(1, family='evtx', pointer='/event_id'))
    assert result['status'] == 'UNRESOLVED'
    assert result['propositions'][0]['support_search'] == 'no_match'
    assert 'not proof of absence' in result['propositions'][0]['gaps'][0]


@pytest.mark.parametrize('question', ['What happened?', 'Did script.ps1 execute and cause the attack?',
    'What supports the suspected sequence, and did the PowerShell script execute?',
    ASR + ' and did it execute?', 'Did "script.ps1" never execute?'])
def test_unknown_or_ambiguous_question_is_never_silently_narrowed(question):
    result = q._assess(question, 'a' * 32, r._build(reduced()))
    assert result['question'] == question
    assert result['status'] == 'NOT_ASSESSABLE'
    assert result['propositions'][0]['type'] == 'unmapped'
    assert result['propositions'][0]['contextual_clauses']
    assert not result['propositions'][0]['direct_clauses']


def test_explicit_compound_is_partial_and_preserves_original():
    question = ASR + '; Did "some-script.ps1" execute?'
    result = q._assess(question, 'a' * 32, r._build(reduced()))
    assert result['question'] == question
    assert result['status'] == 'PARTIALLY_SUPPORTED'
    assert [p['status'] for p in result['propositions']] == ['SUPPORTED_WITHIN_SCOPE', 'UNRESOLVED']
    assert len({p['id'] for p in result['propositions']}) == 2


def test_semicolon_in_literal_not_a_subquestion():
    c = clause('a;b', family='evtx', pointer='/original_event_data/0/value', name='Name')
    result = assess(f'Does clause {c["id"]} report "a;b"?', c)
    assert result['status'] == 'SUPPORTED_WITHIN_SCOPE' and len(result['propositions']) == 1


def test_recorded_order_supported_and_reverse_contradicted():
    a, b = clause('2026-01-01T00:00:00Z'), clause('2026-01-01T00:00:03Z', number=1)
    question = f'Do recorded UTC values for clause {a["id"]} precede clause {b["id"]}?'
    result = assess(question, a, b)
    assert result['status'] == 'SUPPORTED_WITHIN_SCOPE'
    assert result['propositions'][0]['direct_relationships']
    reverse = assess(f'Do recorded UTC values for clause {b["id"]} precede clause {a["id"]}?', a, b)
    assert reverse['status'] == 'CONTRADICTED'
    assert reverse['propositions'][0]['contradictory_relationships']
    assert 'physical_event_order' in json.dumps(result['evidence'])


def test_sparse_unknown_timezone_not_extra_edge():
    a = clause('2026-01-01T00:00:00')
    b = clause('2026-01-01T00:00:03Z', number=1, source='other')
    question = f'Do recorded UTC values for clause {a["id"]} precede clause {b["id"]}?'
    result = assess(question, a, b)
    assert result['status'] == 'UNRESOLVED'
    assert not result['propositions'][0]['direct_relationships']
    assert result['evidence']['coverage']['incomplete']


def test_no_transitive_edge_from_display_order():
    rows = [clause(f'2026-01-01T00:00:0{i*2}Z', number=i) for i in range(3)]
    result = assess(f'Do recorded UTC values for clause {rows[0]["id"]} precede clause {rows[2]["id"]}?', *rows)
    assert result['status'] == 'UNRESOLVED'
    assert result['propositions'][0]['support_search'] == 'no_match'


def test_missing_clause_truncation_and_empty_state():
    assert assess('What happened?')['status'] == 'NOT_ASSESSABLE'
    assert assess(ASR)['status'] == 'NOT_ASSESSABLE'
    result = assess('Does clause ' + 'f' * 64 + ' report 1?')
    assert result['status'] == 'NOT_ASSESSABLE'
    c = clause(1121, family='evtx', pointer='/event_id', shortened=True)
    result = assess(f'Does clause {c["id"]} report 1121?', c)
    assert result['status'] == 'NOT_ASSESSABLE'
    assert result['propositions'][0]['support_search'] == 'incomplete'


def test_budget_exhaustion_reports_unassessed_not_absent():
    rows = [clause(i, family='evtx', pointer='/event_id', number=i) for i in range(s.MAX_CLAUSES)]
    result = assess('Is event ID 1121 present in the inspected EVTX records?', *rows, check_limit=1)
    assert result['metrics']['support_checks'] == 1
    assert result['metrics']['unassessed_candidates'] == 95
    assert result['propositions'][0]['support_search'] == 'incomplete'
    assert result['status'] != 'CONTRADICTED'
    question = ';'.join([ASR] * 9)
    limited = assess(question)
    assert limited['status'] == 'NOT_ASSESSABLE'
    assert limited['question'] == question and len(limited['propositions']) == 1


def test_multisource_context_does_not_merge_identity():
    a = clause(r'C:\file.ps1', pointer='/objects/0', source='source-a')
    b = clause(r'C:\file.ps1', number=1, pointer='/objects/0', source='source-b')
    result = assess('Did "file.ps1" execute?', a, b)
    assert result['status'] == 'UNRESOLVED'
    assert result['evidence']['factual']['clauses'] == [a, b]
    assert {c['supports'][0]['context']['source_context']['source_ids'][0] for c in result['evidence']['factual']['clauses']} == {'source-a', 'source-b'}


@pytest.mark.parametrize('change', ['id', 'interpretation', 'source', 'view', 'relationship'])
def test_tampered_support_fails_closed(change):
    state = r._build(reduced())
    c = state['factual']['clauses'][0]
    if change == 'id':
        c['id'] = 'f' * 64
    elif change == 'source':
        c['supports'][0]['context']['source_context'] = {'source_ids': ['forged']}
    elif change == 'view':
        c['evidence_state']['view_id'] = 'b' * 32
    elif change == 'interpretation':
        next(c for c in state['factual']['clauses'] if c['interpretation_ids'])['interpretation_ids'] = ['forged']
    else:
        state['relationships'].append({'predicate': 'caused_execution', 'endpoints': [c['id'], c['id']]})
    with pytest.raises(ValueError):
        q._assess(ASR, 'a' * 32, state)


def test_hypotheses_remain_unverified_and_status_tampering_rejected():
    state = r._build(reduced())
    state['factual']['hypotheses'] = [{'statement': 'Successful execution occurred', 'verification': 'UNVERIFIED', 'alternatives': ['It did not.']}]
    result = q._assess('Did "file.ps1" execute?', 'a' * 32, state)
    assert result['status'] == 'UNRESOLVED'
    assert not result['propositions'][0]['direct_clauses']
    assert 'Unverified hypotheses' in q.render(result)
    result['status'] = 'SUPPORTED_WITHIN_SCOPE'
    with pytest.raises(ValueError, match='derivation'):
        q.render(result)


def test_public_reconstruction_original_question_and_no_writes(tmp_path, monkeypatch, capsys):
    import sys
    from test_autonomous_stage_a import setup
    from forensic_assistant.investigation_ai import autonomous
    from forensic_assistant.reporting.transcripts import load
    config, worker, client, _, _ = setup(tmp_path, count=6)
    result = autonomous.run(config, config['_stage_a']['objective'], tmp_path/'runs', client=client, worker_factory=worker)
    root, identity = tmp_path/'runs', result['investigation_id']
    before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
    original_s1, original_s2 = s.reconstruct(root, identity), r.reconstruct(root, identity)
    first = q.reconstruct(root, identity)
    assert first == q.reconstruct(root, identity)
    assert first['question'] == config['_stage_a']['objective']
    assert first['investigation_termination'] == 'AUTHORIZED_PLAN_EXHAUSTED'
    assert first['evidence'] == original_s2 and first['evidence']['factual'] == original_s1
    assert len(client.calls) == 6 and before == {p: p.read_bytes() for p in before}
    with pytest.raises(ValueError, match='Incremental report import'):
        load(root, identity)
    monkeypatch.setattr(sys, 'argv', ['synthesis', str(root), identity, '--assessment', '--json'])
    s.main()
    assert json.loads(capsys.readouterr().out) == first
    assert q.render(first)


def test_failed_investigation_without_accepted_batches_is_not_negative(tmp_path):
    from test_autonomous_stage_a import setup
    from forensic_assistant.investigation_ai import autonomous
    def failed(messages):
        raise ValueError('synthetic provider failure')
    config, worker, client, _, _ = setup(tmp_path, actions=[failed])
    result = autonomous.run(config, config['_stage_a']['objective'], tmp_path/'runs', client=client, worker_factory=worker)
    rebuilt = q.reconstruct(tmp_path/'runs', result['investigation_id'])
    assert rebuilt['status'] == 'NOT_ASSESSABLE'
    assert rebuilt['investigation_termination'] == 'PROVIDER_FAILURE'
    assert rebuilt['recorded_source_view'] is not None and rebuilt['evidence_state'] is None
    assert 'PROVIDER_FAILURE' in q.render(rebuilt)


def test_exact_presence_matching_does_not_normalize_paths():
    c = clause(r'C:\Sample.zip', family='browser', pointer='/target_path')
    question = 'Does the examined Browser evidence record a download to "C:\\\\sample.zip"?'
    result = assess(question, c)
    assert result['status'] == 'UNRESOLVED'
    assert not result['propositions'][0]['direct_clauses']


def test_bounded_partial_compound_does_not_claim_all_propositions_assessed():
    c = clause(1121, family='evtx', pointer='/event_id')
    question = f'Does clause {c["id"]} report 1121?; Does clause {c["id"]} report 1121?'
    result = assess(question, c, check_limit=1)
    assert result['status'] == 'PARTIALLY_SUPPORTED'
    assert result['metrics']['unassessed_candidates'] == 1
    assert result['propositions'][1]['status'] == 'NOT_ASSESSABLE'


def test_unknown_question_keeps_model_hypotheses_out_of_direct_support():
    state = r._build(reduced())
    state['factual']['hypotheses'] = [{'statement': ASR, 'alternatives': ['unknown']}]
    result = q._assess('Tell me what happened and why.', 'a' * 32, state)
    assert result['status'] == 'NOT_ASSESSABLE'
    assert result['metrics']['direct_supports'] == 0


def test_render_escapes_control_characters_in_question_and_values():
    question = 'What happened?\x1b[31m'
    result = assess(question, clause('test\x1b[31m', pointer='/objects/0'))
    assert '\x1b' not in q.render(result)


def test_question_and_proposition_ids_are_deterministic_and_scoped():
    state = r._build(reduced())
    a = q._assess(ASR, 'a' * 32, state)
    b = q._assess(ASR, 'b' * 32, state)
    assert a == q._assess(ASR, 'a' * 32, state)
    assert a['question_id'] != b['question_id']
    assert a['propositions'][0]['id'] != b['propositions'][0]['id']


def test_shortened_presence_candidate_reports_incomplete_not_clean_no_match():
    c = clause(1121, family='evtx', pointer='/event_id', shortened=True)
    result = assess('Is event ID 1121 present in the inspected EVTX records?', c)
    assert result['status'] == 'UNRESOLVED'
    assert result['propositions'][0]['support_search'] == 'incomplete'
    assert result['propositions'][0]['incomplete_support_candidates'] == 1

"""S1: synthetic recorded-view grounding, no live provider or protected case."""
from copy import deepcopy
import json

import pytest

from forensic_assistant.investigation_ai import autonomous, disclosure, synthesis as s
from forensic_assistant.investigation_ai.state import State, Budget
from forensic_assistant.investigation_ai.transcript import digest
from test_compact_disclosure import records, envelope, answer
from test_autonomous_stage_a import setup

VIEW = {'contract': 'sqlite-read-view-v1', 'view_id': 'a' * 32,
        'file_identity': {'device': 1, 'inode': 1}}


def batch(rows=None, view=None, number=1, previous=None, reverse=False):
    state = State(Budget())
    state.compact_final = True
    state.finalization_requested = True
    for record in rows or records():
        state.ingest(envelope([record]), operation='show_evidence')
    _, packet, _ = state.prompt('PowerShell download metadata', [], [])
    state.disclose(packet)
    proposal = dict(action='final', answer=answer(packet))
    if reverse:
        proposal['answer']['observed'].reverse()
    findings = state.render(proposal['answer'])
    delta = dict(contract=autonomous.DELTA, id=digest(proposal), evidence_state=view or VIEW,
                 disclosure_sha256=digest(packet), proposal=proposal, findings=findings,
                 batch=number, based_on=previous)
    return state, delta, packet


def reduced(*args, **kwargs):
    reducer = s._Reducer()
    reducer.consume(*batch(*args, **kwargs))
    return reducer.finish()


def test_multi_family_exact_grounding_and_interpretation():
    state, delta, packet = batch()
    reducer = s._Reducer()
    reducer.consume(state, delta, packet)
    result = reducer.finish()
    observations = [c for c in result['clauses'] if c['type'] == 'observation']
    assert len(observations) == len(delta['findings']['observed'])
    for clause in observations:
        support = clause['supports'][0]
        expected = next(o for o in delta['findings']['observed']
                        if o['evidence_ids'][0] == support['evidence_id'] and o['field'] == support['field']['pointer'])
        assert support['field']['value'] == expected['reported_value']
        assert clause['evidence_state'] == VIEW
        assert clause['lineage'][0]['disclosure_sha256'] == digest(packet)
        assert clause['id'] == digest({k: v for k, v in clause.items() if k not in ('id', 'lineage')})
    assert {c['predicate'] for c in result['clauses']} >= {
        'browser_download_field', 'mft_metadata_field', 'evtx_recorded_field',
        'prefetch_metadata_field', 'defender_asr_block'}
    interpreted = next(c for c in result['clauses'] if c['type'] == 'deterministic_interpretation')
    assert interpreted['interpretation_ids'] == [delta['findings']['interpretations'][0]['interpretation_id']]
    assert any('does not establish successful' in q for q in interpreted['qualifications'])
    assert interpreted['supports'][0]['premises']['event_id'] == 1121
    assert 'not revalidated against the current case' in s.render(result)


def test_dedup_and_order_independent_of_proposal_dictionary_order():
    first = batch()
    reducer = s._Reducer()
    reducer.consume(*first)
    before = reducer.finish()['clauses']
    second = batch(number=2, previous=first[1]['id'], reverse=True)
    reducer.consume(*second)
    after = reducer.finish()['clauses']
    assert [c['id'] for c in before] == [c['id'] for c in after]
    assert all(len(c['lineage']) == 2 for c in after)
    reversed_rows = [{k: v for k, v in reversed(list(r.items()))} for r in records()]
    assert reduced(rows=reversed_rows)['clauses'] == reduced()['clauses']


def test_cross_batch_accumulation():
    reducer = s._Reducer()
    first = batch(rows=records()[:2])
    reducer.consume(*first)
    reducer.consume(*batch(rows=records()[2:], number=2, previous=first[1]['id']))
    assert len(reducer.finish()['coverage']['represented_record_ids']) == 6


@pytest.mark.parametrize('change', ['value', 'view', 'source', 'qualification', 'pointer'])
def test_identity_changes_with_support(change):
    rows = [records()[2]]
    baseline = reduced(rows=rows)
    view = deepcopy(VIEW)
    if change == 'view':
        view['view_id'] = 'b' * 32
    elif change == 'value':
        rows[0]['objects'] = ['different.zip']
    elif change == 'source':
        rows[0]['source_context'] = {'source_ids': ['different-source']}
    elif change == 'qualification':
        rows[0]['coverage_notes'] = ['original_fields_omitted']
    else:
        rows[0]['timestamps'][0]['slot'] = 'fn:0'
    result = reduced(rows=rows, view=view)
    assert {c['id'] for c in result['clauses']} != {c['id'] for c in baseline['clauses']}


def test_multiple_slots_and_unknown_timezone_preserved():
    row = records()[2]
    row['timestamps'] = [dict(utc='unknown', type=kind, slot=slot, meaning='timezone unknown')
                         for kind, slot in [('SI Created', 'si:c'), ('FN Created', 'fn:0:c')]]
    result = reduced(rows=[row])
    clauses = [c for c in result['clauses'] if 'timestamp' in c['supports'][0]]
    assert len(clauses) == 2
    assert {c['supports'][0]['timestamp']['slot'] for c in clauses} == {'si:c', 'fn:0:c'}
    assert all(c['supports'][0]['field']['value'] == 'unknown' for c in clauses)
    assert 'timezone unknown' in s.render(result)
    assert all(any('not inferred' in q for q in c['qualifications']) for c in clauses)


def test_prefetch_reference_and_truncation_not_execution():
    row = records()[-1]
    row['objects'] = ['suspicious.ps1']
    row['coverage_notes'] = ['original_fields_omitted']
    result = reduced(rows=[row])
    text = s.render(result)
    assert 'Referenced files are not executed images' in text
    assert 'bounded/truncated' in text and 'absence is not established' in text
    assert 'original_fields_omitted' in text


@pytest.mark.parametrize('change', ['value', 'pointer', 'interpretation', 'disclosure', 'hypothesis'])
def test_reject_invalid_accepted_support(change):
    state, delta, packet = batch()
    if change == 'value':
        delta['findings']['observed'][0]['reported_value'] = True
    elif change == 'pointer':
        delta['proposal']['answer']['observed'][0]['field'] = '/invented'
    elif change == 'interpretation':
        delta['findings']['interpretations'][0]['text'] = 'execution proved'
    elif change == 'disclosure':
        packet['records'][0]['observations'][0][2] = 'forged'
    else:
        delta['findings']['observed'].append({'classification': 'HYPOTHESIS', 'evidence_ids': ['syntactic-id']})
    with pytest.raises(ValueError):
        s._Reducer().consume(state, delta, packet)


def test_hypotheses_are_not_clauses():
    state, delta, packet = batch()
    delta['proposal']['answer']['hypotheses'] = [dict(statement='A download caused execution.',
        evidence_ids=[records()[0]['id']], alternatives=['The events may be unrelated.'])]
    delta['findings'] = state.render(delta['proposal']['answer'])
    reducer = s._Reducer()
    reducer.consume(state, delta, packet)
    result = reducer.finish()
    assert result['hypotheses']
    assert 'A download caused execution' not in json.dumps(result['clauses'])
    assert 'Unverified hypotheses' in s.render(result)


def test_cross_view_rejected_and_budget_bounded(monkeypatch):
    reducer = s._Reducer()
    first = batch()
    reducer.consume(*first)
    view = dict(VIEW, view_id='b' * 32)
    with pytest.raises(ValueError, match='view chain'):
        reducer.consume(*batch(number=2, previous=first[1]['id'], view=view))
    monkeypatch.setattr(s, 'MAX_CLAUSES', 1)
    with pytest.raises(ValueError, match='count budget'):
        reduced()
    monkeypatch.setattr(s, 'MAX_RESULT_BYTES', 100)
    with pytest.raises(ValueError, match='serialization budget'):
        reduced(rows=[records()[0]])


@pytest.mark.parametrize('change', ['contract', 'predicate', 'rule', 'qualifications', 'value'])
def test_renderer_rejects_tampered_contracts(change):
    result = reduced()
    clause = result['clauses'][0]
    if change == 'value':
        clause['arguments']['value'] = 'forged'
    elif change == 'qualifications':
        clause[change] = []
    else:
        clause[change] = 'caused_successful_execution'
    with pytest.raises(ValueError):
        s.render(result)


def test_reconstruction_no_provider_and_preserves_stage_a(tmp_path):
    config, worker, client, seen, closed = setup(tmp_path, count=6)
    result = autonomous.run(config, config['_stage_a']['objective'], tmp_path/'runs', client=client, worker_factory=worker)
    baseline = autonomous.reconstruct(tmp_path/'runs', result['investigation_id'])
    before = {p: p.read_bytes() for p in (tmp_path/'runs').rglob('*') if p.is_file()}
    calls = len(client.calls)
    one = s.reconstruct(tmp_path/'runs', result['investigation_id'])
    two = s.reconstruct(tmp_path/'runs', result['investigation_id'])
    assert one == two and one['validated_batches'] == 6
    assert len(one['coverage']['represented_record_ids']) == 6
    assert len(client.calls) == calls
    assert autonomous.reconstruct(tmp_path/'runs', result['investigation_id']) == baseline
    assert before == {p: p.read_bytes() for p in before}
    assert 'synthesis' not in result


def test_untrusted_control_characters_are_escaped():
    row = records()[2]
    row['objects'] = ['bad\x1b[31m\nvalue']
    text = s.render(reduced(rows=[row]))
    assert '\x1b' not in text and '\\u001b' in text


def test_rule_version_participates_in_identity(monkeypatch):
    before = reduced()
    rules = dict(s.RULES)
    rules['mft_metadata_field'] = ('mft-metadata-field-v2', rules['mft_metadata_field'][1])
    monkeypatch.setattr(s, 'RULES', rules)
    after = reduced()
    for left, right in zip(before['clauses'], after['clauses']):
        assert (left['id'] != right['id']) == (left['predicate'] == 'mft_metadata_field')


def test_generic_fallback_does_not_invent_semantics():
    row = records()[0]
    row['id'] = row['id'].replace(':download:', ':visit:')
    result = reduced(rows=[row])
    assert all(c['predicate'] == 'record_reports_field' for c in result['clauses'])
    assert 'The browser download record' not in s.render(result)


def test_forged_interpretation_even_with_new_hash_rejected():
    result = reduced()
    clause = next(c for c in result['clauses'] if c['type'] == 'deterministic_interpretation')
    old = clause['arguments']['text']
    clause['arguments']['text'] = 'Successful execution proved.'
    clause['qualifications'] = sorted('Successful execution proved.' if q == old else q for q in clause['qualifications'])
    clause['id'] = digest({k: v for k, v in clause.items() if k not in ('id', 'lineage')})
    with pytest.raises(ValueError, match='interpretation render contract'):
        s.render(result)


def test_batch_and_clause_bytes_limits(monkeypatch):
    reducer = s._Reducer()
    first = batch()
    reducer.consume(*first)
    monkeypatch.setattr(s, 'MAX_BATCHES', 1)
    with pytest.raises(ValueError, match='batch budget'):
        reducer.consume(*batch(number=2, previous=first[1]['id']))
    monkeypatch.setattr(s, 'MAX_CLAUSE_BYTES', 32)
    with pytest.raises(ValueError, match='serialization budget'):
        reduced()


def test_report_import_remains_forbidden(tmp_path):
    from forensic_assistant.reporting.transcripts import load as report_load
    config, worker, client, _, _ = setup(tmp_path)
    result = autonomous.run(config, config['_stage_a']['objective'], tmp_path/'runs', client=client, worker_factory=worker)
    s.reconstruct(tmp_path/'runs', result['investigation_id'])
    with pytest.raises(ValueError, match='Incremental report import'):
        report_load(tmp_path/'runs', result['investigation_id'])


def test_transcript_tampering_fails_before_clause_output(tmp_path):
    config, worker, client, _, _ = setup(tmp_path)
    result = autonomous.run(config, config['_stage_a']['objective'], tmp_path/'runs', client=client, worker_factory=worker)
    events = tmp_path/'runs'/result['investigation_id']/'events.jsonl'
    events.write_bytes(events.read_bytes().replace(b'validated_delta', b'validated_deltX', 1))
    with pytest.raises(ValueError, match='integrity'):
        s.reconstruct(tmp_path/'runs', result['investigation_id'])


def test_source_projection_change_after_disclosure_is_rejected():
    state, delta, packet = batch()
    eid = packet['records'][0]['id']
    state.records[eid]['source_context'] = {'source_ids': ['substituted']}
    with pytest.raises(ValueError, match='source projection changed'):
        s._Reducer().consume(state, delta, packet)

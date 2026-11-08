"""Synthetic S2 rule boundaries; no provider, original case or sidecar writes."""
from copy import deepcopy
import json

import pytest

from forensic_assistant.investigation_ai import relationships as r, synthesis as s
from forensic_assistant.investigation_ai.disclosure import descriptor, provenance
from forensic_assistant.investigation_ai.transcript import digest
from test_factual_clauses import VIEW


def clause(value, *, number=0, family='mft', pointer='/timestamps/0/utc', slot='si:c',
           source='source-a', name='ProcessGuid', view=None, shortened=False, extra_time=None):
    """Application-built S1 units for isolated rule tests; journal tests below
    exercise the actual public grounding entry point instead of this factory."""
    eid = family.upper() + ':' + digest(number) + ':Offset:' + str(number)
    if family == 'browser':
        eid = 'BROWSER:' + digest(number) + ':download:' + str(number)
    stamp = dict(utc=value, slot=slot, type=slot, meaning='recorded', **(extra_time or {}))
    record = dict(id=eid, source_type=family, timestamps=[stamp, stamp],
                  source_context={'source_ids': [source], 'basis': 'analyst assertion'},
                  original_event_data=[{'name': name, 'ordinal': 3, 'value': value, 'truncated': shortened}])
    field = descriptor(record, pointer, value)
    support = dict(evidence_id=eid, field=field, source_type=family,
                   provenance=provenance(record), context=s._context(record))
    if pointer.startswith('/timestamps/'):
        support['timestamp'] = stamp
    if shortened:
        support['context']['truncated_fields'] = [pointer]
    predicate = s._predicate(family, eid, pointer)
    body = s._body(view or VIEW, predicate, support)
    return dict(body, id=digest(body), lineage=[{'delta_id': 'synthetic', 'disclosure_sha256': digest(value)}])


def factual(*clauses):
    return dict(contract=s.RESULT, recorded_not_revalidated=True, evidence_state=deepcopy(VIEW),
                clauses=list(clauses), hypotheses=[], unresolved_questions=[], coverage={}, limitations=[])


def temporal(*clauses, **limits):
    return r._build(factual(*clauses), **limits)


def test_strict_recorded_order_preserves_support_and_limits():
    a = clause('2026-01-01T00:00:00Z')
    b = clause('2026-01-01T00:00:03+00:00', number=1, family='evtx', pointer='/timestamp_utc')
    out = temporal(a, b)
    edge, = out['relationships']
    assert edge['predicate'] == 'recorded_time_before'
    assert edge['endpoints'] == [a['id'], b['id']]
    assert edge['supports'] == a['supports'] + b['supports']
    assert edge['semantics']['physical_event_order'] == 'not established'
    assert set(a['qualifications']) <= set(edge['qualifications'])
    assert 'physical event order is not established' in r.render(out)
    assert edge['id'] == digest({k: v for k, v in edge.items() if k not in ('id', 'lineage')})


@pytest.mark.parametrize('later', ['2026-01-01T00:00:00Z', '2026-01-01T00:00:00.500Z', '2026-01-01T00:00:01Z'])
def test_equal_overlapping_and_touching_intervals_indeterminate(later):
    out = temporal(clause('2026-01-01T00:00:00Z'), clause(later, number=1))
    assert not out['relationships']
    assert out['rejected_candidates'][0]['reason'] == 'equal_or_overlapping_recorded_intervals'


def test_fractional_precision_not_rounded_to_microseconds():
    out = temporal(clause('2026-01-01T00:00:00.0000001Z'), clause('2026-01-01T00:00:00.0000003Z', number=1))
    assert len(out['relationships']) == 1
    entries = out['chronology']['entries']
    assert all(t['original_precision'] == 'unknown' for t in entries)
    assert all(t['serialized_resolution_seconds'] == '1E-7' for t in entries)


@pytest.mark.parametrize('value', ['2026-01-01T00:00:00', 'unknown', '2026-01-01T00:00:00+99:00'])
def test_unknown_timezone_invalid_values_fail_closed(value):
    out = temporal(clause(value), clause('2026-01-01T00:00:03Z', number=1))
    assert not out['relationships']
    assert out['coverage']['incomparable_timestamp_entries'] == 1
    assert 'Incomparable timestamps' in r.render(out)


@pytest.mark.parametrize('skew', [None, 0, 10])
def test_clock_metadata_does_not_create_validated_clock_contract(skew):
    a = clause('2026-01-01T00:00:00Z', extra_time={'clock_skew_seconds': skew, 'clock_domain': 'host-a'})
    b = clause('2026-01-01T00:00:05Z', number=1, source='source-b', extra_time={'clock_domain': 'host-b'})
    out = temporal(a, b)
    assert len(out['relationships']) == 1
    edge = out['relationships'][0]
    assert edge['semantics']['ordering'] == 'recorded_utc_values_only'
    assert edge['semantics']['left']['clock_skew'] == 'unknown'
    assert edge['semantics']['right']['source_ids'] == ['source-b']
    assert 'Conditional physical-event ordering: none' in r.render(out)


def test_offset_normalization_compares_coordinates_not_clock_synchronization():
    out = temporal(clause('2026-01-01T01:00:00+01:00'), clause('2026-01-01T00:00:00Z', number=1))
    assert not out['relationships']
    assert out['coverage']['rejected'] == 1


def test_multiple_slots_and_artifact_meanings_unchanged():
    rows = [clause('2026-01-01T00:00:00Z', slot='SI Created'),
            clause('2026-01-01T00:00:02Z', pointer='/timestamps/1/utc', slot='FN Created'),
            clause('2026-01-01T00:00:04Z', number=2, family='browser', slot='DownloadStart'),
            clause('2026-01-01T00:00:06Z', number=2, family='browser', pointer='/timestamps/1/utc', slot='DownloadEnd'),
            clause('2026-01-01T00:00:08Z', number=3, family='prefetch', slot='LastRun')]
    out = temporal(*rows)
    assert len(out['chronology']['entries']) == 5
    assert {t['timestamp_semantics']['slot'] for t in out['chronology']['entries']} == {
        'SI Created', 'FN Created', 'DownloadStart', 'DownloadEnd', 'LastRun'}
    assert out['factual']['clauses'] == rows
    assert out['chronology']['graph']['transitive_edges_inferred'] is False
    assert len(out['relationships']) == 4  # No inferred A->C closure.


def test_exact_paths_across_sources_do_not_imply_volume_or_object_identity():
    a = clause(r'C:\Users\test\file.ps1', pointer='/objects/0')
    b = clause(r'C:\Users\test\file.ps1', pointer='/objects/0', number=1, source='different-volume')
    out = temporal(a, b)
    edge, = out['relationships']
    assert edge['predicate'] == 'exact_recorded_path'
    assert edge['semantics']['normalization'] == 'none'
    assert edge['semantics']['object_volume_host_identity'] == 'not established'
    assert sorted(edge['semantics']['source_ids']) == [['different-volume'], ['source-a']]
    assert edge['semantics']['source_ids'] == [list(r._sources(c)) for c in
        ({a['id']: a, b['id']: b}[cid] for cid in edge['endpoints'])]
    assert not out['chronology']['entries']


@pytest.mark.parametrize('other', [r'c:\users\test\file.ps1', r'C:\Users\TEST~1\file.ps1',
                                  r'%USERPROFILE%\file.ps1', r'D:\Users\test\file.ps1', 'file.ps1'])
def test_path_alias_case_device_and_basename_not_normalized(other):
    out = temporal(clause(r'C:\Users\test\file.ps1', pointer='/objects/0'),
                   clause(other, pointer='/objects/0', number=1))
    assert not out['relationships']


def test_prefetch_reference_is_only_recorded_string():
    out = temporal(clause(r'C:\run.ps1', pointer='/objects/0', family='prefetch'),
                   clause(r'C:\run.ps1', pointer='/objects/0', number=1))
    assert len(out['relationships']) == 1
    assert not out['chronology']['entries']
    assert any('Referenced files are not executed images' in q for q in out['relationships'][0]['qualifications'])


def test_guid_domains_are_source_scoped_and_exact():
    value = '01234567-1234-1234-1234-0123456789ab'
    a = clause(value, family='evtx', pointer='/original_event_data/0/value')
    b = clause(value, family='evtx', pointer='/original_event_data/0/value', number=1)
    assert any(e['predicate'] == 'exact_recorded_identifier' for e in temporal(a, b)['relationships'])
    for kwargs in ({'source': 'other'}, {'name': 'LogonGuid'}, {'name': 'Image'}):
        other = clause(value, family='evtx', pointer='/original_event_data/0/value', number=1, **kwargs)
        assert not temporal(a, other)['relationships']


def test_conflict_is_only_same_original_occurrence_not_unrelated_values():
    a = clause('value-a', family='evtx', pointer='/original_event_data/0/value', name='Target')
    b = clause('value-b', family='evtx', pointer='/original_event_data/0/value', name='Target')
    out = temporal(a, b)
    edge, = out['relationships']
    assert edge['predicate'] == 'incompatible_recorded_field'
    assert 'neither value is selected' in edge['semantics']['meaning']
    other = clause('value-b', number=1, family='evtx', pointer='/original_event_data/0/value', name='Target')
    assert not temporal(a, other)['relationships']
    other_source = clause('value-b', source='other', family='evtx', pointer='/original_event_data/0/value', name='Target')
    assert not temporal(a, other_source)['relationships']


def test_shortened_values_never_support_equality_or_time():
    a = clause('2026-01-01T00:00:00Z', shortened=True)
    b = clause('2026-01-01T00:00:04Z', number=1)
    assert not temporal(a, b)['relationships']
    a = clause(r'C:\short', shortened=True, pointer='/objects/0')
    b = clause(r'C:\short', number=1, pointer='/objects/0')
    assert not temporal(a, b)['relationships']


def test_forged_clauses_cross_epoch_and_causal_predicate_rejected():
    a = clause('2026-01-01T00:00:00Z')
    bad = deepcopy(a)
    bad['id'] = 'f' * 64
    with pytest.raises(ValueError):
        temporal(a, bad)
    other = clause('2026-01-01T00:00:04Z', number=1, view=dict(VIEW, view_id='b' * 32))
    with pytest.raises(ValueError, match='Cross-view'):
        temporal(a, other)
    with pytest.raises(ValueError):
        r._relationship('caused_execution', a, a, {})
    out = temporal(a, clause('2026-01-01T00:00:04Z', number=1))
    out['relationships'][0]['endpoints'][1] = 'forged'
    with pytest.raises((ValueError, KeyError)):
        r.render(out)


def test_determinism_dedup_identity_and_changed_assumptions():
    a = clause('2026-01-01T00:00:00Z')
    b = clause('2026-01-01T00:00:04Z', number=1)
    first = temporal(a, b)
    second = temporal(b, a, a)
    assert first['relationships'] == second['relationships']
    assert first['chronology'] == second['chronology']
    forged = deepcopy(first)
    forged['relationships'][0]['assumptions'] = ['Clocks synchronized']
    with pytest.raises(ValueError, match='derivation'):
        r.render(forged)


def test_sparse_bounds_scale_linearly_and_preserve_partial():
    rows = [clause(r'C:\same.txt', number=i, pointer='/objects/0') for i in range(s.MAX_CLAUSES)]
    out = temporal(*rows, comparison_limit=5)
    assert out['coverage']['indexed_candidates'] == len(rows) - 1
    assert out['coverage']['considered'] == out['coverage']['accepted'] == 5
    assert out['coverage']['unassessed_candidates'] == 90
    assert out['coverage']['incomplete']
    assert len(out['factual']['clauses']) == s.MAX_CLAUSES
    out = temporal(*rows, relationship_limit=2)
    assert len(out['relationships']) == 2 and out['coverage']['unassessed_candidates'] == 93
    with pytest.raises(ValueError, match='ceiling'):
        temporal(*(rows + [rows[0]]))
    with pytest.raises(ValueError, match='serialization budget'):
        temporal(*(rows * 20))


def test_empty_singleton_and_zero_budget():
    assert not temporal()['relationships']
    a = clause('2026-01-01T00:00:00Z')
    assert len(temporal(a)['chronology']['entries']) == 1
    out = temporal(a, clause('2026-01-01T00:00:05Z', number=1), comparison_limit=0)
    assert out['coverage']['considered'] == 0 and out['coverage']['unassessed_candidates'] == 1


def test_cycles_are_reported_without_discarding_nodes():
    edges = [dict(predicate='recorded_time_before', endpoints=['a', 'b']),
             dict(predicate='recorded_time_before', endpoints=['b', 'a'])]
    graph = r._graph(['a', 'b', 'c'], edges)
    assert graph['unresolved_cycle_or_dependent_nodes'] == ['a', 'b']
    assert graph['recorded_coordinate_layers'] == [['c']]


def test_public_reconstruction_preserves_s1_and_stage_a(tmp_path):
    from test_autonomous_stage_a import setup
    from forensic_assistant.investigation_ai import autonomous
    from forensic_assistant.reporting.transcripts import load
    config, worker, client, _, _ = setup(tmp_path, count=6)
    result = autonomous.run(config, config['_stage_a']['objective'], tmp_path/'runs', client=client, worker_factory=worker)
    before = {p: p.read_bytes() for p in (tmp_path/'runs').rglob('*') if p.is_file()}
    root, identity = tmp_path/'runs', result['investigation_id']
    original = s.reconstruct(root, identity)
    one = r.reconstruct(root, identity)
    assert one == r.reconstruct(root, identity)
    assert one['factual'] == original
    assert len(client.calls) == 6
    assert before == {p: p.read_bytes() for p in before}
    assert r.render(one)
    with pytest.raises(ValueError, match='Incremental report import'):
        load(root, identity)


def test_serialization_budget_retains_validated_prefix(monkeypatch):
    rows = [clause(r'C:\same.txt', number=i, pointer='/objects/0') for i in range(5)]
    empty = temporal(*rows, relationship_limit=0)
    full = temporal(*rows)
    allowance = len(json.dumps(empty).encode()) + 32768 + len(json.dumps(full['relationships'][0]).encode())
    monkeypatch.setattr(r, 'MAX_BYTES', allowance)
    partial = temporal(*rows)
    assert 0 < len(partial['relationships']) < len(full['relationships'])
    assert partial['coverage']['validated_not_retained'] == 1
    assert partial['coverage']['incomplete']
    assert partial['factual']['clauses'] == rows


def test_explicit_interface_does_not_change_default(monkeypatch, capsys):
    import sys
    sample = factual(clause('2026-01-01T00:00:00Z'), clause('2026-01-01T00:00:03Z', number=1))
    monkeypatch.setattr(s, 'reconstruct', lambda root, identity: deepcopy(sample))
    monkeypatch.setattr(sys, 'argv', ['synthesis', 'root', 'identity', '--json'])
    s.main()
    assert json.loads(capsys.readouterr().out) == sample
    monkeypatch.setattr(sys, 'argv', ['synthesis', 'root', 'identity', '--relationships', '--json'])
    s.main()
    output = json.loads(capsys.readouterr().out)
    assert output['contract'] == r.RESULT and output['factual'] == sample


def test_unknown_skew_never_becomes_transitive_event_order():
    rows = [clause('2026-01-01T00:00:0' + str(i * 2) + 'Z', number=i, source='host-' + str(i)) for i in range(3)]
    result = temporal(*rows)
    assert len(result['relationships']) == 2
    assert all(e['semantics']['physical_event_order'] == 'not established' for e in result['relationships'])
    assert not result['chronology']['graph']['transitive_edges_inferred']
    assert result['coverage']['pairs_not_generated_by_sparse_policy'] == 1


def test_control_sequences_in_recorded_path_are_escaped():
    value = 'C:\\bad\x1b[31m\\file'
    result = temporal(clause(value, pointer='/objects/0'), clause(value, number=1, pointer='/objects/0'))
    assert '\x1b' not in r.render(result)

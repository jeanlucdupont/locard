"""Registry diagnostics are content-free observers, never evidence transformations."""
from contextlib import contextmanager
import logging
import re

import pytest

from forensic_assistant import dump_cli as dump
from forensic_assistant.registry_dump_profile import RegistryProfile
from test_dump import mixed, mixed_template, export, read
from test_dump_timing import Clock


def test_profile_counts_content_and_audit(mixed, monkeypatch, caplog):
    monkeypatch.setattr(dump, 'PAGE', 3)
    audit = []
    @contextmanager
    def mutation(action, **fields):
        result = dict(fields)
        yield result
        audit.append((action, result))
    monkeypatch.setattr(dump.activity, 'mutation', mutation)
    export(mixed, 'registry')
    before = mixed.read_bytes()
    target = mixed.parent / 'dump' / 'registry.csv'
    csv_before = target.read_bytes()
    with caplog.at_level(logging.WARNING, logger='forensic_assistant.dump_cli'):
        plain = export(mixed, 'registry', True)
    audit_before = audit[-1]
    assert not caplog.records
    observed = []
    original = dump.groups
    def groups(db, sql, params, key='evidence_id'):
        result = original(db, sql, params, key)
        parents = sorted({r[0]['key_id'] for r in result.values() if r[0]['key_id']}) if 'JOIN registry_hives' in sql else []
        observed.append((sql, len(params), sum(map(len, result.values())), parents))
        return result
    monkeypatch.setattr(dump, 'groups', groups)
    with caplog.at_level(logging.DEBUG, logger='forensic_assistant.dump_cli'):
        profiled = export(mixed, 'registry', True)
    metrics = next(r.args for r in caplog.records if r.msg == 'Registry dump performance: %s')
    primary = [r for r in observed if 'JOIN registry_hives' in r[0]]
    # Each page's own timestamp query precedes its optional parent timestamp query.
    parent_calls = []
    for index, (sql, _, _, parents) in enumerate(observed):
        if parents and index + 1 < len(observed):
            candidate = observed[index + 1]
            if 'FROM evidence_timestamps' in candidate[0]: parent_calls.append(candidate)
    assert metrics['completed']
    assert metrics['page_size'] == metrics['max_page_rows'] == 3
    assert metrics['pages'] == len(primary) > 1
    assert metrics['evidence_ids'] == metrics['csv_rows'] == len(read(mixed, 'registry'))
    assert metrics['primary_rows'] == sum(r[2] for r in primary) == metrics['csv_rows']
    assert metrics['parent_ids'] == sum(r[1] for r in parent_calls) > 0
    assert metrics['timestamp_rows'] == sum(r[2] for r in parent_calls) > 0
    assert metrics['phases']['primary_registry_query']['calls'] == len(primary)
    assert metrics['phases']['parent_timestamp_query']['calls'] == len(parent_calls)
    for m in metrics['phases'].values():
        assert m['seconds'] >= m['max_seconds'] >= 0
        assert m['average_seconds'] == pytest.approx(m['seconds'] / m['calls'] if m['calls'] else 0)
    assert metrics['other_seconds'] >= 0
    parts = metrics['phases']
    assert parts['csv_value_conversion']['calls'] == metrics['csv_rows']
    assert parts['csv_writerow']['calls'] == metrics['csv_rows']
    assert parts['csv_value_conversion']['seconds'] + parts['csv_writerow']['seconds'] <= parts['csv_write']['seconds']
    assert parts['file_write_flush']['seconds'] <= parts['publication']['seconds']
    assert sum(m['seconds'] for name, m in metrics['phases'].items() if name not in metrics['nested_components']) + metrics['other_seconds'] == pytest.approx(metrics['total_seconds'])
    assert re.sub(r'\d+\.\d+ sec', 'TIME', plain) == re.sub(r'\d+\.\d+ sec', 'TIME', profiled)
    assert csv_before == target.read_bytes() and before == mixed.read_bytes()
    assert audit[-1] == audit_before
    assert str(mixed) not in caplog.text and 'ROOT' not in caplog.text and 'SELECT' not in caplog.text
    assert all(row['evidence_id'] not in caplog.text for row in read(mixed, 'registry'))


def test_whole_call_metrics_and_residual_with_fake_clock():
    clock = Clock()
    profile = RegistryProfile(128, clock)
    for seconds in (2, 6):
        with profile.measure('primary_registry_query'): clock.advance(seconds)
    profile.page(128)
    profile.page(2)
    clock.advance(3)
    result = profile.summary(True)
    assert result['phases']['primary_registry_query'] == dict(calls=2, seconds=8, max_seconds=6, average_seconds=4)
    assert result['average_rows_per_page'] == 65
    assert result['total_seconds'] == 11 and result['other_seconds'] == 3
    import time
    assert RegistryProfile(128).clock is time.perf_counter


def test_failed_dump_reports_partial_status(mixed, monkeypatch, caplog):
    original = dump.groups
    def fail(db, sql, params, key='evidence_id'):
        if 'JOIN registry_hives' in sql: raise ValueError('synthetic failure')
        return original(db, sql, params, key)
    monkeypatch.setattr(dump, 'groups', fail)
    with caplog.at_level(logging.DEBUG, logger='forensic_assistant.dump_cli'), pytest.raises(ValueError):
        export(mixed, 'registry')
    result = next(r.args for r in caplog.records if r.msg == 'Registry dump performance: %s')
    assert result['completed'] is False and result['csv_rows'] == 0
    assert not (mixed.parent / 'dump' / 'registry.csv').exists()


def test_nested_components_do_not_double_count_total():
    clock = Clock()
    profile = RegistryProfile(128, clock)
    with profile.measure('csv_write'):
        with profile.measure('csv_value_conversion'): clock.advance(2)
        with profile.measure('csv_writerow'): clock.advance(3)
    clock.advance(1)
    result = profile.summary(True)
    assert result['total_seconds'] == 6
    assert result['other_seconds'] == 1

"""Bounded synthetic audit segments; no providers or existing case access."""
from contextlib import contextmanager
import copy
import io
import json
import os
import time

import pytest

from forensic_assistant import activity, session_recording as sr
from forensic_assistant.database.db import connect
from forensic_assistant.interactive.setup_display import FileProgress
from forensic_assistant.terminal import Palette
from test_session_recording import isolated, case, entries


@contextmanager
def recording(path):
    rec = sr.Recorder(io.StringIO())
    token = sr.ACTIVE.set(rec)
    try:
        rec.open(path)
        with activity.bind(activity.Session(path)):
            yield rec
    finally:
        rec.close()
        sr.ACTIVE.reset(token)


def fill(rec, count=50):
    for n in range(count):
        rec.emit('synthetic_observation', {'index': n, 'text': 'x' * 7000})


def test_rotation_linkage_case_switch_and_no_evidence_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, 'SESSION_BYTES', 256 * 1024)
    a, b = case(tmp_path), case(tmp_path, 'two')
    originals = {p: p.read_bytes() for p in (a, b)}
    with recording(a) as rec:
        logical = rec.id
        rec.operation_id = 'synthetic-command'
        fill(rec)
        rec.open(b)
        fill(rec, 30)
    for path in (a, b):
        result = sr.verify(path)
        assert result['valid'] and len(result['sessions']) >= 2
        rows = sorted(result['sessions'], key=lambda r: r['segment_index'])
        assert {r['application_session_id'] for r in rows} == {logical}
        assert [r['segment_index'] for r in rows] == list(range(len(rows)))
        assert all(r['integrity'] == r['linked_integrity'] == 'verified' for r in rows)
        assert all(r['recording_bytes'] <= sr.SESSION_BYTES for r in rows)
        assert path.read_bytes() == originals[path]
        observed = [e for row in rows for e in sr.review(path, selector=row['session_id'], limit=1000)['records']
                    if e['action'] == 'synthetic_observation']
        assert [e['data']['index'] for e in observed] == list(range(50 if path == a else 30))
        assert all(e['operation_id'] == 'synthetic-command' for e in observed)


@pytest.mark.parametrize('damage', ['missing', 'corrupt', 'swap', 'truncate'])
def test_damaged_linked_sequence_is_not_trusted(tmp_path, monkeypatch, damage):
    monkeypatch.setattr(sr, 'SESSION_BYTES', 256 * 1024)
    path = case(tmp_path)
    with recording(path) as rec:
        fill(rec)
    result = sr.verify(path)
    rows = sorted(result['sessions'], key=lambda r: r['segment_index'])
    root = sr.locations(path)[0]
    first, second = [root / (r['session_id'] + '.jsonl') for r in rows[:2]]
    if damage == 'missing':
        second.unlink()
    elif damage == 'corrupt':
        second.write_bytes(second.read_bytes().replace(b'synthetic_observation', b'synthetic_fabrication', 1))
    elif damage == 'swap':
        left, right = first.read_bytes(), second.read_bytes()
        first.write_bytes(right); second.write_bytes(left)
    else:
        second.write_bytes(b''.join(second.read_bytes().splitlines(keepends=True)[:-1]))
    checked = sr.verify(path)
    assert not checked['valid']
    assert any(r['integrity'] in ('corrupt', 'missing') for r in checked['sessions'])
    with pytest.raises(ValueError):
        sr.review(path, selector=rows[0]['session_id'])


@pytest.mark.parametrize('field,value', [('segment_index', 0), ('application_session_id', 'another'),
                                        ('previous_segment', None), ('anchor_sequence', 0)])
def test_link_semantics_independent_of_per_file_hash(tmp_path, monkeypatch, field, value):
    monkeypatch.setattr(sr, 'SESSION_BYTES', 256 * 1024)
    path = case(tmp_path)
    with recording(path) as rec:
        fill(rec, 30)
    rows = sorted(sr.verify(path)['sessions'], key=lambda r: r['segment_index'])
    rows[1][field] = value
    sr.validate_segment_links(rows)
    assert all(r['linked_integrity'] == 'invalid' for r in rows)


def test_capacity_reserved_before_intent_and_nested_mutations(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, 'SESSION_BYTES', 512 * 1024)
    path = case(tmp_path)
    with recording(path) as rec:
        # Use actual bounded entries to approach the admission threshold.
        while rec.size + rec.event_bytes < 300 * 1024:
            rec.emit('synthetic', {'text': 'x' * 7000})
        before = rec.segment
        with activity.mutation('OUTER'):
            with activity.mutation('INNER'):
                assert len(rec.reservations) == 2
                assert rec.segment != before
                fill(rec, 30)
            assert len(rec.reservations) == 1
        assert not rec.reservations
    assert sr.verify(path)['valid']
    actions = [e for e in entries(activity.sidecar(path)) if e['action'] in ('OUTER', 'INNER')]
    for name in ('OUTER', 'INNER'):
        matching = [e for e in actions if e['action'] == name]
        assert [e['phase'] for e in matching] == ['intent', 'complete']
        assert len({e['operation_id'] for e in matching}) == 1


@pytest.mark.parametrize('error', [PermissionError('private path'), OSError('private detail')])
def test_rotation_failure_refuses_mutation(tmp_path, monkeypatch, error):
    path = case(tmp_path)
    with recording(path) as rec:
        rec.size = sr.SESSION_BYTES - sr.RESERVE - sr.MUTATION_BYTES
        def denied(*a):
            raise error
        monkeypatch.setattr(rec, 'allocate_segment', denied)
        with pytest.raises(activity.AuditError, match='Action refused before execution') as caught:
            with activity.mutation('MUST_NOT_START'):
                pytest.fail('mutation admitted')
        assert caught.value.action_outcome == 'refused'
        assert 'private' not in str(caught.value)
        assert rec.broken
    events = entries(activity.sidecar(path))
    assert not any(e['action'] == 'MUST_NOT_START' for e in events)
    failed = next(e for e in events if e['action'] == 'SESSION_CAPTURE_FAILURE')
    assert failed['reason_code'] == 'segment_rotation_failed'
    assert failed['underlying_exception'] == type(error).__name__


def test_directory_reserves_live_segments_and_refuses_new_work(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, 'ROOT_BYTES', sr.SESSION_BYTES)
    path = case(tmp_path)
    with recording(path) as first:
        other = sr.Recorder(io.StringIO())
        other.open(path)
        assert other.broken and other.failure_reason == 'session_directory_quota_exceeded'
        assert not first.broken


def test_spinner_suppressed_but_outcomes_retained(tmp_path, monkeypatch):
    class Terminal(io.StringIO):
        def isatty(self): return True
        @property
        def encoding(self): return 'utf-8'
    path = case(tmp_path)
    with recording(path) as rec:
        stream = sr.Stream(Terminal(), rec, 'stdout')
        monkeypatch.setattr('forensic_assistant.terminal.capable', lambda s: True)
        meter = FileProgress('prefetch', 500, Palette(), stream=stream)
        for _ in range(10000):
            meter._frame()
        meter.close()
        assert rec.output_bytes == 0 and not rec.omitted_bytes
        with activity.mutation('INGEST', artifact_type='prefetch', source_id='synthetic') as event:
            event.update(status='complete', inserted=1, duplicates=0, errors=0)
        rec.output('Prefetch: complete | 1 record\n')
    rows = sr.verify(path)['sessions']
    stored = sr.review(path, selector=rows[0]['session_id'], limit=1000)['records']
    assert any(e['action'] == 'output' and '1 record' in e['data']['text'] for e in stored)
    assert not any(e['action'] == 'capture_gap' for e in stored)
    assert any(e['action'] == 'INGEST' and e.get('phase') == 'complete' for e in entries(activity.sidecar(path)))


def test_cancel_and_interrupted_rotation_remain_honest(tmp_path, monkeypatch):
    path = case(tmp_path)
    with recording(path) as rec:
        with pytest.raises(KeyboardInterrupt):
            with activity.mutation('CANCELLED'):
                raise KeyboardInterrupt
        assert not rec.reservations
    assert sr.verify(path)['valid']
    assert any(e['action'] == 'CANCELLED' and e['outcome'] == 'cancelled' for e in entries(activity.sidecar(path)))
    with recording(path) as rec:
        original = rec.start_segment
        def interrupt(new):
            raise KeyboardInterrupt
        monkeypatch.setattr(rec, 'start_segment', interrupt)
        with pytest.raises(KeyboardInterrupt): rec.rotate()
        assert rec.broken
        # Simulate interrupted process; do not manufacture a normal close.
        rec.segment = None
    assert not sr.verify(path)['valid']


def test_flush_failure_is_bounded_and_not_success(tmp_path, monkeypatch):
    path = case(tmp_path)
    with recording(path) as rec:
        def denied(fd): raise OSError('sensitive path')
        monkeypatch.setattr(activity.os, 'fsync', denied)
        with pytest.raises(activity.AuditError) as error:
            rec.require()
        assert 'flush_fsync_failure' in str(error.value)
        assert 'sensitive' not in str(error.value)
        assert rec.broken


def test_historical_single_segment_stays_readable_and_incomplete(tmp_path):
    import uuid
    path = case(tmp_path)
    root, authority = sr.locations(path)
    sr.private_directory(root)
    for complete in (True, False):
        identity = uuid.uuid4().hex
        segment = root / (identity + '.jsonl')
        info = path.stat()
        binding = dict(path=str(path.absolute()), device=info.st_dev, inode=info.st_ino)
        rows = [('session_start', 'success', dict(contract='session-record-v1',
                 application_session_id='historical', data=dict(case_binding=binding,
                 application_version='6.149', limitations=[])))]
        if complete:
            rows.append(('session_end', 'success', dict(contract='session-record-v1',
                         application_session_id='historical', data=dict(reason='normal'))))
        last = activity.append_batch(segment, identity, rows)[-1]
        activity.append(authority, 'historical', 'SESSION_RECORD_END' if complete else 'SESSION_RECORD_START',
                        'success', recording_contract='session-record-v1', recording_id=identity,
                        recording_sequence=last['sequence'], recording_hash=last['entry_hash'],
                        recording_bytes=segment.stat().st_size, case_binding=binding)
    originals = {p: p.read_bytes() for p in root.iterdir()}
    result = sr.verify(path)
    assert result['valid']
    assert {r['integrity'] for r in result['sessions']} == {'verified', 'incomplete'}
    for row in result['sessions']:
        assert sr.review(path, selector=row['session_id'])['records']
    assert all(p.read_bytes() == raw for p, raw in originals.items())


@pytest.mark.skipif(os.name != 'nt', reason='Windows lock API')
def test_lock_timeout_has_stable_reason(tmp_path, monkeypatch):
    import msvcrt
    from types import SimpleNamespace
    path = tmp_path / 'lock.jsonl'
    path.write_bytes(b'')
    def busy(*a): raise OSError('busy private path')
    ticks = iter([0, 4])
    monkeypatch.setattr(msvcrt, 'locking', busy)
    monkeypatch.setattr(activity, 'time', SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda s: None))
    with pytest.raises(activity.AuditError) as error:
        with activity.locked(path, write=True):
            pytest.fail('lock admitted')
    assert error.value.reason_code == 'lock_acquisition_timeout'
    assert 'private' not in str(error.value)


def test_completion_keeps_reservation_through_durable_reference(tmp_path, monkeypatch):
    path = case(tmp_path)
    with recording(path) as rec:
        append = activity.append
        observed = []
        def inspect(log, session, action, outcome, **fields):
            if action == 'SYNTHETIC' and fields.get('phase') == 'complete':
                observed.append(len(rec.reservations))
            return append(log, session, action, outcome, **fields)
        monkeypatch.setattr(activity, 'append', inspect)
        with activity.mutation('SYNTHETIC'):
            pass
        assert observed == [1] and not rec.reservations
        references = [e for e in entries(rec.path) if e['action'] == 'activity_reference']
        assert any(e['data']['action'] == 'SYNTHETIC' and e['data']['outcome'] == 'success' for e in references)


def test_seal_promise_cannot_be_erased_by_later_anchor(tmp_path):
    path = case(tmp_path)
    with recording(path) as rec:
        rec.rotate()
    rows = sorted(sr.verify(path)['sessions'], key=lambda r: r['segment_index'])
    authority = activity.sidecar(path)
    first = rows[0]
    old = next(e for e in entries(authority) if e.get('recording_id') == first['session_id']
               and e['action'] == 'SESSION_RECORD_END')
    # Reappend a validly hashed but semantically invalid anchor. The successor
    # promise must survive; a later anchor cannot reopen the sealed segment.
    fields = {k: v for k, v in old.items() if k not in (
        'audit_version', 'timestamp_utc', 'session_id', 'sequence', 'action', 'outcome',
        'previous_entry_hash', 'entry_hash')}
    fields['next_segment'] = None
    activity.append(authority, rec.id, 'SESSION_RECORD_CHECKPOINT', 'success', **fields)
    (sr.locations(path)[0] / (rows[1]['session_id'] + '.jsonl')).unlink()
    result = sr.verify(path)
    assert not result['valid']
    assert any(r['session_id'] == rows[1]['session_id'] and r['integrity'] == 'missing' for r in result['sessions'])


def test_concurrent_authority_change_requires_retry(tmp_path, monkeypatch):
    path = case(tmp_path)
    with recording(path):
        pass
    inspect = activity.inspect
    authority = activity.sidecar(path)
    def changing(file, **kw):
        result = inspect(file, **kw)
        if file == authority:
            activity.append(authority, 'concurrent', 'SYNTHETIC', 'success')
        return result
    monkeypatch.setattr(activity, 'inspect', changing)
    with pytest.raises(activity.AuditError, match='changed during session verification'):
        sr.verify(path)


def test_worst_bounded_pending_output_fits_completion_reservation(tmp_path):
    path = case(tmp_path)
    with recording(path) as rec:
        with activity.mutation('SYNTHETIC'):
            # Both stream buffers may be populated when a required completion
            # flushes them. They cannot borrow another mutation's reservation.
            rec.pending = {'stdout': 'x' * 8192, 'stderr': 'y' * 8192}
            rec.buffered = {'stdout': 'a' * 4095, 'stderr': 'b' * 4095}
            rec.size = sr.SESSION_BYTES - sr.RESERVE - sr.MUTATION_BYTES - 1
            before = rec.segment
        assert rec.segment == before and not rec.broken


def test_partial_commit_and_failure_audit_unavailable_is_unknown(tmp_path, monkeypatch):
    path = case(tmp_path)
    with recording(path) as rec:
        with pytest.raises(activity.AuditError) as error:
            with activity.mutation('SYNTHETIC'):
                rec.broken = True
                raise ValueError('operation failed after possible partial work')
        assert error.value.action_outcome == 'unknown'
        assert 'outcome unknown' in str(error.value)
        assert not rec.reservations


def test_activity_writer_failure_does_not_expose_sensitive_exception(tmp_path, monkeypatch):
    path = case(tmp_path)
    with recording(path):
        def denied(*a, **kw): raise PermissionError('sensitive-case-content')
        monkeypatch.setattr(activity, 'append', denied)
        with pytest.raises(activity.AuditError) as error:
            with activity.mutation('SYNTHETIC'):
                pytest.fail('action admitted')
        assert 'sensitive-case-content' not in str(error.value)
        assert error.value.reason_code == 'writer_permission_failure'
        assert activity.error_data(error.value)['action_outcome'] == 'refused'


def test_400_real_durable_operations_rotate_without_evidence_mutation(tmp_path):
    path = case(tmp_path)
    before = path.read_bytes()
    rotations = []
    started = time.monotonic()
    with recording(path) as rec:
        rotate = rec.rotate
        def measured():
            start = time.monotonic()
            rotate()
            rotations.append(time.monotonic() - start)
        rec.rotate = measured
        for n in range(400):
            with activity.mutation('INGEST_BATCH', command='ingest-prefetch', source_id='synthetic') as batch:
                with activity.mutation('INGEST', artifact_type='prefetch', source_file='synthetic.pf') as item:
                    item.update(status='complete', inserted=1, duplicates=0, errors=0)
                batch.update(files=1, inserted=1, duplicates=0, errors=0)
        assert not rec.broken
    elapsed = time.monotonic() - started
    result = sr.verify(path)
    assert result['valid'] and len(result['sessions']) > 1 and rotations
    assert path.read_bytes() == before
    events = [e for e in entries(activity.sidecar(path)) if e['action'] in ('INGEST', 'INGEST_BATCH')]
    assert len(events) == 1600
    operations = {}
    for e in events: operations.setdefault(e['operation_id'], []).append(e['phase'])
    assert len(operations) == 800 and all(phases == ['intent', 'complete'] for phases in operations.values())
    print(json.dumps(dict(operations=400, elapsed_seconds=round(elapsed, 3), rotations=len(rotations),
                         rotation_seconds=round(sum(rotations), 3),
                         session_bytes=sum(r['recording_bytes'] for r in result['sessions']))))

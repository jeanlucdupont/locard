"""Presentation-only timeline and source identity regressions; synthetic inputs."""
import copy
import json
from contextlib import closing
from types import SimpleNamespace

import pytest

from forensic_assistant import cli, source_cli, terminal_activity as ui
from forensic_assistant.database.db import connect
from forensic_assistant.retrieval import mixed_display, status_display
from forensic_assistant.terminal import Palette
from test_terminal_activity import terminal, wait_for


@pytest.mark.parametrize('stamp,expected', [
    ('2026-09-30T00:00:00.123499999Z', '2026-09-30 00:00:00.123'),
    ('2026-09-30T00:00:00.123500000Z', '2026-09-30 00:00:00.124'),
    ('2026-09-30T00:00:00.000000000Z', '2026-09-30 00:00:00.000'),
    ('2026-09-30T00:00:00.999500000Z', '2026-09-30 00:00:01.000'),
    ('2026-09-30T00:00:59.999500000Z', '2026-09-30 00:01:00.000'),
    ('2026-09-30T00:59:59.999500000Z', '2026-09-30 01:00:00.000'),
    ('2026-09-30T23:59:59.999500000Z', '2026-10-01 00:00:00.000'),
    ('2026-12-31T23:59:59.999500000Z', '2027-01-01 00:00:00.000'),
])
def test_compact_rounding_only(stamp, expected):
    record = dict(id='synthetic', source_type='evtx', provider='Example', event_id=42,
                  timestamp_utc=stamp, timestamp={'slot': 'Event.SystemTime'}, warnings=[])
    result = dict(records=[record], total=1, offset=0, truncated=False)
    before = json.dumps(result)
    assert expected in mixed_display.compact_timeline(result, width=120)
    assert json.dumps(result) == before and record['timestamp_utc'] == stamp


def test_display_collision_preserves_observations_order_slots_and_pagination():
    records = [dict(id='same', source_type='evtx', provider=name, event_id=42,
                    timestamp_utc=f'2026-09-30T00:00:00.{fraction}Z',
                    timestamp={'slot': slot}, warnings=[])
               for name, fraction, slot in [('First', '123100000', 'one'),
                                             ('Second', '123200000', 'two')]]
    result = dict(records=records, total=8, offset=2, truncated=True)
    before = copy.deepcopy(result)
    text = mixed_display.compact_timeline(result, width=120)
    assert text.count('2026-09-30 00:00:00.123') == 2
    assert text.index('First') < text.index('Second')
    assert result == before
    assert len(mixed_display.mft_display.groups(records, source_types=('evtx',))) == 2


@pytest.mark.parametrize('failure', [None, ValueError, KeyboardInterrupt])
def test_timeline_dispatch_indicator_covers_retrieval_and_clears(terminal, tmp_path, monkeypatch, failure):
    db_path = tmp_path / 'case.db'
    with closing(connect(db_path)):
        pass
    args = cli.build_parser().parse_args(['--db', str(db_path), 'evidence', 'timeline', '--text'])
    indicators = []
    original = ui.operation
    def operation(text, args):
        indicator = original(text, args)
        assert text == 'Retrieving timeline...' and indicator.delay == .5
        indicators.append(indicator)
        return indicator
    monkeypatch.setattr(ui, 'operation', operation)
    def retrieval(*a, **k):
        assert indicators[0]._thread.is_alive()
        wait_for(lambda: 'Retrieving timeline...' in terminal.getvalue())
        if failure:
            raise failure('synthetic')
        return dict(records=[], total=0, offset=0, truncated=False), 0
    monkeypatch.setattr('forensic_assistant.v2_cli.dispatch', retrieval)
    output = []
    def write(value):
        assert indicators[0]._thread is None
        assert terminal.getvalue().endswith('\r\x1b[K')
        output.append(value)
    writer = SimpleNamespace(palette=Palette(), write=write, json=write)
    if failure is KeyboardInterrupt:
        with pytest.raises(failure):
            cli._dispatch(args, writer)
    elif failure:
        assert cli._dispatch(args, writer) == 2
    else:
        assert cli._dispatch(args, writer) == 0 and output
    assert indicators[0]._thread is None and not ui._OWNER.locked()


@pytest.mark.parametrize('mode', ['json', 'output_file', 'append_file', 'page', 'redirect', 'stdin'])
def test_timeline_suppression_at_dispatch(terminal, tmp_path, monkeypatch, mode):
    import io
    with closing(connect(tmp_path / 'case.db')):
        pass
    args = cli.build_parser().parse_args(['--db', str(tmp_path / 'case.db'), 'evidence', 'timeline', '--text'])
    if mode == 'redirect':
        monkeypatch.setattr(ui.sys, 'stdout', io.StringIO())
    elif mode == 'stdin':
        monkeypatch.setattr(ui.sys, 'stdin', io.StringIO())
    else:
        setattr(args, mode, True)
    captured = []
    original = ui.operation
    def operation(text, args):
        indicator = original(text, args)
        captured.append(indicator)
        return indicator
    monkeypatch.setattr(ui, 'operation', operation)
    def retrieval(*a, **k):
        assert not captured[0].active and captured[0]._thread is None
        return dict(records=[], total=0, offset=0, truncated=False), 0
    monkeypatch.setattr('forensic_assistant.v2_cli.dispatch', retrieval)
    writer = SimpleNamespace(palette=Palette(), write=lambda value: None, json=lambda value: None)
    assert cli._dispatch(args, writer) == 0
    assert not terminal.getvalue()


UNKNOWN = 'Analyst hostname unknown; source membership alone does not establish a host'
CONFLICT = 'Source-level conflicting hostname assertions; record hosts are resolved individually'


def source(hostname=None, conflict=False):
    return dict(source_id='src-synthetic', display_name='Lab', hostname=hostname,
                host_conflict=conflict, files=1, evidence_count=1, artifacts={'evtx': 1},
                artifact_hostnames=['one', 'two'] if conflict else [],
                limitations=([UNKNOWN] if not hostname else []) + ([CONFLICT] if conflict else []) + ['Distinct limitation'],
                **{k: {'total': 0} for k in ('assertion_history', 'retrospective_assignments', 'retrospective_files', 'file_occurrences')})


@pytest.mark.parametrize('hostname,conflict', [(None, False), (None, True), ('one', True), ('one', False)])
def test_source_notes_keep_original_detailed_data(hostname, conflict):
    value = source(hostname, conflict)
    before = copy.deepcopy(value)
    text = source_cli.render_show(value)
    details = source_cli.render_show(value, details=True)
    assert 'Distinct limitation' in text
    if conflict:
        assert text.count('Conflicting hostnames were observed') == 1
        assert 'evaluate host attribution per evidence record' in text
        assert UNKNOWN not in text and CONFLICT not in text
    elif not hostname:
        assert 'Source computer identity has not been confirmed.' in text
    for note in value['limitations']:
        assert note in details
    assert value == before


def test_status_identity_scope_and_unlisted_sources():
    sources = [source(), source('asserted', True), source(None, True)]
    value = dict(artifact_counts={'evtx': 3}, source_coverage=dict(
        sources=sources, total=4, unknown_hostname_sources=3, limitations=['Coverage limitation']))
    before = copy.deepcopy(value)
    details = dict(runs={}, dirty_hives=0, hive_warnings=[], error_summaries=[])
    text = status_display.render(value, 'synthetic', details)
    assert 'Source 1: Source computer identity has not been confirmed.' in text
    assert 'Source 2: Source computer identity is unconfirmed; conflicting hostnames were observed.' in text
    assert 'Source 3: Source computer identity is unconfirmed; conflicting hostnames were observed.' in text
    assert '1 additional sources outside this source page' in text
    assert 'Coverage limitation' in text and value == before
    detailed = status_display.render(value, 'synthetic', details, verbose=True)
    assert 'Analyst hostname unknown for 3 sources' in detailed
    assert 'Source-level conflicting hostname assertions' in detailed


def test_single_source_and_list_consolidation():
    row = source(None, True)
    details = dict(runs={}, dirty_hives=0, hive_warnings=[], error_summaries=[])
    value = dict(source_coverage=dict(sources=[row], total=1, unknown_hostname_sources=1))
    text = status_display.render(value, 'synthetic', details)
    assert text.count('Source computer identity is unconfirmed; conflicting hostnames were observed.') == 1
    assert 'has not been confirmed' not in text
    page = dict(sources=[row, source('host', True)], offset=0, total=2)
    text = source_cli.render_list(page)
    assert 'Source 1:' in text and 'Source 2:' in text
    assert text.count('conflicting hostnames were observed') == 2

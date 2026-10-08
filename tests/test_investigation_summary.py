"""Synthetic-only checks for deterministic, bounded, non-causal text summaries."""
import copy
import json
from datetime import datetime, timedelta

import pytest

from forensic_assistant.artifacts.paths import normalize_path
from forensic_assistant.retrieval import investigation_summary as summary
from forensic_assistant.retrieval.analysis_display import View, render_investigation
from forensic_assistant.correlation.investigation import investigate
from forensic_assistant.terminal import Palette, SGR
from test_mixed_temporal import mixed_case, UA_SLOT
from test_investigate_mixed import registry_rows


def stamp(ns=0):
    seconds, fraction = divmod(ns, 1_000_000_000)
    return (datetime(2020, 1, 1, 10) + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%S') + f'.{fraction:09d}Z'


def record(kind, name, index, ns=0, user=None):
    source = {'userassist': 'registry', 'service': 'evtx', 'process': 'evtx', 'file': 'evtx', 'event': 'evtx'}.get(kind, kind)
    slot = {'userassist': UA_SLOT, 'prefetch': 'run:0', 'registry': 'LastWrite', 'mft': 'SI.Modified'}.get(kind, 'SystemTime')
    r = dict(id=f'{source.upper()}:synthetic:{index}', source_type=source, artifact_type=kind,
             host_key='host-a', username=user, context=dict(hostname='host-a', conflicts=[], source_ids=['synthetic']),
             detail={}, objects=[], timestamps=[dict(slot=slot, timestamp_utc=stamp(ns))])
    if kind == 'prefetch':
        r['detail']['executable'] = name
    elif kind == 'userassist':
        r['detail']['userassist'] = dict(decoded_name=name, status='parsed')
    elif kind == 'registry':
        r['detail']['key_path'] = name
        r['objects'] = [dict(role='key', original=name, normalized=name.lower())]
    elif kind == 'service':
        r.update(provider='Service Control Manager', channel='System', event_id=7045, service_name='example')
        r['service_installation'] = dict(image_path=name, account='LocalSystem', service_name='example')
    else:
        role = {'process': 'process_image', 'file': 'file_create_target', 'mft': 'file_path'}.get(kind, 'unmapped')
        r['objects'] = [dict(role=role, original=name, normalized=normalize_path(name)['normalized'])]
        if kind == 'process':
            r['process_name'] = name
        if kind == 'file':
            r.update(provider='Microsoft-Windows-Sysmon', channel='Microsoft-Windows-Sysmon/Operational', event_id=11)
    return r


def result(anchor, *rows):
    return dict(direct_evidence=[anchor], evidence_records=[anchor, *rows], detections=[],
                parameters=dict(seconds=120, timestamp_slot=anchor['timestamps'][0]['slot']))


def text(r, color=False):
    view = View(Palette(color))
    anchor = r['direct_evidence'][0]
    summary.render(view, r, anchor, anchor['timestamps'][0]['timestamp_utc'], r['parameters']['timestamp_slot'])
    return view.result()


def chosen(r):
    a = r['direct_evidence'][0]
    return summary.select(r, a, a['timestamps'][0]['timestamp_utc'])


def test_related_evidence_and_tools_surface_but_noise_does_not():
    a = record('userassist', r'C:\Windows\example.exe', 'anchor', user='alice')
    rows = [record('prefetch', 'EXAMPLE.EXE', 'pf', 63_320_300),
            record('userassist', 'cmd.exe', 'cmd-ua', 17_157_000_000),
            record('prefetch', 'CMD.EXE', 'cmd-pf', 17_188_420_200),
            record('prefetch', 'CONHOST.EXE', 'conhost', 17_219_426_100),
            record('prefetch', 'SC.EXE', 'sc', 113_313_809_700),
            record('service', r'C:\Windows\example.exe', 'svc', 113_329_537_000)]
    noise = [record('prefetch', f'noise{i}.exe', f'noise{i}', i) for i in range(50)]
    noise += [record('registry', f'Software\\Noise{i}', f'key{i}', i) for i in range(50)]
    noise += [record('event', 'unmapped', 'unmapped', 1)]
    r = result(a, *noise, *rows)
    selected, count = chosen(r)
    assert {o.record['id'] for o in selected} == {v['id'] for v in rows} and count == 6
    shown = text(r)
    assert '+0.063s' in shown and '+17.157s' in shown and '+113.330s' in shown
    assert 'noise' not in shown.lower() and 'LastWrite' not in shown and 'unmapped' not in shown
    assert 'Command Prompt-related observations' in shown
    assert len(r['evidence_records']) == 108


def test_direct_match_precedes_unrelated_high_semantics_and_cap(monkeypatch):
    a = record('process', r'C:\example.exe', 'anchor')
    direct = record('prefetch', 'EXAMPLE.EXE', 'direct', 100_000_000_000)
    unrelated = record('service', r'C:\other.exe', 'service', 1)
    monkeypatch.setattr(summary, 'MAX_OBSERVATIONS', 1)
    selected, count = chosen(result(a, unrelated, direct))
    assert count == 2 and selected[0].record['id'] == direct['id']
    assert selected[0].reason == 'exact object comparison'


def test_stable_cap_and_distinct_evidence_slots():
    a = record('userassist', 'example.exe', 'anchor')
    rows = [record('prefetch', 'EXAMPLE.EXE', f'{i:02}', 1_000_000) for i in range(12)]
    rows[0]['timestamps'].append(dict(slot='run:1', timestamp_utc=stamp(1_000_000)))
    r = result(a, *rows)
    before = copy.deepcopy(r)
    selected, count = chosen(r)
    assert count == 13 and len(selected) == summary.MAX_OBSERVATIONS == 8
    assert selected[0].record['id'] == selected[1].record['id']
    assert {selected[0].timestamp['slot'], selected[1].timestamp['slot']} == {'run:0', 'run:1'}
    assert len({o.key for o in selected}) == 8
    r['evidence_records'].reverse()
    for row in r['evidence_records']:
        row['timestamps'].reverse()
    assert [o.key for o in chosen(r)[0]] == [o.key for o in selected]
    assert '8 of 13 eligible' in text(r)
    assert len(before['evidence_records']) == len(r['evidence_records'])


@pytest.mark.parametrize('status,slot,expected', [('parsed', 'LastWrite', 'Registry key LastWrite'),
                                                ('unsupported', UA_SLOT, None), ('parsed', UA_SLOT, 'UserAssist recorded')])
def test_userassist_slot_semantics(status, slot, expected):
    a = record('prefetch', 'example.exe', 'anchor')
    ua = record('userassist', 'example.exe', 'ua', 5)
    ua['detail']['userassist']['status'] = status
    ua['timestamps'][0]['slot'] = slot
    shown = text(result(a, ua))
    if expected:
        assert expected in shown
    else:
        assert 'No higher-priority related observations' in shown
    if slot == 'LastWrite':
        assert 'UserAssist recorded' not in shown
        assert 'containing-key timestamp; not an execution time' in shown
        assert 'UserAssist and Prefetch observations' not in shown


def test_attribution_color_and_no_causal_prose():
    a = record('process', r'C:\example.exe', 'anchor')
    ua = record('userassist', r'C:\example.exe', 'ua', -63_320_300, user='alice')
    pf = record('prefetch', 'EXAMPLE.EXE', 'pf', 63_320_300)
    svc = record('service', r'C:\Windows\example.exe', 'svc', 113_329_537_000)
    r = result(a, ua, pf, svc)
    plain = text(r)
    assert plain.count('User: alice') == 1
    assert plain.index('UserAssist recorded') < plain.index('User: alice') < plain.index('Prefetch recorded')
    assert 'Service account: LocalSystem' in plain and 'User: LocalSystem' not in plain
    assert '-0.063s' in plain and '+0.063s' in plain
    assert '\x1b' not in plain and '\x1b' in text(r, True)
    assert SGR.sub('', text(r, True)) == plain
    for phrase in ('launched', 'caused', 'executed by', 'attacker', 'persistence established', 'successfully ran'):
        assert phrase not in plain.casefold()
    assert summary.CAUTION in plain
    assert 'same file' in plain  # basename agreement is explicitly limited


def test_no_fuzzy_or_incidental_reference_match():
    a = record('prefetch', 'example.exe', 'anchor')
    pf = record('prefetch', 'unrelated.exe', 'pf')
    pf['objects'].append(dict(role='referenced_file', original=r'C:\example.exe'))
    typo = record('userassist', 'examp1e.exe', 'typo')
    assert chosen(result(a, pf, typo)) == ([], 0)
    process = record('process', r'C:\unrelated.exe', 'process')
    process['objects'].append(dict(role='parent_image', original=r'C:\example.exe'))
    obs = chosen(result(a, process))[0][0]
    assert not obs.matches  # process remains an observation, never a basename relationship
    ambiguous = record('service', r'C:\Program Files\example.exe --arg', 'ambiguous')
    assert not chosen(result(a, ambiguous))[0][0].matches


@pytest.mark.parametrize('mode', ['other-host', 'unknown', 'conflict', 'ambiguous', 'outside-window'])
def test_host_and_window_boundaries(mode):
    a = record('prefetch', 'example.exe', 'anchor')
    row = record('userassist', 'example.exe', 'row')
    if mode == 'other-host': row['host_key'] = 'host-b'
    if mode == 'unknown': row['host_key'] = None
    if mode == 'conflict': row['context']['conflicts'] = ['hostname']
    if mode == 'ambiguous': row['context']['source_ids'] = ['a', 'b']
    if mode == 'outside-window': row['timestamps'][0]['timestamp_utc'] = stamp(121_000_000_000)
    assert chosen(result(a, row)) == ([], 0)


def test_mft_file_creation_and_detection_exception_keep_semantics():
    a = record('prefetch', 'example.exe', 'anchor')
    mft = record('mft', r'C:\example.exe', 'mft', 1)
    file = record('file', r'C:\example.exe', 'file', 2)
    file['timestamps'][0]['slot'] = 'Sysmon.CreationUtcTime'
    event = record('event', 'unmapped', 'event', 3)
    r = result(a, mft, file, event)
    r['detections'] = [dict(rule_id='TEST-001', rule_name='Synthetic', evidence_ids=[event['id']])]
    selected, _ = chosen(r)
    assert len(selected) == 3
    shown = text(r)
    assert 'MFT metadata timestamp' in shown and 'Sysmon-reported target-file creation timestamp' in shown
    assert 'EVTX observation' in shown and 'TEST-001: Synthetic' in shown


def test_untrusted_terminal_text_is_escaped():
    a = record('prefetch', 'example.exe', 'anchor')
    svc = record('service', r'C:\example.exe', 'service')
    svc['service_name'] = 'name\x1b[31m\nattacker-supplied'
    shown = text(result(a, svc))
    assert '\x1b' not in shown
    assert r'\u001b[31m\nattacker-supplied' in shown


def test_rendering_queries_nothing_preserves_json_and_nearby(mixed_case, monkeypatch):
    from forensic_assistant.retrieval.evidence import EvidenceQueries
    db, pfid, uaid, _ = mixed_case
    ids = registry_rows(db, uaid, 10, stamp(100_000_000))
    r = investigate(db, uaid, seconds=1, timestamp_slot=UA_SLOT)
    before = json.dumps(r)
    sql = []
    db.set_trace_callback(sql.append)
    def forbidden(*args, **kwargs):
        pytest.fail('Presentation attempted evidence retrieval')
    monkeypatch.setattr(EvidenceQueries, 'search', forbidden)
    shown = render_investigation(r)
    assert sql == [] and json.dumps(r) == before
    assert shown.index('Anchor') < shown.index('Investigation summary') < shown.index('Nearby evidence')
    top = shown.split('Investigation summary')[1].split('Nearby evidence')[0]
    assert 'Prefetch recorded TEST.EXE' in top and 'Registry key LastWrite' not in top
    assert '7 additional Registry LastWrite observations omitted' in shown
    assert set(ids) <= {v['id'] for v in r['evidence_records']}
    assert 'Timestamp:' in shown.split('Nearby evidence')[1]
    assert pfid in r['temporal_neighbor_ids']
    assert SGR.sub('', render_investigation(r, Palette(True))) == shown


def test_unresolved_anchor_has_no_summary(mixed_case):
    db, _, uaid, _ = mixed_case
    r = investigate(db, uaid, seconds=1)
    shown = render_investigation(r)
    assert 'Investigation summary' not in shown
    assert 'Available slots:' in shown and 'Temporal search not performed' in shown


def test_empty_and_unknown_host_guidance():
    a = record('prefetch', 'example.exe', 'anchor')
    assert 'No higher-priority related observations' in text(result(a))
    a['host_key'] = None
    shown = text(result(a, record('prefetch', 'example.exe', 'other')))
    assert 'resolve the anchor host context' in shown
    assert 'No higher-priority related observations' not in shown


def test_detection_references_do_not_copy_rule_narrative():
    a = record('prefetch', 'example.exe', 'anchor')
    svc = record('service', r'C:\example.exe', 'service')
    r = result(a, svc)
    finding = dict(rule_id='LOCARD-SVC-001', rule_name='Service installation', evidence_ids=[svc['id']],
                   reason='Full explanation belongs below', severity='low')
    r['detections'] = [finding, copy.deepcopy(finding)]
    shown = text(r)
    assert shown.count('LOCARD-SVC-001: Service installation') == 1
    assert finding['reason'] not in shown
    assert len(r['detections']) == 2  # presentation never edits underlying findings

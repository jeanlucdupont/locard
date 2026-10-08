"""Deterministic text-only prioritization of already hydrated investigation evidence.

No queries, new evidence, or forensic relationships are produced here. Selection
uses exact object comparisons, explicit artifact semantics and a small named-tool
list for temporal context. A basename match is not proof of the same file.
"""
from dataclasses import dataclass
import ntpath

from forensic_assistant.artifacts.paths import normalize_path, executable_reference
from forensic_assistant.artifacts.userassist import SLOT as UA_SLOT
from forensic_assistant.correlation.models import time_ns
from forensic_assistant.ingest.service import is_installation
from forensic_assistant.ingest.sysmon import is_file_create
from .around_display import delta
from .prefetch_display import executable
from .presentation import safe_path

MAX_OBSERVATIONS = 8
# Exact names only: temporal context, never a parent/child or causal assertion.
ADJACENCY_NAMES = frozenset(('cmd.exe', 'command prompt.lnk', 'conhost.exe', 'sc.exe'))
SEMANTIC_ORDER = {'service': 0, 'process': 1, 'file': 2, 'userassist': 3,
                  'prefetch': 4, 'mft': 5, 'registry': 6, 'event': 7}
ROLES = {'filename', 'file_path', 'file_create_target', 'process_image', 'executable_name'}
CAUTION = ('Temporal proximity does not establish causality or prove a shared '
           'process instance or process chain.')


def object_values(record):
    """Exclude parent images and incidental Prefetch referenced files."""
    detail = record.get('detail') or {}
    source = record['source_type']
    if source == 'prefetch':
        return [executable(record)]
    if ua := detail.get('userassist'):
        return [ua.get('decoded_name')]
    if service := record.get('service_installation'):
        return [executable_reference(service.get('image_path') or '')]
    if source == 'evtx' and is_file_create(record):
        return [o['original'] for o in record.get('objects', []) if o['role'] == 'file_create_target']
    return [o['original'] for o in record.get('objects', []) if o['role'] in ROLES]


def identity(record):
    keys = set()
    for value in object_values(record):
        if not value:
            continue
        path = normalize_path(value)
        if path['normalized']:
            keys.add(('path', path['normalized']))
            if path['basename']:
                keys.add(('basename', path['basename']))
    if record.get('service_name'):
        keys.add(('service', record['service_name'].casefold()))
    for obj in record.get('objects', []):
        if obj['role'] == 'key' and obj.get('normalized'):
            keys.add(('registry_key', obj['normalized']))
    return keys


def semantics(record, timestamp):
    """Labels depend on the actual slot, particularly for UserAssist LastWrite."""
    source, slot = record['source_type'], timestamp['slot']
    detail = record.get('detail') or {}
    values = sorted(filter(None, object_values(record)), key=lambda x: (x.casefold(), x))
    name = values[0] if values else None
    ua = detail.get('userassist')
    if source == 'registry':
        if ua and ua.get('status') == 'parsed' and slot == UA_SLOT:
            return 'userassist', ntpath.basename(ua['decoded_name'])
        if slot == 'LastWrite':
            return 'registry', (ua or {}).get('decoded_name') or detail.get('key_path')
    elif source == 'prefetch' and slot.startswith('run:') and slot[4:].isdigit():
        return 'prefetch', name
    elif source == 'mft':
        return 'mft', name
    elif source == 'evtx':
        if record.get('artifact_type') == 'service' and slot == 'SystemTime':
            return 'service', record.get('service_name')
        if record.get('artifact_type') == 'process' and slot == 'SystemTime':
            return 'process', record.get('process_name') or name
        if is_file_create(record) and slot in ('SystemTime', 'Sysmon.UtcTime', 'Sysmon.CreationUtcTime'):
            return 'file', name
        if slot == 'SystemTime':
            return 'event', name or f"Event {record.get('event_id', 'unknown')}"
    return None, None


@dataclass(frozen=True)
class Observation:
    record: dict
    timestamp: dict
    kind: str
    name: str
    matches: frozenset
    reason: str
    rank: tuple

    @property
    def key(self):
        return self.record['id'], self.timestamp['slot'], self.timestamp['timestamp_utc']


def select(result, anchor, stamp):
    """Return capped observations plus the eligible count; never mutate input.

    Rank: direct object match, semantic class, detection relevance, absolute
    temporal distance, UTC, evidence ID, slot. Display the selected set in UTC
    order. Distinct IDs/slots stay separate even at identical timestamps.
    """
    host = anchor.get('host_key')
    if not host:
        return [], 0
    anchor_keys = identity(anchor)
    detected = {eid for d in result['detections'] for eid in d.get('evidence_ids', [])}
    observations = {}
    for record in result['evidence_records']:
        if record['id'] == anchor['id'] or record.get('host_key') != host:
            continue
        context = record.get('context') or {}
        if len(context.get('source_ids', [])) > 1 or {'hostname', 'source membership', 'source/artifact hostname'} & set(context.get('conflicts', [])):
            continue
        keys = identity(record)
        matches = frozenset(anchor_keys & keys)
        known_tool = any(('basename', name) in keys for name in ADJACENCY_NAMES)
        detection = record['id'] in detected
        for timestamp in record['timestamps']:
            value = timestamp.get('timestamp_utc')
            if not value:
                continue
            distance = abs(time_ns(value) - time_ns(stamp))
            if distance > result['parameters']['seconds'] * 1_000_000_000:
                continue
            kind, name = semantics(record, timestamp)
            if not kind or not name:
                continue
            tool = known_tool and kind in ('prefetch', 'userassist', 'process')
            if not (matches or detection or tool or kind in ('service', 'process', 'file')):
                continue
            reason = ('exact object comparison' if matches else 'existing detection' if detection
                      else 'exact named-tool temporal context' if tool else 'normalized event semantics')
            rank = (not bool(matches), SEMANTIC_ORDER[kind], not detection, distance,
                    value, record['id'], timestamp['slot'])
            observation = Observation(record, timestamp, kind, name, matches, reason, rank)
            observations[observation.key] = observation
    ranked = sorted(observations.values(), key=lambda o: o.rank)
    selected = sorted(ranked[:MAX_OBSERVATIONS], key=lambda o: (o.timestamp['timestamp_utc'], o.key))
    return selected, len(ranked)


def assessment(anchor, stamp, selected, anchor_slot):
    lines = []
    basename_matches = sorted({value for o in selected for namespace, value in o.matches if namespace == 'basename'})
    if basename_matches:
        name = basename_matches[0]
        related = [o for o in selected if ('basename', name) in o.matches]
        families = {anchor['source_type'], *(o.record['source_type'] for o in related)}
        if len(families) > 1:
            lines.append(f'Multiple independent artifact families reference {name} on the same host within the selected window.')
            lines.append('Executable/object basename agreement does not prove identical paths or the same file.')
        anchor_kind, _ = semantics(anchor, {'slot': anchor_slot})
        paired = [o for o in related if {o.kind, anchor_kind} == {'userassist', 'prefetch'}]
        if paired:
            nearest = min(paired, key=lambda o: (abs(time_ns(o.timestamp['timestamp_utc']) - time_ns(stamp)), o.key))
            separation = delta(nearest.timestamp['timestamp_utc'], stamp).lstrip('+-')
            lines.append(f'UserAssist and Prefetch observations for {name} are approximately {separation} apart.')
    commands = [o for o in selected if o.kind in ('userassist', 'prefetch', 'process')
                and ntpath.basename(o.name).casefold() in ('cmd.exe', 'command prompt.lnk')]
    if commands:
        closest = min(commands, key=lambda o: (abs(time_ns(o.timestamp['timestamp_utc']) - time_ns(stamp)), o.key))
        lines.append('Command Prompt-related observations occur at ' + delta(closest.timestamp['timestamp_utc'], stamp) + ' relative to the anchor.')
    sc = [o for o in selected if o.kind == 'prefetch' and ntpath.basename(o.name).casefold() == 'sc.exe']
    if sc:
        closest = min(sc, key=lambda o: (abs(time_ns(o.timestamp['timestamp_utc']) - time_ns(stamp)), o.key))
        lines.append('SC.EXE Prefetch activity is recorded at ' + delta(closest.timestamp['timestamp_utc'], stamp) + ' relative to the anchor.')
    services = [o for o in selected if o.kind == 'service' and o.matches and (o.record.get('service_installation') or {}).get('image_path')]
    if services:
        closest = min(services, key=lambda o: (abs(time_ns(o.timestamp['timestamp_utc']) - time_ns(stamp)), o.key))
        lines.append('A service installation referencing ' + closest.record['service_installation']['image_path']
                     + ' is recorded at ' + delta(closest.timestamp['timestamp_utc'], stamp) + ' relative to the anchor.')
    lines.append(CAUTION)
    return lines


def render(view, result, anchor, stamp, anchor_slot):
    """Append only human presentation through the existing palette/escaping."""
    def line(text, role='secondary_text'):
        view.lines.append(view.palette(role, safe_path(text)))

    view.section('Investigation summary')
    if not anchor.get('host_key'):
        line('Same-host summary unavailable; resolve the anchor host context.')
        return
    selected, count = select(result, anchor, stamp)
    if not selected:
        line('No higher-priority related observations identified in the selected window.')
        line('This describes the returned evidence, not a complete examination.')
        return
    line('Key observations', 'heading')
    for obs in selected:
        r, t, name = obs.record, obs.timestamp, obs.name
        if obs.kind == 'service':
            text = ('Service Control Manager recorded installation of service "' + name + '"'
                    if is_installation(r) else 'EVTX recorded service observation for ' + name)
        else:
            text = {'userassist': 'UserAssist recorded ', 'prefetch': 'Prefetch recorded ',
                    'process': 'EVTX recorded process observation for ', 'file': 'Sysmon file creation observation: ',
                    'mft': 'MFT metadata timestamp for ', 'registry': 'Registry key LastWrite for ',
                    'event': 'EVTX observation: '}[obs.kind] + name
        if obs.kind == 'registry' and (r.get('detail') or {}).get('userassist'):
            text += ' (containing-key timestamp; not an execution time)'
        if obs.kind == 'file' and t['slot'] == 'Sysmon.CreationUtcTime':
            text = 'Sysmon-reported target-file creation timestamp for ' + name
        role = {'prefetch': 'string_value', 'registry': 'key', 'mft': 'number_value', 'evtx': 'boolean_value'}[r['source_type']]
        line(delta(t['timestamp_utc'], stamp) + '  ' + text + ' [' + t['slot'] + ']', role)
        if obs.kind == 'userassist' and r.get('username') and 'username' not in r.get('context', {}).get('conflicts', []):
            line('    User: ' + r['username'])
        if obs.kind == 'service':
            service = r.get('service_installation') or {}
            for label, key in [('Image', 'image_path'), ('Service account', 'account')]:
                if service.get(key):
                    line('    ' + label + ': ' + service[key])
    line(f'{len(selected)} of {count} eligible observations selected from the retrieved evidence; details remain below.')
    line('')
    line('Assessment', 'heading')
    for text in assessment(anchor, stamp, selected, anchor_slot):
        line('- ' + text)
    findings = sorted({(d['rule_id'], d['rule_name']) for d in result['detections']})
    if findings:
        line('')
        line('Detection references (details below)', 'heading')
        for rule_id, name in findings[:3]:
            line('- ' + rule_id + ': ' + name)
        if len(findings) > 3:
            line(f'{len(findings) - 3} additional rules listed in Detections below.')

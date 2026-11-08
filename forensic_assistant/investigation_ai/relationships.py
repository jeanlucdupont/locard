"""S2: bounded derived comparisons of validated S1 recorded-view clauses.

reconstruct() is the grounding entry point. _build() and render() consume trusted
application reconstruction, not external JSON claiming to contain evidence.
No database access, provider calls, physical clock inference or transitive closure.
"""
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
import json
import re

from . import synthesis as s1
from .projection import same
from .state import encoded
from .transcript import digest

CONTRACT = 'synthesis-relationship-v1'
RESULT = 'recorded-relationships-v1'
MAX_COMPARISONS = 192
MAX_RELATIONSHIPS = 64
MAX_BYTES = s1.MAX_RESULT_BYTES
RULES = {
    'recorded_time_before': 'recorded-utc-interval-v1',
    'exact_recorded_path': 'exact-path-string-v1',
    'exact_recorded_identifier': 'same-source-guid-string-v1',
    'incompatible_recorded_field': 'same-occurrence-value-conflict-v1',
}
TIME = re.compile(r'^(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$')
STAMP = re.compile(r'/timestamps/\d+/utc\Z')
PATH = re.compile(r'^(?:[A-Za-z]:\\|\\\\[^\\]+\\|\\Device\\)')
_GUID_BODY = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
GUID = re.compile(r'^(?:' + _GUID_BODY + r'|\{' + _GUID_BODY + r'\})$')
GUID_NAMES = frozenset(('ProcessGuid', 'ParentProcessGuid', 'LogonGuid'))


def _support(c):
    return c['supports'][0]


def _sources(c):
    context = _support(c)['context'].get('source_context') or {}
    ids = context.get('source_ids', [])
    return tuple(sorted(set(ids))) if isinstance(ids, list) and all(isinstance(v, str) for v in ids) else ()


def _complete(c):
    support = _support(c)
    field = support.get('field', {})
    if field.get('semantic', {}).get('truncated'):
        return False
    pointer = field.get('pointer', '')
    for truncated in support['context'].get('truncated_fields') or []:
        root = '/' + str(truncated).strip('/')
        if root == '/*' or pointer == root or pointer.startswith(root + '/'):
            return False
    notes = support['context'].get('coverage_notes') or []
    return not (('original_value_shortened' in notes and pointer.startswith('/original_event_data/'))
                or 'normalized_value_shortened' in notes)


def _time(c):
    if c['type'] != 'observation':
        return None
    support = _support(c)
    field = support['field']
    pointer = field['pointer']
    if not STAMP.fullmatch(pointer) and pointer != '/timestamp_utc':
        return None
    stamp = deepcopy(support.get('timestamp') or field.get('semantic') or {})
    value = field['value']
    out = dict(clause_id=c['id'], evidence_id=support['evidence_id'], field=pointer,
               original_value=deepcopy(value), timestamp_semantics=stamp,
               source_ids=list(_sources(c)), source_context=deepcopy(support['context'].get('source_context')),
               original_precision=stamp.get('precision', 'unknown'),
               clock_domain='not established', clock_skew='unknown',
               status='incomparable', reason='unknown_timezone_or_unsupported_timestamp',
               interval=None)
    if not _complete(c):
        out['reason'] = 'truncated_timestamp_projection'
        return out
    if not isinstance(value, str) or not (match := TIME.fullmatch(value)):
        return out
    try:
        zone = match[4]
        if zone == 'Z':
            offset = 0
        else:
            hours, minutes = map(int, zone[1:].split(':'))
            if hours > 14 or minutes > 59 or (hours == 14 and minutes):
                return out
            offset = (1 if zone[0] == '+' else -1) * (hours * 3600 + minutes * 60)
        base = datetime.fromisoformat(match[1] + 'T' + match[2]).replace(tzinfo=timezone.utc)
        seconds = Decimal((base - datetime(1970, 1, 1, tzinfo=timezone.utc)).days * 86400
                          + (base - datetime(1970, 1, 1, tzinfo=timezone.utc)).seconds - offset)
        fraction = match[3] or ''
        seconds += Decimal('0.' + fraction) if fraction else Decimal(0)
        quantum = Decimal(10) ** -len(fraction)
        # Conservative closed enclosure of serialized resolution, NOT acquisition
        # precision, clock uncertainty or real-world event-time accuracy.
        out.update(status='recorded_utc_coordinate', reason=None, timezone=zone,
                   serialized_resolution_seconds=str(quantum),
                   interval={'lower': str(seconds), 'upper': str(seconds + quantum),
                             'basis': 'serialized UTC coordinate enclosure; not physical event uncertainty'})
    except (ValueError, OverflowError):
        pass
    return out


def _path(c):
    if c['type'] != 'observation' or not _complete(c):
        return None
    support = _support(c)
    field = support['field']
    pointer, value = field['pointer'], field['value']
    known = (pointer in ('/target_path', '/current_path')
             or (pointer.startswith('/objects/') and support['source_type'] in ('mft', 'prefetch')))
    # URL, filename, executable basename and command-line strings are not paths.
    return value if known and isinstance(value, str) and PATH.match(value) else None


def _identifier(c):
    if c['type'] != 'observation' or not _complete(c):
        return None
    support = _support(c)
    field = support['field']
    semantic = field.get('semantic', {})
    sources = _sources(c)
    if (support['source_type'] != 'evtx' or not field['pointer'].startswith('/original_event_data/')
            or semantic.get('name') not in GUID_NAMES or len(sources) != 1
            or not isinstance(field['value'], str) or not GUID.fullmatch(field['value'])):
        return None
    # No case/braces normalization, and ProcessGuid is not equated with LogonGuid.
    return (semantic['name'], sources, field['value'])


def _occurrence(c):
    if c['type'] != 'observation' or not _complete(c):
        return None
    support = _support(c)
    field = support['field']
    semantic = field.get('semantic', {})
    # Only exact original EventData occurrence. Other scalar/array semantics lack
    # enough occurrence identity in S1; different times/names are not conflicts.
    if (support['source_type'] != 'evtx'
            or not re.fullmatch(r'/original_event_data/\d+/value', field['pointer'])
            or not isinstance(semantic.get('name'), str) or type(semantic.get('ordinal')) is not int):
        return None
    return (support['evidence_id'], field['pointer'], semantic['name'], semantic['ordinal'],
            support['provenance'], encoded(support['context'].get('source_context')))


def _relationship(predicate, a, b, semantics):
    if predicate not in RULES or not same(a['evidence_state'], b['evidence_state']):
        raise ValueError('Unsupported relationship or cross-view endpoints')
    qualifiers = sorted(set(a['qualifications'] + b['qualifications'] + [
        'Derived recorded-view comparison, not independent evidence or current-case revalidation.',
        'No causality, common file/process/host identity, or successful execution is established.',
    ]))
    body = dict(contract=CONTRACT, predicate=predicate, rule=RULES[predicate],
                endpoints=[a['id'], b['id']], supports=deepcopy(a['supports'] + b['supports']),
                interpretation_ids=sorted(set(a['interpretation_ids'] + b['interpretation_ids'])),
                evidence_state=deepcopy(a['evidence_state']), semantics=deepcopy(semantics),
                assumptions=['Clock synchronization and physical event ordering are not established.']
                    if predicate == 'recorded_time_before' else ['Only the declared recorded-value domain is compared.'],
                qualifications=qualifiers, validation='validated_recorded_comparison')
    return dict(body, id=digest(body), lineage={a['id']: deepcopy(a['lineage']), b['id']: deepcopy(b['lineage'])})


def _compare(predicate, a, b, times):
    if predicate == 'recorded_time_before':
        left, right = times[a['id']], times[b['id']]
        if left['interval'] is None or right['interval'] is None:
            return None, 'incomparable_time'
        if Decimal(left['interval']['upper']) >= Decimal(right['interval']['lower']):
            return None, 'equal_or_overlapping_recorded_intervals'
        return _relationship(predicate, a, b, dict(ordering='recorded_utc_values_only',
            left=left, right=right, physical_event_order='not established',
            conditional_event_order='Would require independently justified clock/precision bounds; not validated in S2.')), None
    if predicate == 'exact_recorded_path':
        if _path(a) is None or _path(a) != _path(b):
            return None, 'not_exact_complete_paths'
        return _relationship(predicate, a, b, dict(domain='exact_recorded_path_string', value=_path(a),
            normalization='none', source_ids=[list(_sources(a)), list(_sources(b))],
            object_volume_host_identity='not established')), None
    if predicate == 'exact_recorded_identifier':
        key = _identifier(a)
        if key is None or key != _identifier(b):
            return None, 'incompatible_identifier_domain'
        return _relationship(predicate, a, b, dict(domain=key[0], source_ids=list(key[1]),
            value=key[2], normalization='none', meaning='same recorded GUID string in the same asserted source; not an independently confirmed process/session identity')), None
    if predicate == 'incompatible_recorded_field':
        if _occurrence(a) is None or _occurrence(a) != _occurrence(b):
            return None, 'incomparable_occurrences'
        if same(_support(a)['field']['value'], _support(b)['field']['value']):
            return None, 'same_recorded_value'
        return _relationship(predicate, a, b, dict(domain='same_original_eventdata_occurrence',
            meaning='Incompatible recorded projections of one field occurrence; neither value is selected as correct.')), None
    raise ValueError('Unsupported relationship predicate')


def _graph(nodes, relations):
    """Kahn layers over explicit edges only. No inferred/transitive edges."""
    edges = [(r['endpoints'][0], r['endpoints'][1]) for r in relations if r['predicate'] == 'recorded_time_before']
    indegree = dict.fromkeys(nodes, 0)
    outgoing = defaultdict(set)
    for left, right in edges:
        if left not in indegree or right not in indegree:
            raise ValueError('Unknown temporal endpoint')
        if right not in outgoing[left]:
            outgoing[left].add(right)
            indegree[right] += 1
    layers = []
    frontier = sorted(n for n, count in indegree.items() if not count)
    visited = set()
    while frontier:
        layers.append(frontier)
        next_nodes = []
        for node in frontier:
            visited.add(node)
            for target in sorted(outgoing[node]):
                indegree[target] -= 1
                if not indegree[target]:
                    next_nodes.append(target)
        frontier = sorted(next_nodes)
    return dict(recorded_coordinate_layers=layers, unresolved_cycle_or_dependent_nodes=sorted(set(nodes) - visited),
                transitive_edges_inferred=False,
                layer_meaning='Topological display grouping only; membership or adjacency does not assert an additional temporal relationship.')


def _build(factual, *, comparison_limit=MAX_COMPARISONS, relationship_limit=MAX_RELATIONSHIPS):
    """Internal service for verified S1 output; not an external JSON importer."""
    if (type(comparison_limit) is not int or not 0 <= comparison_limit <= MAX_COMPARISONS
            or type(relationship_limit) is not int or not 0 <= relationship_limit <= MAX_RELATIONSHIPS):
        raise ValueError('Invalid relationship limits')
    s1._bounded(factual, s1.MAX_RESULT_BYTES)
    if factual.get('contract') != s1.RESULT or factual.get('recorded_not_revalidated') is not True:
        raise ValueError('Expected validated recorded S1 state')
    if len(factual['clauses']) > s1.MAX_CLAUSES:
        raise ValueError('S1 clause ceiling exceeded')
    clauses = {}
    for clause in factual['clauses']:
        s1._validate_render_clause(clause)
        if not same(clause['evidence_state'], factual['evidence_state']):
            raise ValueError('Cross-view relationship input')
        if clause['id'] in clauses and not same(clause, clauses[clause['id']]):
            raise ValueError('Conflicting duplicate clause')
        clauses[clause['id']] = clause
    times = {c['id']: t for c in clauses.values() if (t := _time(c)) is not None}
    ordered = sorted((t for t in times.values() if t['interval']),
                     key=lambda t: (Decimal(t['interval']['lower']), t['clause_id']))
    candidates = []
    omitted_pairs = max(0, len(ordered) * (len(ordered) - 1) // 2 - max(0, len(ordered) - 1))
    # Adjacent timestamp candidates, not unrestricted all-pairs chronology.
    candidates += [('recorded_time_before', a['clause_id'], b['clause_id']) for a, b in zip(ordered, ordered[1:])]
    for predicate, key_fn in (('exact_recorded_path', _path), ('exact_recorded_identifier', _identifier),
                              ('incompatible_recorded_field', _occurrence)):
        groups = defaultdict(list)
        for clause in clauses.values():
            key = key_fn(clause)
            if key is not None:
                groups[key].append(clause['id'])
        for key in sorted(groups, key=encoded):
            ids = sorted(groups[key])
            omitted_pairs += max(0, len(ids) * (len(ids) - 1) // 2 - max(0, len(ids) - 1))
            candidates += [(predicate, ids[0], other) for other in ids[1:]]
    candidates = sorted(set(candidates))
    relations, rejected = [], []
    coverage = dict(clauses_examined=len(clauses), indexed_candidates=len(candidates), considered=0,
                    accepted=0, rejected=0, validated_not_retained=0, unassessed_candidates=len(candidates),
                    pairs_not_generated_by_sparse_policy=omitted_pairs,
                    incomparable_timestamp_entries=sum(t['interval'] is None for t in times.values()),
                    comparison_limit=comparison_limit, relationship_limit=relationship_limit,
                    incomplete=True, relevance_of_omissions='Not evaluated',
                    policy='Adjacent comparable UTC timestamps; star comparisons within exact path/identifier/occurrence buckets. Other pairs are not assessed.')
    output = dict(contract=RESULT, recorded_not_revalidated=True, factual=deepcopy(factual), relationships=relations,
                  chronology=dict(entries=[times[k] for k in sorted(times)], graph={}),
                  rejected_candidates=rejected, coverage=coverage,
                  limitations=['Recorded UTC ordering does not establish physical event ordering, causality or execution.',
                    'No validated clock-domain/skew-bound contract is available in S1; same-clock and skew-conditional event edges are not generated.',
                    'Exact paths are compared without normalization; drive letters and equal paths do not establish volume/object/host identity.',
                    'Unknown timezone and shortened fields fail closed; sparse comparisons are not exhaustive.',
                    'All original S1 qualifications and hypotheses remain in factual output; no question-level answer is generated.'])
    used = len(encoded(output).encode())
    for predicate, left, right in candidates:
        if coverage['considered'] >= comparison_limit or len(relations) >= relationship_limit:
            break
        relation, reason = _compare(predicate, clauses[left], clauses[right], times)
        coverage['considered'] += 1
        if relation is None:
            rejection = dict(predicate=predicate, endpoints=[left, right], reason=reason)
            size = len(encoded(rejection).encode())
            if used + size + 32768 > MAX_BYTES:
                coverage['considered'] -= 1
                break
            used += size
            rejected.append(rejection)
            coverage['rejected'] += 1
        else:
            # Reserve bounded envelope/graph/counter space before retaining a unit.
            size = len(encoded(relation).encode())
            if used + size + 32768 > MAX_BYTES:
                coverage['validated_not_retained'] += 1
                break
            used += size
            relations.append(relation)
            coverage['accepted'] += 1
    coverage['unassessed_candidates'] = len(candidates) - coverage['considered']
    coverage['incomplete'] = bool(coverage['unassessed_candidates'] or omitted_pairs or
                                  coverage['validated_not_retained'] or coverage['incomparable_timestamp_entries'])
    output['chronology']['graph'] = _graph(times, relations)
    s1._bounded(output, MAX_BYTES)
    return output


def reconstruct(root, identity):
    return _build(s1.reconstruct(root, identity))


def render(result):
    """Render validated application output, never a model-authored attack story."""
    if result.get('contract') != RESULT:
        raise ValueError('Unsupported relationship result')
    s1._bounded(result, MAX_BYTES)
    clauses = {c['id']: c for c in result['factual']['clauses']}
    for clause in clauses.values():
        s1._validate_render_clause(clause)
        if not same(clause['evidence_state'], result['factual']['evidence_state']):
            raise ValueError('Cross-view relationship input')
    times = {c['id']: t for c in clauses.values() if (t := _time(c)) is not None}
    if not same([times[k] for k in sorted(times)], result['chronology']['entries']):
        raise ValueError('Invalid chronology support')
    if not same(_graph(times, result['relationships']), result['chronology']['graph']):
        raise ValueError('Invalid chronology graph')
    labels = {cid: 'C' + str(i + 1) for i, cid in enumerate(sorted(clauses))}
    lines = ['Recorded-view qualified chronology — not current-case revalidation',
             'Recorded UTC coordinates only; physical event order is not established.',
             'Display adjacency is not causality or an additional validated edge.', '']
    for status in ('recorded_utc_coordinate', 'incomparable'):
        lines.append('Recorded timestamp values' if status == 'recorded_utc_coordinate' else 'Incomparable timestamps')
        for item in sorted(result['chronology']['entries'], key=lambda t: (
                Decimal(t['interval']['lower']) if t['interval'] else Decimal('Infinity'), t['clause_id'])):
            if item['status'] != status:
                continue
            lines.append('  ' + labels[item['clause_id']] + ': ' + json.dumps(item['original_value'], ensure_ascii=True)
                         + ' | ' + encoded(item['timestamp_semantics']))
            if item['reason']:
                lines.append('    ' + item['reason'])
    lines += ['', 'Conditional physical-event ordering: none (validated clock bounds unavailable).', '', 'Typed relationships']
    notes = set(result['limitations'])
    for clause in clauses.values():
        notes.update(clause['qualifications'])
    for relation in result['relationships']:
        if relation['predicate'] not in RULES or len(relation['endpoints']) != 2:
            raise ValueError('Unsupported relationship predicate/endpoints')
        if any(k not in clauses for k in relation['endpoints']):
            raise ValueError('Unknown supporting clause ID')
        a, b = (clauses[k] for k in relation['endpoints'])
        expected, _ = _compare(relation['predicate'], a, b, times)
        if not same(expected, relation):
            raise ValueError('Invalid relationship derivation')
        lines.append('  ' + relation['predicate'] + ': ' + labels[a['id']] + ' -> ' + labels[b['id']])
        notes.update(relation['qualifications'])
        notes.update(relation['assumptions'])
    lines += ['', 'Clause reference key (original references; all S1 clauses retained in JSON)']
    referenced = set(t['clause_id'] for t in result['chronology']['entries'])
    referenced.update(cid for r in result['relationships'] for cid in r['endpoints'])
    for cid in sorted(referenced):
        support = _support(clauses[cid])
        lines.append('  ' + labels[cid] + ': ' + json.dumps(support['evidence_id']) + ' ' + json.dumps(support.get('field', {}).get('pointer')))
    lines += ['', 'Qualifications'] + ['  - ' + json.dumps(n, ensure_ascii=True) for n in sorted(notes)]
    if result['chronology']['graph']['unresolved_cycle_or_dependent_nodes']:
        lines.append('Unresolved temporal cycle/dependencies: ' + encoded(result['chronology']['graph']['unresolved_cycle_or_dependent_nodes']))
    lines += ['', 'Relationship coverage: ' + encoded(result['coverage'])]
    lines += ['S1 factual clauses retained: ' + str(len(clauses)) + '; unverified hypotheses kept separate: '
              + str(len(result['factual']['hypotheses']))]
    return '\n'.join(lines)

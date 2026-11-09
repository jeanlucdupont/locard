"""B1 local previews from verified reconstruction; never a JSON evidence importer.

No provider, worker, database opener, journal writer or disclosure-ledger mutation.
The backend plan service consumes trusted application state. reconstruct() is the
public grounding entry point for saved investigations; hashes alone are not proof.
"""
from copy import deepcopy
from dataclasses import dataclass
import json
import re
import time

from . import disclosure, synthesis as s1, relationships as s2, decomposition, autonomous
from .conclusions import interpretations
from .projection import same
from .state import State, Budget, fields, encoded
from .transcript import load, digest

CONTRACT = 'synthesis-packet-v1'
SELECTION = 'synthesis-selection-v1'
SUPPORT = 'synthesis-support-v1'
INTERPRETATION = 'synthesis-interpretation-support-v1'
BINDING = 'synthesis-binding-v1'
RULE = 'bounded-original-support-v1'
INSTRUCTION = ('LOCAL PREVIEW ONLY; not dispatched. Original fields and recognized interpretations '
               'retain their distinct meanings. Scope is the recorded view, not the current case. '
               'Qualifications are mandatory. Historical hypotheses and omitted values are not '
               'evidence. Matching citations do not establish execution, causation or complete intent.')


@dataclass(frozen=True)
class Limits:
    packets: int = 2
    content_bytes: int = 5600
    candidates: int = 192
    resolutions: int = 512
    observations: int = 12
    interpretations: int = 4
    seconds: float = 5

    def __post_init__(self):
        caps = dict(packets=2, content_bytes=5600, candidates=192, resolutions=512,
                    observations=12, interpretations=4, seconds=5)
        for key, cap in caps.items():
            value = getattr(self, key)
            if type(value) not in ((int, float) if key == 'seconds' else (int,)) or not 0 < value <= cap:
                raise ValueError('Invalid preview budget')


class PlanningLimit(ValueError):
    pass


class Meter:
    def __init__(self, limits, clock):
        self.limits, self.clock = limits, clock
        self.deadline = clock() + limits.seconds
        self.resolutions = 0

    def check(self):
        if self.clock() >= self.deadline:
            raise PlanningLimit('planning_time')

    def resolve(self):
        self.check()
        if self.resolutions >= self.limits.resolutions:
            raise PlanningLimit('support_resolution_budget')
        self.resolutions += 1


@dataclass
class Context:
    """Trusted reducer inputs, not serialized claims from a user/model."""
    state: State
    factual: dict
    related: dict
    manifest: dict
    mapping: dict | None
    accepted: set


def _lineage_key(lineage):
    return (lineage['delta_id'], lineage['disclosure_sha256'], lineage['batch'])


def _validate_context(ctx):
    if (len(ctx.factual['clauses']) > s1.MAX_CLAUSES or len(ctx.related['relationships']) > s2.MAX_RELATIONSHIPS
            or not same(ctx.factual, ctx.related['factual'])
            or not same(ctx.factual['evidence_state'], ctx.manifest.get('evidence_state')) and ctx.factual['clauses']):
        raise ValueError('Unsupported preview state size/view')
    s1.render(ctx.factual)
    s2.render(ctx.related)
    if ctx.related['chronology']['graph']['unresolved_cycle_or_dependent_nodes']:
        raise ValueError('Cyclic chronology is not eligible for packet dependencies')
    grant = ctx.manifest['authorization']
    if grant.get('contract') not in ('investigation-authorization-v1', 'investigation-s4-authorization-v1', 'investigation-s4-b2-authorization-v1'):
        raise ValueError('Unknown recorded authorization contract')
    if ctx.mapping is not None:
        if not same(decomposition.validate(ctx.mapping['proposal'], ctx.manifest['question']), ctx.mapping):
            raise ValueError('Invalid recorded objective mapping')
    ids = [c['id'] for c in ctx.factual['clauses']]
    if len(set(ids)) != len(ids):
        raise ValueError('Duplicate factual clause')


def _rehydrate(clause, ctx, meter):
    meter.resolve()
    support = clause['supports'][0]
    eid = support['evidence_id']
    grant = ctx.manifest['authorization']
    if eid not in grant['evidence_ids'] or not same(clause['evidence_state'], ctx.manifest['evidence_state']):
        raise ValueError('Invalid support scope or epoch')
    record = lineage = None
    for entry in sorted(clause['lineage'], key=encoded):
        meter.check()
        if (entry.get('projection_contract') != disclosure.CONTRACT or entry.get('projection_encoding') != 'tuples-v1'
                or entry.get('origin') not in ('current', 'retained')):
            raise ValueError('Unsupported original projection contract')
        if _lineage_key(entry) not in ctx.accepted:
            raise ValueError('Unsupported accepted disclosure lineage')
        source = (ctx.state.records if entry['origin'] == 'current' else ctx.state.exposed).get(eid)
        if source is not None and digest(source) == entry['record_projection_sha256']:
            record, lineage = source, entry
            break
    if record is None:
        return None
    if (disclosure.provenance(record) != support['provenance']
            or not same(s1._context(record), support['context']) or record['source_type'] != support['source_type']):
        return None
    source_ids = set((record.get('source_context') or {}).get('source_ids', []))
    if not source_ids or not source_ids <= set(grant['source_ids']) or record['source_type'] not in grant['families']:
        raise ValueError('Invalid source binding')
    source = dict(context=deepcopy(support['context']), provenance=support['provenance'],
                  projection_sha256=digest(record), source_type=record['source_type'])
    common = dict(evidence_id=eid, source=source, lineage=deepcopy(lineage), clause_id=clause['id'])
    leaves = []
    derived = []
    if clause['type'] == 'observation':
        pointer = support['field']['pointer']
        available = dict(fields(record))
        if (pointer not in available or (lineage['origin'] == 'retained' and not ctx.state.field_eligible(eid, pointer))
                or not same(disclosure.descriptor(record, pointer, available[pointer]), support['field'])):
            return None
        leaf = dict(common, contract=SUPPORT, field=deepcopy(support['field']))
        if 'timestamp' in support:
            index = int(pointer.split('/')[2])
            if not same(support['timestamp'], record['timestamps'][index]):
                return None
            leaf['timestamp'] = deepcopy(record['timestamps'][index])
        leaves.append(leaf)
    else:
        expected = interpretations(record).get(support['interpretation_id'])
        if (support['interpretation_id'] not in record.get('interpretation_ids', [])
                or not same(expected, clause['arguments'])):
            return None
        for pointer in support['premise_pointers']:
            meter.resolve()
            key = pointer[1:]
            if key not in record or not same(record[key], support['premises'][key]):
                return None
            # defender_asr is recognized derived metadata, never mislabeled as an original observation.
            leaves.append(dict(common, contract=SUPPORT, field=dict(pointer=pointer, value=deepcopy(record[key]),
                label=key, semantic={'kind':'deterministic_premise' if key=='defender_asr' else 'original_premise'})))
        derived.append(dict(contract=INTERPRETATION, interpretation=deepcopy(expected),
                            premise_pointers=deepcopy(support['premise_pointers']), evidence_id=eid))
    return dict(clauses=[clause['id']], leaves=leaves, interpretations=derived,
                qualifications=deepcopy(clause['qualifications']), relationships=[])


def _typed(clause, kind, value):
    """Exact typed field domains only; no language/extension/command-line inference."""
    if clause['type'] != 'observation' or not s2._complete(clause):
        return False
    support = clause['supports'][0]
    pointer = support['field']['pointer']
    actual = support['field']['value']
    if not same(actual, value):
        return False
    if kind == 'browser_download':
        return clause['predicate'] == 'browser_download_field' and pointer in ('/target_path', '/current_path')
    if kind == 'filesystem_path':
        return support['source_type'] == 'mft' and s2._path(clause) is not None
    if kind == 'event_identifier':
        return support['source_type'] == 'evtx' and pointer == '/event_id' and type(value) is int
    return False


def _bindings(ctx, hydrated, meter):
    result = []
    for objective in (ctx.mapping or {}).get('objectives', []):
        meter.check()
        kind, args = objective['proposal']['proposition_type'], objective['arguments']
        status = 'unsupported_role'
        candidates = []
        if objective['proposal']['unresolved']:
            status = 'unsupported_role'
        elif kind in ('browser_download', 'filesystem_path', 'event_identifier'):
            value = args.get('event_id' if kind == 'event_identifier' else 'value')
            if kind in ('browser_download', 'filesystem_path') and (not isinstance(value, str) or not s2.PATH.match(value)):
                status = 'not_a_validated_technical_referent'
            else:
                domains = {}
                incomplete = unavailable = False
                for clause in ctx.factual['clauses']:
                    meter.check()
                    if clause['id'] not in hydrated:
                        incomplete = True
                        continue
                    if _typed(clause, kind, value):
                        if hydrated[clause['id']] is None:
                            unavailable = True
                            continue
                        support = clause['supports'][0]
                        # Conservative occurrence identity: equal paths in separate records do not unify objects.
                        domain = encoded([support['evidence_id'], support['context'].get('source_context'), value])
                        domains.setdefault(domain, []).append(clause['id'])
                        candidates.append(clause['id'])
                    elif clause['type'] == 'observation' and not s2._complete(clause):
                        incomplete = True
                status = ('incomplete_candidates' if incomplete else 'support_unavailable' if unavailable else
                          'ambiguous' if len(domains)>1 else 'resolved_within_declared_candidates' if len(domains)==1 else
                          'not_a_validated_technical_referent')
        elif kind == 'execution_outcome' and args.get('value'):
            # Existing rules do not establish generic script roles. A verb or role phrase is not an identifier.
            value = args['value']
            status = ('unsupported_role' if isinstance(value,str) and s2.PATH.match(value)
                      else 'not_a_validated_technical_referent')
        body = dict(contract=BINDING, rule='exact-typed-occurrence-v1', objective_id=objective['id'],
                    proposed_type=kind, proposed_arguments=deepcopy(args), status=status,
                    candidates=sorted(candidates), intent='provisional', original_proposal_unchanged=True,
                    domain='Accepted complete S1 fields in this recorded view; not the entire case',
                    meaning='Exact recorded typed-field match only; not execution, causality or complete analyst intent')
        result.append(dict(body, id=digest(body)))
    return result


def _bundle(unit, clauses, hydrated, conflicts):
    ids = set(unit['endpoints'] if 'endpoints' in unit else [unit['id']])
    edges = {edge['id']:edge for cid in ids for edge in conflicts.get(cid, [])}
    for edge in edges.values():
        ids.update(edge['endpoints'])
    if 'endpoints' in unit:
        edges[unit['id']] = unit
    if any(cid not in clauses for cid in ids):
        raise ValueError('Unknown relationship endpoint')
    if any(cid not in hydrated or hydrated[cid] is None for cid in ids):
        return None
    result = dict(clauses=sorted(ids), leaves=[], interpretations=[], qualifications=[], relationships=[])
    for cid in sorted(ids):
        current = hydrated[cid]
        result['leaves'].extend(current['leaves'])
        result['interpretations'].extend(current['interpretations'])
        result['qualifications'].extend(current['qualifications'])
    for edge in sorted(edges.values(),key=lambda e:e['id']):
        result['relationships'].append({k:deepcopy(edge[k]) for k in ('id','contract','rule','predicate','endpoints','semantics','assumptions')})
        result['qualifications'].extend(edge['qualifications'] + edge['assumptions'])
    result['qualifications'] = sorted(set(result['qualifications']))
    return result


def _assemble(ctx, selected, objective, selection, encoder=None):
    """Lossless source/qualification dictionaries, defined completely in this packet."""
    leaves, derived, sources, lineages = {}, {}, {}, {}
    for _, bundle in selected:
        for original in bundle['leaves']:
            leaf = deepcopy(original)
            source = leaf.pop('source')
            lineage = leaf.pop('lineage')
            lineages[digest(lineage)] = lineage
            leaf['lineage_ref'] = digest(lineage)
            sources[digest(source)] = source
            leaf['source_ref'] = digest(source)
            leaves[digest(leaf)] = leaf
        for item in bundle['interpretations']:
            derived[digest(item)] = item
    source_alias = {key:'P'+str(i+1) for i,key in enumerate(sorted(sources))}
    lineage_alias = {key:'D'+str(i+1) for i,key in enumerate(sorted(lineages))}
    for leaf in leaves.values():
        leaf['source_ref'] = source_alias[leaf['source_ref']]
        leaf['lineage_ref'] = lineage_alias[leaf['lineage_ref']]
    body = dict(contract=CONTRACT, rule=RULE, mode='local_preview_not_disclosed',
        question=ctx.manifest['question'], question_sha256=digest(ctx.manifest['question']),
        objective=deepcopy(objective), view=deepcopy(ctx.manifest.get('evidence_state')),
        authorization={'id':ctx.manifest['authorization']['id'], 'contract':ctx.manifest['authorization']['contract'],
                       'scope':'recorded grant only; no permission for new dispatch'},
        sources={source_alias[k]:sources[k] for k in sorted(sources)},
        lineages={lineage_alias[k]:lineages[k] for k in sorted(lineages)},
        supports=[leaves[k] for k in sorted(leaves)], interpretations=[derived[k] for k in sorted(derived)],
        clauses=sorted({cid for _,b in selected for cid in b['clauses']}),
        relationships=list({r['id']:r for _,b in selected for r in b['relationships']}.values()),
        qualifications=sorted({q for _,b in selected for q in b['qualifications']}),
        selection_sha256=digest(selection), coverage={k:selection[k] for k in ('known','examined','unassessed','omitted_counts')})
    if encoder is not None:
        return encoder(ctx, body)
    messages = [{'role':'system','content':INSTRUCTION}, {'role':'user','content':encoded(body)}]
    return dict(content=body, messages=messages, content_bytes=sum(len(m['content'].encode('utf-8')) for m in messages),
                digest=digest(messages), represented_supports=[{'evidence_id':v['evidence_id'],'pointer':v['field']['pointer'],
                    'value_sha256':digest(v['field']['value'])} for v in body['supports']], actually_disclosed=False)


def _plan(ctx, *, limits, _clock, encoder=None):
    """Provider-independent local service; caller supplies trusted reducer state."""
    meter = Meter(limits, _clock)
    meter.check()
    _validate_context(ctx)
    meter.check()
    clauses = {c['id']:c for c in ctx.factual['clauses']}
    units = {**clauses, **{e['id']:e for e in ctx.related['relationships']}}
    conflicts = {}
    for edge in ctx.related['relationships']:
        if edge['predicate']=='incompatible_recorded_field':
            for cid in edge['endpoints']:
                conflicts.setdefault(cid, []).append(edge)
    hydrated, bindings, packets, selections = {}, [], [], []
    exhausted = None
    try:
        for cid in sorted(clauses):
            hydrated[cid] = _rehydrate(clauses[cid], ctx, meter)
        bindings = _bindings(ctx, hydrated, meter)
    except PlanningLimit as exc:
        exhausted = str(exc)
    if encoder is not None:
        materializer = encoder
        encoder = lambda context, body: materializer(context, body, bindings)
    objectives = (ctx.mapping or {}).get('objectives', [])
    seen_units, represented_ids = set(), set()
    for packet_index in range(limits.packets):
        if exhausted:
            break
        objective = objectives[packet_index % len(objectives)] if objectives else None
        compact_objective = ({'id':objective['id'],'type':objective['proposal']['proposition_type'],
            'polarity':objective['proposal']['polarity'],'question_span':objective['proposal']['question_span'],
            'arguments':objective['arguments'],'unresolved':objective['proposal']['unresolved'],'intent':'provisional'} if objective else None)
        direct = set(next((b['candidates'] for b in bindings if objective and b['objective_id']==objective['id']), []))
        complementary = {cid for b in bindings for cid in b['candidates'] if cid not in seen_units}
        terms = set(re.findall(r'[a-z0-9_]{4,}', (objective['text'] if objective else ctx.manifest['question']).casefold()))
        def rank(unit):
            endpoints = unit.get('endpoints',[unit['id']])
            values = [clauses[c]['arguments'] for c in endpoints]
            ids = {clauses[c]['supports'][0]['evidence_id'] for c in endpoints}
            score = len(terms & set(re.findall(r'[a-z0-9_]{4,}', encoded(values).casefold())))
            return (0 if direct & set(endpoints) else 1 if complementary & set(endpoints) else 2,
                    bool(ids <= represented_ids), -score,
                    sorted(ids), unit['id'])
        decisions = {uid:'already_represented' if uid in seen_units else 'unassessed' for uid in units}
        selected = []
        examined = 0
        def selection():
            counts = {}
            for reason in decisions.values():
                if reason!='selected':counts[reason]=counts.get(reason,0)+1
            return dict(contract=SELECTION,rule=RULE,known=len(units),examined=examined,
                unassessed=sum(v=='unassessed' for v in decisions.values()),
                decisions=dict(sorted(decisions.items())),omitted_counts=counts,
                relevance='Heuristic priority is not a relevance determination', actually_disclosed=0)
        try:
            for unit in sorted(units.values(),key=rank):
                meter.check()
                uid = unit['id']
                if uid in seen_units:
                    continue
                if examined >= limits.candidates:
                    break
                examined += 1
                bundle = _bundle(unit,clauses,hydrated,conflicts)
                if bundle is None:
                    decisions[uid]='support_unavailable'
                    continue
                decisions[uid]='selected'
                candidate = _assemble(ctx,selected+[(uid,bundle)],compact_objective,selection(),encoder)
                body = candidate['content']
                if len(body['supports'])>limits.observations or len(body['interpretations'])>limits.interpretations:
                    decisions[uid]='support_count_budget'
                elif candidate['content_bytes']>limits.content_bytes:
                    decisions[uid]='byte_budget'
                else:
                    selected.append((uid,bundle))
            meter.check()
        except PlanningLimit as exc:
            exhausted = str(exc)
            for uid, _ in selected:
                decisions[uid] = 'planning_time'
            selected = []
        # Final omission metadata is measured too; remove a whole unit if needed.
        while selected:
            meter.check()
            final = _assemble(ctx,selected,compact_objective,selection(),encoder)
            meter.check()
            if final['content_bytes']<=limits.content_bytes:
                packets.append(final)
                seen_units.update(uid for uid,_ in selected)
                represented_ids.update(s['evidence_id'] for s in final['content']['supports'])
                break
            uid,_ = selected.pop()
            decisions[uid]='final_metadata_byte_budget'
        selections.append(selection())
        if not selected:
            break
    result = dict(contract='synthesis-preview-v1',status='ready' if packets else 'no_supported_packet',
        packets=packets,bindings=bindings,selections=selections, planning_stop=exhausted,
        counts={'known_clauses':len(clauses),'known_relationships':len(ctx.related['relationships']),
                'known_record_ids':sorted({c['supports'][0]['evidence_id'] for c in clauses.values()}),
                'available_record_ids':sorted({clauses[cid]['supports'][0]['evidence_id'] for cid,b in hydrated.items() if b is not None}),
                'represented_record_ids':sorted(represented_ids),
                'support_resolutions':meter.resolutions,'support_unavailable':sum(v is None for v in hydrated.values()),
                'unassessed_clauses':len(clauses)-len(hydrated),'represented_records':len(represented_ids),
                'historically_disclosed_records':len(ctx.state.exposed),'actually_disclosed_records':0,
                'provider_requests':0,'evidence_lookups':0},
        historical_decomposition=deepcopy(ctx.mapping),
        limitations=['Local preview only; historical current-request membership is unchanged.',
            'Recorded-view reconstruction, not current-case equality or byte-identical historical execution.',
            'Selection priority is heuristic; omitted evidence is not established irrelevant.',
            'No execution, causality, generic role inference or complete intent is established.'])
    s1._bounded(result,s1.MAX_RESULT_BYTES)
    return result


def plan(ctx, *, limits=Limits(), _clock=time.monotonic, _encoder=None):
    """Build a local preview. No deadline failure returns a dispatchable packet.

    The deadline covers bounded in-memory planning, not transcript disk I/O.
    Context is an internal verified reducer result, not a serialized import API.
    """
    try:
        return _plan(ctx, limits=limits, _clock=_clock, encoder=_encoder)
    except PlanningLimit as exc:
        return dict(contract='synthesis-preview-v1', status='no_supported_packet',
                    packets=[], bindings=[], selections=[], planning_stop=str(exc),
                    counts={'actually_disclosed_records':0, 'provider_requests':0, 'evidence_lookups':0},
                    historical_decomposition=deepcopy(ctx.mapping),
                    limitations=['Planning stopped before a validated preview was completed.'])


def validate_preview(ctx, preview, *, limits=Limits()):
    """Rebuild from trusted original state, never trust packet hashes or aliases alone.

    Does not grant dispatch permission or mutate current-request disclosure state.
    A future consumer still needs its own approved dispatch/grounding contract.
    """
    expected = plan(ctx, limits=limits)
    if expected['planning_stop'] or not same(expected, preview):
        raise ValueError('Preview does not match bounded original support reconstruction')
    return True


def reconstruct(root, identity, *, limits=Limits()):
    """Read only the existing transcript. No sidecar writes, case or provider access."""
    manifest, events = load(root,identity)
    reducer = s1._Reducer()
    retained = State(Budget())
    accepted = set()
    def consume(state,delta,exposure):
        nonlocal retained
        reducer.consume(state,delta,exposure)
        retained=state
        accepted.add((delta['id'],delta['disclosure_sha256'],delta['batch']))
    autonomous.reconstruct(root,identity,_on_validated=consume)
    mapping = None
    if manifest.get('engine')==decomposition.ENGINE:
        decision=decomposition.validate_journal(manifest,events)
        mapping=decision.get('mapping') if decision['status']=='accepted' else None
    factual=reducer.finish()
    ctx=Context(retained,factual,s2._build(factual),manifest,mapping,accepted)
    result=plan(ctx,limits=limits)
    if manifest.get('engine') == decomposition.ENGINE:
        assessment = decomposition.assess(manifest['question'], identity, ctx.related, decision)
        for event in events:
            if event['kind'] == 'terminal' and 'question_decomposition' in event['data']:
                if not same(assessment, event['data']['question_decomposition']):
                    raise ValueError('Invalid S4 terminal assessment')
        result['original_s3_assessment'] = assessment['original_assessment']
    after,_=load(root,identity)
    if not same(manifest,after):raise ValueError('Transcript changed during preview')
    result['source_manifest_sha256']=digest(manifest)
    return result


def render(result):
    lines=['Local synthesis packet preview — not sent to AI', 'Status: '+result['status'],
           'Counts: '+encoded(result['counts'])]
    if result['planning_stop']:lines.append('Planning limit: '+result['planning_stop'])
    for index,packet in enumerate(result['packets'],1):
        lines.append(f'Packet {index}: {packet["content_bytes"]} content bytes; digest {packet["digest"]}')
        for support in packet['represented_supports']:
            lines.append('  '+json.dumps(support['evidence_id'])+' '+json.dumps(support['pointer']))
    for binding in result['bindings']:
        lines.append('Binding '+binding['objective_id']+': '+binding['status'])
        lines.append('  '+binding['domain'])
    for selection in result['selections']:
        lines.append('Omissions: '+encoded(selection['omitted_counts']))
    lines.extend(result['limitations'])
    return '\n'.join(lines)

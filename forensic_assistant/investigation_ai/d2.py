"""Provider-free D2-0: validated recorded support, issue packets, offline decisions.

Public entry point is open_history(), never a deserialized evidence/packet importer.
No backend, SQLite opener, grant issuer, journal writer or investigation executor.
"""
from copy import deepcopy
from pathlib import Path
import argparse
import json
import re
import stat
import time

from . import packets as b1, synthesis as s1, relationships as s2, autonomous
from . import decomposition, question_assessment as s3, d2_contracts as c
from .state import State, Budget, encoded
from .transcript import load, digest


def _anchor(manifest, events):
    return dict(run_id=manifest['investigation_id'], manifest_sha256=digest(manifest),
                event_head=events[-1]['hash'] if events else None)


def _read(root, identity):
    # load validates the identifier and chain; check redirection before reading.
    if not re.fullmatch('[a-f0-9]{32}', identity):
        raise ValueError('D2_INVALID_RUN')
    for path in (Path(root), Path(root)/identity,
                 Path(root)/identity/'manifest.json', Path(root)/identity/'events.jsonl'):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('D2_REDIRECTED_SOURCE')
    return load(root, identity)


def open_history(root, identity):
    """Rebuild accepted originals, including the existing B2/C1/D1b validators."""
    root = Path(root)
    manifest, events = _read(root, identity)
    anchor = _anchor(manifest, events)
    facts = s1._Reducer()
    retained = State(Budget())
    accepted = set()
    def consume(state, delta, exposure):
        nonlocal retained
        facts.consume(state, delta, exposure)
        retained = state
        accepted.add((delta['id'], delta['disclosure_sha256'], delta['batch']))
    autonomous.reconstruct(root, identity, _on_validated=consume)
    decision = decomposition.validate_journal(manifest, events)
    factual = facts.finish()
    ctx = b1.Context(retained, factual, s2._build(factual), manifest,
                     decision.get('mapping') if decision['status'] == 'accepted' else None, accepted)
    original = s3._assess(manifest['question'], identity, ctx.related)
    after, later = _read(root, identity)
    if anchor != _anchor(after, later):
        raise ValueError('D2_SOURCE_CHANGED')
    return _History(ctx, anchor, original, decision['status'], root)


def _encode(ctx, anchor, original, issue, selected, selection):
    assembled = b1._assemble(ctx, selected, None, selection)['content']
    # Lossless packet-local dictionaries: no field, qualifier or lineage shortened.
    eids = sorted({s['evidence_id'] for s in assembled['supports']})
    records = {eid: 'E'+str(i+1) for i, eid in enumerate(eids)}
    clauses = {cid: 'C'+str(i+1) for i, cid in enumerate(assembled['clauses'])}
    supports = []
    for i, leaf in enumerate(assembled['supports'], 1):
        leaf = deepcopy(leaf)
        if leaf.pop('contract') != b1.SUPPORT:
            raise ValueError('D2_UNSUPPORTED_LEAF_CONTRACT')
        leaf['record_ref'] = records[leaf.pop('evidence_id')]
        leaf['clause_ref'] = clauses[leaf.pop('clause_id')]
        leaf['alias'] = 'O'+str(i)
        supports.append(leaf)
    interpretations = deepcopy(assembled['interpretations'])
    for i, entry in enumerate(interpretations, 1):
        entry['record_ref'] = records[entry.pop('evidence_id')]
        entry['alias'] = 'I'+str(i)
    relationships = deepcopy(assembled['relationships'])
    for i, entry in enumerate(relationships, 1):
        entry['alias'] = 'R'+str(i)
    body = dict(contract=c.PACKET, source=deepcopy(anchor), view=assembled['view'],
        question=ctx.manifest['question'], original_s3_status=original['status'],
        issue=deepcopy(issue), scope='Recorded authorized fields only; preview is not a dispatch grant',
        records={ref: eid for eid, ref in records.items()}, clauses={ref: cid for cid, ref in clauses.items()},
        sources=assembled['sources'], lineages=assembled['lineages'], support_contract=b1.SUPPORT, supports=supports,
        interpretations=interpretations, relationships=relationships,
        qualifications=assembled['qualifications'], coverage=assembled['coverage'])
    packet_digest = digest(body)
    request_id = digest([c.REQUEST, anchor, issue['id'], packet_digest])
    messages = [dict(role='system', content=c.SYSTEM), dict(role='user', content=encoded(
        dict(contract=c.REQUEST, request_id=request_id, packet_digest=packet_digest, packet=body)))]
    content_bytes = sum(len(m['content'].encode('utf-8')) for m in messages)
    support_bytes = len(encoded({k: body[k] for k in
        ('records', 'clauses', 'sources', 'lineages', 'support_contract', 'supports', 'interpretations', 'relationships', 'qualifications')}).encode('utf-8'))
    return dict(contract=c.REQUEST, request_id=request_id, packet_digest=packet_digest,
        content=body, messages=messages, message_digest=digest(messages), content_bytes=content_bytes,
        support_bytes=support_bytes, overhead_bytes=content_bytes-support_bytes,
        selected_units=[uid for uid, _ in selected], selection=deepcopy(selection),
        represented_fields=[dict(evidence_id=body['records'][leaf['record_ref']],
            pointer=leaf['field']['pointer'], value_sha256=digest(leaf['field']['value'])) for leaf in supports],
        actually_disclosed=False, dispatch_authorized=False)


def _closure(unit, clauses, hydrated, conflicts, meter):
    """B1 closure plus a fixed point over recognized conflicting endpoints."""
    initial = b1._bundle(unit, clauses, hydrated, conflicts)
    if initial is None:
        return None
    bundles = [initial]
    seen = set(initial['clauses'])
    pending = sorted(seen)
    while pending:
        meter.check()
        cid = pending.pop(0)
        for edge in conflicts.get(cid, []):
            if set(edge['endpoints']) <= seen:
                continue
            extra = b1._bundle(edge, clauses, hydrated, conflicts)
            if extra is None:
                return None
            pending.extend(sorted(set(extra['clauses'])-seen))
            seen.update(extra['clauses'])
            bundles.append(extra)
    return dict(clauses=sorted(seen), **{key: [v for b in bundles for v in b[key]] for key in
        ('leaves', 'interpretations', 'qualifications', 'relationships')})


class _History:
    """Internal trusted reconstruction handle, not a serialized import interface."""
    def __init__(self, ctx, anchor, original, mapping_status, root=None):
        self._ctx, self._anchor, self._original = ctx, deepcopy(anchor), deepcopy(original)
        self._mapping_status, self._root = mapping_status, root
        self._seal = self._digest()

    def _digest(self):
        ctx = self._ctx
        return digest([ctx.manifest, ctx.factual, ctx.related, ctx.mapping,
                       ctx.state.records, ctx.state.exposed, sorted(ctx.accepted),
                       self._anchor, self._original, self._mapping_status])

    def _check(self):
        if self._digest() != self._seal:
            raise ValueError('D2_TRUSTED_STATE_CHANGED')
        if self._root is not None:
            m, es = _read(self._root, self._anchor['run_id'])
            if _anchor(m, es) != self._anchor:
                raise ValueError('D2_SOURCE_CHANGED')

    def preview(self, *, exploratory=False, issue_ids=(), _clock=time.monotonic):
        self._check()
        if type(exploratory) is not bool or len(issue_ids)>2 or len(set(issue_ids))!=len(issue_ids):
            raise ValueError('D2_PREVIEW_OPTIONS')
        ctx = self._ctx
        result = dict(contract=c.PREVIEW, source=deepcopy(self._anchor), question=ctx.manifest['question'],
            original_s3_assessment=deepcopy(self._original), decomposition_status=self._mapping_status,
            issues=[], packets=[], issue_results=[], planning_stop=None,
            provider_requests=0, evidence_lookups=0, actually_disclosed=False, dispatch_authorized=False,
            classes=dict(deterministic_findings='existing S1/S2/S3', ai_proposals='none generated', analyst_decisions='not implemented'))
        meter = b1.Meter(b1.Limits(), _clock)
        try:
            meter.check()
            b1._validate_context(ctx)
            clauses = {c['id']: c for c in ctx.factual['clauses']}
            hydrated = {cid: b1._rehydrate(value, ctx, meter) for cid, value in sorted(clauses.items())}
            bindings = b1._bindings(ctx, hydrated, meter)
            units = {**clauses, **{r['id']: r for r in ctx.related['relationships']}}
            conflicts = {}
            for edge in ctx.related['relationships']:
                if edge['predicate'] == 'incompatible_recorded_field':
                    for cid in edge['endpoints']:
                        conflicts.setdefault(cid, []).append(edge)
            issues = []
            for mapping in (ctx.mapping or {}).get('objectives', []):
                binding = next(b for b in bindings if b['objective_id']==mapping['id'])
                if mapping['eligible'] and binding['status']=='resolved_within_declared_candidates':
                    issues.append(dict(kind='typed_objective', mode='typed', objective_id=mapping['id'],
                        objective=dict(type=mapping['proposal']['proposition_type'],arguments=mapping['arguments'],
                            polarity=mapping['proposal']['polarity'],question_span=mapping['proposal']['question_span']),
                        binding=binding['status'], seeds=binding['candidates'], purpose='explain_recorded_facts'))
            if exploratory:
                for uid, unit in sorted(units.items()):
                    kind = ('relationship' if 'endpoints' in unit else 'interpretation'
                            if unit['type']=='deterministic_interpretation' else 'recorded_fields')
                    issues.append(dict(kind=kind, mode='exploratory', objective_id=None,
                        binding='unavailable_for_this_issue', seeds=[uid], purpose='compare_alternatives'
                        if kind=='relationship' else 'explain_recorded_facts'))
            for issue in issues:
                issue['id'] = digest([c.PREVIEW, self._anchor, issue])
            terms = set(re.findall(r'[a-z0-9_]{4,}', ctx.manifest['question'].casefold()))
            def score(unit):
                return len(terms & set(re.findall(r'[a-z0-9_]{4,}', encoded(unit).casefold())))
            rank = dict(typed_objective=0, interpretation=1, relationship=2, recorded_fields=3)
            issues.sort(key=lambda i:(rank[i['kind']], -sum(score(units[k]) for k in i['seeds']), i['id']))
            result['issues'] = deepcopy(issues)
            result['bindings'] = deepcopy(bindings)
            if issue_ids and not set(issue_ids) <= {i['id'] for i in issues}:
                raise ValueError('D2_UNKNOWN_OR_UNAUTHORIZED_ISSUE')
            selected_issues = [next(i for i in issues if i['id']==uid) for uid in issue_ids] if issue_ids else issues[:2]
            if not selected_issues:
                result['status'] = 'exploratory_permission_required' if not exploratory else 'no_original_support'
                result['support_resolutions']=meter.resolutions
                self._check()
                return result
            represented = set()
            for issue in selected_issues:
                meter.check()
                selected = []
                decisions = {uid:'unassessed' for uid in sorted(units)}
                examined = 0
                def selection():
                    omitted = {}
                    for status in decisions.values():
                        if status!='selected':omitted[status]=omitted.get(status, 0)+1
                    return dict(known=len(units), examined=examined,
                        unassessed=sum(v=='unassessed' for v in decisions.values()), omitted_counts=omitted,
                        decisions=deepcopy(decisions), relevance='Omitted is not irrelevant')
                mandatory = []
                for uid in issue['seeds']:
                    meter.check();examined += 1
                    bundle = _closure(units[uid], clauses, hydrated, conflicts, meter)
                    if bundle is None:
                        decisions[uid]='support_unavailable'
                        break
                    mandatory.append((uid,bundle));decisions[uid]='selected'
                complete = len(mandatory)==len(issue['seeds'])
                packet = _encode(ctx,self._anchor,self._original,issue,mandatory,selection()) if complete else None
                if packet is None or packet['content_bytes']>5600 or len(packet['content']['supports'])>12 or len(packet['content']['interpretations'])>4:
                    reason = 'support_unavailable' if packet is None else 'ATOMIC_BUNDLE_TOO_LARGE'
                    for uid in issue['seeds']:decisions[uid]=reason
                    result['issue_results'].append(dict(issue_id=issue['id'],status=reason,
                        required_bytes=packet['content_bytes'] if packet else None,limit=5600,selection=selection()))
                    continue
                selected = mandatory
                seed_clauses = {cid for _,b in mandatory for cid in b['clauses']}
                seed_eids = {clauses[cid]['supports'][0]['evidence_id'] for cid in seed_clauses}
                seed_fields = {(leaf['evidence_id'], leaf['field']['pointer'])
                               for _, bundle in mandatory for leaf in bundle['leaves']}
                def candidate_rank(uid):
                    ids = units[uid].get('endpoints',[uid])
                    fields = {(clauses[k]['supports'][0]['evidence_id'],clauses[k]['supports'][0].get('field',{}).get('pointer')) for k in ids}
                    return (fields <= seed_fields | represented,
                            not any(eid in seed_eids for eid,_ in fields), -score(units[uid]), uid)
                for uid in sorted(set(units)-set(issue['seeds']),key=candidate_rank):
                    meter.check()
                    if examined>=192:break
                    examined += 1
                    bundle = _closure(units[uid],clauses,hydrated,conflicts,meter)
                    if bundle is None:
                        decisions[uid]='support_unavailable';continue
                    decisions[uid]='selected'
                    candidate = _encode(ctx,self._anchor,self._original,issue,selected+[(uid,bundle)],selection())
                    body = candidate['content']
                    if len(body['supports'])>12 or len(body['interpretations'])>4:decisions[uid]='support_count_budget'
                    elif candidate['content_bytes']>5600:decisions[uid]='byte_budget'
                    else:selected.append((uid,bundle))
                # Final omission accounting is part of the measured wire envelope.
                while selected:
                    meter.check()
                    packet = _encode(ctx,self._anchor,self._original,issue,selected,selection())
                    if packet['content_bytes']<=5600:break
                    if len(selected)==len(mandatory):
                        selected=[];break
                    uid,_=selected.pop();decisions[uid]='final_metadata_byte_budget'
                if not selected:
                    result['issue_results'].append(dict(issue_id=issue['id'],status='ATOMIC_BUNDLE_TOO_LARGE',
                        required_bytes=packet['content_bytes'],limit=5600,selection=selection()))
                    continue
                result['packets'].append(packet)
                represented.update((f['evidence_id'],f['pointer']) for f in packet['represented_fields'])
                result['issue_results'].append(dict(issue_id=issue['id'],status='ready_offline',
                    required_bytes=packet['content_bytes'],limit=5600,selection=selection()))
            meter.check()
            result['status']='ready_offline' if result['packets'] else 'no_supported_packet'
        except b1.PlanningLimit as exc:
            result.update(status='planning_stopped',packets=[],planning_stop=str(exc))
        result['support_resolutions']=meter.resolutions
        self._check()
        return result

    def validate(self, packet, raw, *, exploratory=False, issue_ids=()):
        """Rebuild from trusted originals before checking an untrusted packet/response."""
        preview = self.preview(exploratory=exploratory,issue_ids=issue_ids)
        expected = next((p for p in preview['packets'] if p['request_id']==packet.get('request_id')),None)
        if expected is None or digest(expected)!=digest(packet):
            raise ValueError('D2_PACKET_SOURCE_BINDING')
        context = self.response_context(preview)
        result = validate_response(expected, raw, context)
        self._check()
        return result

    def response_context(self, preview):
        # Internal authenticated input, never supplied by a worker or JSON import.
        return dict(source=deepcopy(self._anchor), original=deepcopy(self._original),
                    issues=[i['id'] for i in preview['issues']],
                    registered={r['id']: r for r in s2._build(self._ctx.factual)['relationships']})


def validate_response(expected, raw, context, checkpoint=lambda: None):
    """Existing strict validator over parent-owned frozen inputs; no IO or replay."""
    checkpoint()
    value = c.parse(raw)
    if value['request_id']!=expected['request_id'] or value['packet_digest']!=expected['packet_digest']:
        raise ValueError('D2_RESPONSE_REQUEST_BINDING')
    body = expected['content']
    refs = {s['alias']:s for s in body['supports']}
    interpretations = {s['alias']:s for s in body['interpretations']}
    edges = {s['alias']:s for s in body['relationships']}
    registered = context['registered']
    if not set(value['assessment']['support_refs'])<=refs.keys():raise ValueError('D2_UNKNOWN_SUPPORT')
    accepted = []
    for item in value['items']:
        checkpoint()
        if (not set(item['support_refs']+item['contradictory_refs'])<=refs.keys()
            or not set(item['interpretation_refs'])<=interpretations.keys()
            or not set(item['relationship_refs'])<=edges.keys()
            or not set(item['next_issue_refs'])<= set(context['issues'])):
            raise ValueError('D2_UNKNOWN_SUPPORT')
        cited = [refs[a] for a in item['support_refs']+item['contradictory_refs']]
        clause_ids = {body['clauses'][leaf['clause_ref']] for leaf in cited}
        for edge in body['relationships']:
            if edge['predicate']=='incompatible_recorded_field' and set(edge['endpoints']) & clause_ids:
                if not set(edge['endpoints']) <= clause_ids:
                    raise ValueError('D2_OMITTED_CONTRADICTORY_SUPPORT')
        for alias in item['interpretation_refs']:
            interp=interpretations[alias]
            if not set(interp['premise_pointers']) <= {s['field']['pointer'] for s in cited if s['record_ref']==interp['record_ref']}:
                raise ValueError('D2_INCOMPLETE_INTERPRETATION')
        validated_edges=[]
        for alias in item['relationship_refs']:
            edge=edges[alias];original=registered.get(edge['id'])
            if original is None or not set(edge['endpoints'])<=clause_ids:
                raise ValueError('D2_INCOMPLETE_RELATIONSHIP')
            if any(digest(edge[k])!=digest(original[k]) for k in ('contract','rule','predicate','endpoints','semantics','assumptions')):
                raise ValueError('D2_INVALID_RELATIONSHIP')
            validated_edges.append(original)
        if item['relationship'] and not any(
            r['predicate']==item['relationship'][0]['predicate'] and r['endpoints']==item['relationship'][0]['endpoints'] for r in validated_edges):
            raise ValueError('D2_UNSUPPORTED_RELATIONSHIP')
        accepted.append(dict(id=digest([c.RESPONSE,expected['request_id'],item]),
            request_id=expected['request_id'],packet_digest=expected['packet_digest'],
            classification='mechanically_accepted_unverified',item=deepcopy(item),
            dependencies=[dict(evidence_id=body['records'][s['record_ref']],
                clause_id=body['clauses'][s['clause_ref']],field=deepcopy(s['field']),
                source=deepcopy(body['sources'][s['source_ref']]),
                lineage=deepcopy(body['lineages'][s['lineage_ref']]),
                **({'timestamp':deepcopy(s['timestamp'])} if 'timestamp' in s else {})) for s in cited],
            interpretation_support=deepcopy([interpretations[a] for a in item['interpretation_refs']]),
            validated_relationship_ids=[r['id'] for r in validated_edges],
            mandatory_qualifications=deepcopy(body['qualifications'])))
    checkpoint()
    return dict(contract='d2-offline-validation-v1',status='accepted_offline',proposals=accepted,
        source=deepcopy(context['source']),request_id=expected['request_id'],packet_digest=expected['packet_digest'],
        assessment=deepcopy(value['assessment']),assessment_classification='unverified_packet_limited',
        original_s3_assessment=deepcopy(context['original']),actually_disclosed=False,dispatch_authorized=False)



def render(result):
    from .explanation import _safe
    lines=['D2 provider-free issue preview — no dispatch authorization',_safe(result['question']),
        'Original S3 status: '+result['original_s3_assessment']['status'], 'Status: '+result['status']]
    for row in result['issue_results']:
        lines.append(row['issue_id']+': '+row['status']+'; bytes '+str(row['required_bytes'])+' / 5600')
    for packet in result['packets']:
        lines.append('Issue '+packet['content']['issue']['id'])
        for leaf in packet['content']['supports']:
            lines.append('  '+leaf['alias']+': '+_safe(packet['content']['records'][leaf['record_ref']])+' '+_safe(leaf['field']['pointer']))
        lines.extend('  Qualification: '+_safe(q) for q in packet['content']['qualifications'])
        lines.append('  Omission counts: '+encoded(packet['content']['coverage']['omitted_counts']))
    lines.append('No evidence lookups or provider requests. Omitted material is not established irrelevant.')
    return '\n'.join(lines)


def main():
    parser=argparse.ArgumentParser(description='Provider-free D2 historical issue preview')
    parser.add_argument('root');parser.add_argument('run_id')
    parser.add_argument('--exploratory',action='store_true',help='Permit exploratory local previews only; never cloud disclosure')
    parser.add_argument('--issue',action='append',default=[],help='Select a listed issue ID (maximum two)')
    parser.add_argument('--json',action='store_true')
    args=parser.parse_args()
    result=open_history(args.root,args.run_id).preview(exploratory=args.exploratory,issue_ids=args.issue)
    print(encoded(result) if args.json else render(result))


if __name__=='__main__':
    main()

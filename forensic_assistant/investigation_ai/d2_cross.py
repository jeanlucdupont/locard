"""Bounded cross-artifact preparation over authenticated history, never live queries.

Reuses B1 restoration/atomic closure and the D2 supervisor. The new question
does not amend the historical manifest, grant, S3 assessment or exposure ledger.
"""
from copy import deepcopy
import json
import re
import time

from . import d2, d2_quality as quality, d2_wire as wire, d2_schema
from . import packets as b1, question_assessment as s3
from .transcript import digest

POLICY = 'd2-cross-artifact-request-v1'
VERSION = 'd2x1'
LIMIT = 16384
GUIDE = quality.GUIDE + (' Answer the analyst question across the selected artifact families. '
    'Registered relationships are qualified application context, not model findings; '
    'cite their original O endpoints, never R IDs. Separate present discriminators '
    'from proposed examinations: name the family, question, contrasting outcomes '
    'and missing coverage. Shared strings and temporal proximity do not establish '
    'common identity or causality. Selection roles and sufficiency are structural aids, not forensic findings.')
SCHEMA = quality.SCHEMA
expand_response = quality.expand_response


def messages(packet):
    result = quality.messages(packet)
    result[0]['content'] = GUIDE
    view = json.loads(result[1]['content'])
    view['wire_version'] = VERSION
    result[1]['content'] = wire.J(view)
    return result


def expand_view(value, packet):
    value = deepcopy(value)
    if value.get('wire_version') != VERSION:
        raise ValueError('D2_CROSS_VERSION')
    value['wire_version'] = quality.VERSION
    return quality.expand_view(value, packet)


def _question(value):
    if (type(value) is not str or not value.strip() or len(value.encode('utf-8')) > 1600
            or any(ord(c) < 32 and c not in '\n\t' for c in value)):
        raise ValueError('D2_CROSS_QUESTION')
    return value


# Roles describe registered fields, never guessed entity types in arbitrary text.
IDENTIFYING = frozenset(('path', 'name', 'reference', 'url', 'hash', 'identifier'))
STOP = frozenset('the and what which how evidence recorded observations connects connect compare '
                 'comparison subsequent additional examination discriminate hypotheses remains remain '
                 'would could should this that with from between activity information'.split())


def field_role(clause):
    from . import relationships as s2
    if clause['type'] != 'observation': return 'interpretation'
    field = clause['supports'][0]['field']
    pointer = field['pointer']
    if s2._time(clause) is not None: return 'time'
    if s2._identifier(clause) is not None: return 'identifier'
    if pointer in ('/target_path', '/current_path') or field['label'] == 'Recorded filesystem name/path':
        return 'path'
    if pointer in ('/filename', '/process_name', '/executable', '/value_name'): return 'name'
    if pointer in ('/sha256', '/sha1', '/md5'): return 'hash'
    if re.fullmatch(r'/original_event_data/\d+/value', pointer) and field.get('semantic',{}).get('name') in ('SHA256','SHA1','MD5'):
        return 'hash'
    if pointer in ('/url', '/referrer') or re.fullmatch(r'/url_chain/\d+/url', pointer): return 'url'
    if re.fullmatch(r'/objects/\d+', pointer) or pointer in ('/key', '/key_path', '/value_data'): return 'reference'
    if pointer in ('/process_id', '/parent_process_id'): return 'identifier'
    return 'context'


def question_requirements(question):
    words = set(re.findall(r'[a-z]+', question.casefold()))
    comparison = bool(re.search(r'\b(connect\w*|compar\w*|correspond\w*|same|match\w*|versus|between|link\w*)\b', question.casefold()))
    roles = []
    kind = None
    if comparison:
        if words & {'hash', 'hashes', 'sha256', 'sha1', 'md5'}: kind, roles = 'recorded_hash_comparison', ['hash']
        elif words & {'process', 'executable', 'registry', 'prefetch', 'run'}:
            kind, roles = 'recorded_identity_context_comparison', ['name', 'reference', 'identifier', 'path']
        elif words & {'path', 'paths', 'pathname', 'pathnames', 'filesystem', 'download', 'file', 'files', 'filename'}:
            kind, roles = 'recorded_pathname_comparison', ['path']
        elif words & {'url', 'urls', 'domain', 'domains'}: kind, roles = 'recorded_url_comparison', ['url']
    return dict(contract='cross-context-sufficiency-v1', pattern=kind,
                identifying_roles=roles, requires_reference='registry' in words, temporal_context=bool(words & {'before', 'after', 'subsequent', 'later', 'chronology', 'sequence'}),
                comparison_requested=comparison,
                meaning='Recognized input requirements only; no object identity, causality or complete question understanding is established.')


def _words(value):
    return set(re.findall(r'[\w.-]{3,}', str(value).casefold())) - STOP


class History(d2._History):
    """Internal handle constructed only from a validated D2 history."""
    def __init__(self, history, question, model):
        history._check()
        super().__init__(history._ctx, history._anchor, history._original,
                         history._mapping_status, history._root)
        self.question, self.model = _question(question), model
        self._question_seal = digest([self.question, self.model])

    def preview(self, *, exploratory=True, issue_ids=(), _clock=time.monotonic):
        self._check()
        if digest([self.question, self.model]) != self._question_seal or issue_ids or exploratory is not True:
            raise ValueError('D2_CROSS_OPTIONS')
        meter = b1.Meter(b1.Limits(), _clock)
        ctx = self._ctx
        b1._validate_context(ctx)
        clauses = {c['id']: c for c in ctx.factual['clauses']}
        hydrated = {k: b1._rehydrate(v, ctx, meter) for k, v in sorted(clauses.items())}
        units = {**clauses, **{r['id']: r for r in ctx.related['relationships']}}
        conflicts = {}
        for edge in ctx.related['relationships']:
            if edge['predicate'] == 'incompatible_recorded_field':
                for cid in edge['endpoints']:
                    conflicts.setdefault(cid, []).append(edge)
        requirements = question_requirements(self.question)
        roles = {k: field_role(v) for k, v in clauses.items()}
        from . import relationships as s2
        complete = {k: hydrated[k] is not None and s2._complete(c) for k,c in clauses.items()}
        terms = _words(self.question)
        def score(uid):
            ids = units[uid].get('endpoints', [uid])
            fields = [clauses[k]['arguments'] for k in ids]
            return len(terms & _words(wire.J(fields).replace('_', ' ')))
        def rank(uid):
            unit = units[uid]
            kind = ('contradiction' if uid in conflicts or unit.get('predicate') == 'incompatible_recorded_field'
                    else 'relationship' if 'endpoints' in unit else roles[uid])
            if kind=='interpretation' and score(uid): return (0,-score(uid),uid)
            return ({'contradiction':0,'path':1,'hash':1,'identifier':1,'name':1,'reference':1,'url':2,
                     'interpretation':3,'context':4,'time':5,'relationship':6}[kind], -score(uid), uid)
        assessment = s3._assess(self.question, self._anchor['run_id'], ctx.related)
        issue = dict(id=digest([POLICY, self._anchor, self.question]), kind='cross_artifact',
                     mode='exploratory', objective_id=None, binding='no_objective_binding',
                     seeds=[], purpose='compare_alternatives', request_policy=POLICY,
                     question_id=digest(self.question), question_assessment_status=assessment['status'])
        # Use a private projection for the new question, retaining the original grant.
        projected = deepcopy(ctx)
        projected.manifest['question'] = self.question
        available = {}
        for clause in clauses.values():
            support = clause['supports'][0]
            available.setdefault(support['source_type'], set()).add(support['evidence_id'])
        decisions = {k: 'unexamined' for k in sorted(units)}
        bundle_diagnostics = []
        primary = []
        relevance = {k: ('potentially_contradictory' if k in conflicts or units[k].get('predicate') == 'incompatible_recorded_field'
                         else 'direct_lexical_match' if score(k) else 'contextual_candidate') for k in units}
        selected, examined_ids = [], set()
        pairs = []
        evaluated_pairs = 0
        def comparison_pair(a,z):
            if clauses[a]['supports'][0]['evidence_id']==clauses[z]['supports'][0]['evidence_id']: return False
            if roles[a] not in requirements['identifying_roles'] or roles[z] not in requirements['identifying_roles']: return False
            if requirements['pattern']=='recorded_identity_context_comparison':
                pair={roles[a],roles[z]}
                if requirements['requires_reference']:
                    return 'reference' in pair and bool(pair & {'name','identifier','path'})
                return bool(pair & {'name','identifier'})
            return True
        def sufficiency():
            selected_ids = {cid for _,bundle in selected for cid in bundle['clauses']}
            eligible = [k for k in clauses if roles[k] in requirements['identifying_roles'] and complete[k]]
            present = [k for k in eligible if k in selected_ids]
            records = {clauses[k]['supports'][0]['evidence_id'] for k in present}
            present_pairs=[(a,z) for i,a in enumerate(present) for z in present[i+1:] if comparison_pair(a,z)]
            available_pairs=[(a,z) for i,a in enumerate(eligible) for z in eligible[i+1:] if comparison_pair(a,z)]
            available_records = {clauses[k]['supports'][0]['evidence_id'] for k in eligible}
            time_records = {clauses[k]['supports'][0]['evidence_id'] for k in selected_ids if roles[k]=='time' and complete[k]}
            available_time_records = {clauses[k]['supports'][0]['evidence_id'] for k in clauses if roles[k]=='time' and complete[k]}
            required = ['identifying_fields_from_two_distinct_records']
            if requirements['temporal_context']: required.append('recorded_time_context_for_both')
            present_roles = (['identifying_fields_from_two_distinct_records'] if present_pairs else [])
            if requirements['temporal_context'] and any(all(clauses[k]['supports'][0]['evidence_id'] in time_records for k in pair) for pair in present_pairs): present_roles.append('recorded_time_context_for_both')
            missing = [r for r in required if r not in present_roles]
            available_roles = (['identifying_fields_from_two_distinct_records'] if available_pairs else [])
            if any(all(clauses[k]['supports'][0]['evidence_id'] in available_time_records for k in pair) for pair in available_pairs): available_roles.append('recorded_time_context_for_both')
            return dict(contract=requirements['contract'], pattern=requirements['pattern'],
                        status='question_sufficiency_not_established' if requirements['pattern'] is None else
                        'comparison_inputs_present' if not missing else 'comparison_inputs_missing',
                        required_roles=required if requirements['pattern'] else [], present_roles=present_roles,
                        missing_roles=missing if requirements['pattern'] else [],
                        available_but_omitted_roles=[r for r in missing if r in available_roles],
                        unavailable_roles=[r for r in missing if r not in available_roles],
                        meaning=requirements['meaning'])
        def selection():
            counts = {}
            for status in decisions.values():
                if status != 'selected': counts[status] = counts.get(status, 0) + 1
            return dict(known=len(units), examined=len(examined_ids),
                        unassessed=sum(v == 'unexamined' for v in decisions.values()),
                        omitted_counts=counts, decisions=deepcopy(decisions),
                        relevance=deepcopy(relevance), field_roles=deepcopy(roles),
                        bundles=deepcopy(bundle_diagnostics), sufficiency=sufficiency(),
                        pair_candidates=len(pairs), pairs_evaluated=evaluated_pairs,
                        pairs_unexamined=max(0,len(pairs)-evaluated_pairs))
        def encode(bundles):
            represented = {}
            for _, bundle in bundles:
                for leaf in bundle['leaves']:
                    family = leaf['source']['source_type']
                    represented.setdefault(family, set()).add(leaf['evidence_id'])
            coverage = {family: dict(available_records=len(eids), represented_records=len(represented.get(family, set())))
                        for family, eids in sorted(available.items())}
            bound_issue = dict(issue, artifact_coverage=coverage,
                               context_sufficiency=sufficiency(),
                               coverage_scope='Validated history only, not the entire case')
            return d2._encode(projected, self._anchor, self._original, bound_issue, bundles, selection())
        def fits(packet):
            body = packet['content']
            if len(body['supports']) > 12 or len(body['interpretations']) > 4:
                return 'support_count_budget'
            if len(wire.body(messages(packet), self.model, d2_schema.from_packet(packet))) > LIMIT:
                return 'complete_request_byte_budget'
            return None
        def restore(keys):
            bundles = []
            for key in keys:
                meter.check()
                examined_ids.add(key)
                bundle = d2._closure(units[key], clauses, hydrated, conflicts, meter)
                if bundle is None: return None
                bundles.append((key,bundle))
            return bundles

        # Evaluate up to 24 alternative identity-pair groups before choosing one.
        # Cost is exact final SDK bytes, not field character count. No family quota.
        family_words = _words(self.question) & {c['supports'][0]['source_type'] for c in clauses.values()}
        def relevant_family(key):
            return ((requirements['comparison_requested'] and 'only' not in _words(self.question)) or len(family_words)!=1 or
                    clauses[key]['supports'][0]['source_type'] in family_words)
        identifiers = [k for k in sorted(clauses) if roles[k] in IDENTIFYING and complete[k] and relevant_family(k)]
        pairs = []
        for index,a in enumerate(identifiers):
            for z in identifiers[index+1:]:
                meter.check()
                left,right = clauses[a]['supports'][0],clauses[z]['supports'][0]
                if left['evidence_id']==right['evidence_id']: continue
                wanted = bool(requirements['pattern']) and comparison_pair(a,z)
                overlap = len(_words(left['field']['value']) & _words(right['field']['value']))
                exact = left['field']['value']==right['field']['value']
                pairs.append((int(wanted), int(exact), min(overlap,8), score(a)+score(z), a,z))
        best = None
        from fractions import Fraction
        for wanted,exact,overlap,lexical,a,z in sorted(pairs, key=lambda v:(-v[0],-v[1],-v[2],-v[3],v[4:]))[:24]:
            evaluated_pairs += 1
            keys = [a,z]
            endpoints = {a,z}
            for edge in ctx.related['relationships']:
                if edge['predicate']!='recorded_time_before' and set(edge['endpoints'])<=endpoints:
                    keys.append(edge['id'])
            # One recorded timestamp per endpoint: preserve its own SI/FN/etc meaning.
            for key in (a,z):
                eid = clauses[key]['supports'][0]['evidence_id']
                times = [k for k in clauses if roles[k]=='time' and complete[k] and clauses[k]['supports'][0]['evidence_id']==eid]
                if times: keys.append(sorted(times, key=lambda k:(-score(k),k))[0])
            variants = [list(dict.fromkeys(keys))]
            core = [k for k in keys if k not in roles or roles[k]!='time']
            if core!=variants[0]: variants.append(core)
            for keys in variants:
                meter.check()
                bundles = restore(keys)
                if bundles is None: continue
                selected = bundles
                candidate = encode(bundles)
                cost = len(wire.body(messages(candidate),self.model,d2_schema.from_packet(candidate))) if len(candidate['content']['supports'])<=12 else None
                reason = fits(candidate)
                enough = sufficiency()['status']=='comparison_inputs_present'
                utility = 1+8*exact+2*overlap+min(lexical,8)
                value = (int(enough),wanted,Fraction(utility,cost or 1))
                bundle_diagnostics.append(dict(units=keys,cost_bytes=cost,reason=reason or 'alternative_evaluated',
                                               rationale='Source-bound identifying pair with mandatory closure and available recorded context.'))
                if not reason and (best is None or value>best[0]): best=(value,bundles)
        selected = best[1] if best else []
        primary = [k for k,_ in selected]
        for key in primary: decisions[key]='selected'
        for entry in bundle_diagnostics:
            if entry['units']==primary and not entry['reason'].endswith('budget'):entry['reason']='selected_primary'
        # Complement the chosen comparison. Temporal edges are optional and only
        # considered for explicit temporal questions, at most one edge per packet.
        temporal_edges = 0
        for uid in sorted(set(units)-set(primary), key=rank):
            meter.check()
            if len(examined_ids) >= 192: break
            examined_ids.add(uid)
            unit = units[uid]
            ids = unit.get('endpoints',[uid])
            if not all(relevant_family(k) for k in ids):
                decisions[uid]='outside_explicit_family_question';continue
            if unit.get('predicate')=='recorded_time_before':
                if not requirements['temporal_context'] or temporal_edges>=1:
                    decisions[uid]='temporal_comparison_not_prioritized';continue
            bundle = d2._closure(unit, clauses, hydrated, conflicts, meter)
            if bundle is None:
                decisions[uid]='support_unavailable';continue
            decisions[uid]='selected'
            previous = selected
            selected = selected+[(uid,bundle)]
            candidate=encode(selected)
            reason=fits(candidate)
            bundle_diagnostics.append(dict(units=[uid], cost_bytes=len(wire.body(messages(candidate),self.model,d2_schema.from_packet(candidate))) if len(candidate['content']['supports'])<=12 and len(candidate['content']['interpretations'])<=4 else None,
                                           reason=reason or 'selected_complement', rationale='Complementary original context; cost includes the already selected context.'))
            if reason: decisions[uid]=reason;selected=previous
            elif unit.get('predicate')=='recorded_time_before': temporal_edges+=1
        packet = None
        while selected:
            meter.check()
            candidate = encode(selected)
            if not fits(candidate):
                packet = candidate
                break
            uid, _ = selected.pop()
            decisions[uid] = 'final_coverage_byte_budget'
        families = sorted({s['source_type'] for s in packet['content']['sources'].values()}) if packet else []
        status = 'ready_offline' if len(families) >= 2 else 'insufficient_artifact_coverage'
        self._check()
        return dict(contract=POLICY, status=status, issues=[issue],
                    packets=[packet] if status == 'ready_offline' else [],
                    question=self.question, question_id=digest(self.question),
                    question_assessment=assessment, original_s3_assessment=deepcopy(self._original),
                    families=families, selection=selection(), context_sufficiency=sufficiency(), support_resolutions=meter.resolutions,
                    provider_requests=0, evidence_lookups=0,
                    limitation='Recorded authorized history only; lexical relevance is not semantic proof. '
                               'Unselected evidence is not irrelevant; missing families require separately authorized retrieval.')


def prepare(root, run_id, question, config):
    from forensic_assistant.ai.settings import validate
    from .d2_execution import Prepared
    config = validate(config)
    history = History(d2.open_history(root, run_id), question, config['model'])
    preview = history.preview()
    if not preview['packets']:
        raise ValueError('D2_CROSS_INSUFFICIENT_ARTIFACT_COVERAGE')
    if preview['context_sufficiency']['status']=='comparison_inputs_missing':
        raise ValueError('D2_CROSS_CONTEXT_INSUFFICIENT')
    return Prepared(history, preview['packets'][0], config, dict(exploratory=True), profile=VERSION)


def preview(root, run_id, question, config):
    """Provider-free admission including useful failure/coverage information."""
    from forensic_assistant.ai.settings import validate
    from .d2_execution import Prepared
    config = validate(config)
    if config['provider'] != 'openai':
        raise ValueError('D2_OPENAI_REQUIRED')
    history = History(d2.open_history(root, run_id), question, config['model'])
    result = history.preview()
    if result['packets']:
        value = Prepared(history, result['packets'][0], config, dict(exploratory=True), profile=VERSION).preview()
        return dict(value, context_sufficiency=result['context_sufficiency'],
                    investigative_admission=result['context_sufficiency']['status']!='comparison_inputs_missing')
    return dict(result, request_policy=POLICY, provider=config['provider'], model=config['model'],
                source=deepcopy(history._anchor), view=deepcopy(history._ctx.manifest['evidence_state']),
                fits=False, body_bytes=None, body_byte_limit=LIMIT,
                authorization='Not admissible; no grant or provider request.')



def render_preview(value):
    """Concise local inspection; complete original provenance remains in --json."""
    from .explanation import _safe
    selection = value.get('selection', {})
    sufficient = selection.get('sufficiency', value.get('context_sufficiency', {}))
    lines = ['Cross-artifact context preview — no provider request',
             'Policy: '+value['request_policy'],
             'Provider: '+_safe(value['provider']+' / '+value['model']),
             'Complete request bytes: '+str(value.get('body_bytes'))+' / '+str(LIMIT),
             'Byte admission: '+('fits' if value['fits'] else 'not admissible'),
             'Context sufficiency: '+sufficient.get('status','question_sufficiency_not_established'),
             'Artifact families: '+', '.join(value.get('families',[]))]
    for field in value.get('canonical_packet',{}).get('supports',[]):
        packet = value['canonical_packet']
        role = selection.get('field_roles',{}).get(packet['clauses'][field['clause_ref']], 'interpretation_premise')
        family = packet['sources'][field['source_ref']]['source_type']
        lines.append('  '+_safe(field['alias']+' '+family+' '+field['field']['pointer']+' ['+role+']'))
    lines += ['Missing roles: '+', '.join(sufficient.get('missing_roles',[])),
              'Omitted candidates: '+str(selection.get('omitted_counts',{})),
              'Input sufficiency is not identity, causality or case completeness.',
              'Full bundle costs, decisions and original provenance: --json.']
    return '\n'.join(lines)

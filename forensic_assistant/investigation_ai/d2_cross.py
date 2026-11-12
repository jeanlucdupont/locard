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
    'common identity or causality. Selection relevance is lexical, not a forensic finding.')
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
        terms = set(re.findall(r'[\w.-]{3,}', self.question.casefold()))
        def score(uid):
            unit = units[uid]
            # Original field values/semantics, not historical model summaries.
            ids = unit.get('endpoints', [uid])
            text = wire.J([clauses[k]['supports'] for k in ids]).casefold()
            return len(terms & set(re.findall(r'[\w.-]{3,}', text)))
        def rank(uid):
            unit = units[uid]
            return (-score(uid), 0 if uid in conflicts else
                    1 if 'endpoints' in unit else
                    2 if unit.get('type') == 'deterministic_interpretation' else 3, uid)
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
        relevance = {k: ('potentially_contradictory' if k in conflicts or units[k].get('predicate') == 'incompatible_recorded_field'
                         else 'direct_lexical_match' if score(k) else 'contextual_candidate') for k in units}
        selected, examined = [], 0
        def selection():
            counts = {}
            for status in decisions.values():
                if status != 'selected': counts[status] = counts.get(status, 0) + 1
            return dict(known=len(units), examined=examined,
                        unassessed=sum(v == 'unexamined' for v in decisions.values()),
                        omitted_counts=counts, decisions=deepcopy(decisions),
                        relevance=deepcopy(relevance))
        def encode(bundles):
            represented = {}
            for _, bundle in bundles:
                for leaf in bundle['leaves']:
                    family = leaf['source']['source_type']
                    represented.setdefault(family, set()).add(leaf['evidence_id'])
            coverage = {family: dict(available_records=len(eids), represented_records=len(represented.get(family, set())))
                        for family, eids in sorted(available.items())}
            bound_issue = dict(issue, artifact_coverage=coverage,
                               coverage_scope='Validated history only, not the entire case')
            return d2._encode(projected, self._anchor, self._original, bound_issue, bundles, selection())
        def fits(packet):
            body = packet['content']
            if len(body['supports']) > 12 or len(body['interpretations']) > 4:
                return 'support_count_budget'
            if len(wire.body(messages(packet), self.model, d2_schema.from_packet(packet))) > LIMIT:
                return 'complete_request_byte_budget'
            return None
        for uid in sorted(units, key=rank):
            meter.check()
            if examined >= 192: break
            examined += 1
            bundle = d2._closure(units[uid], clauses, hydrated, conflicts, meter)
            if bundle is None:
                decisions[uid] = 'support_unavailable'
                continue
            decisions[uid] = 'selected'
            candidate = encode(selected + [(uid, bundle)])
            reason = fits(candidate)
            if reason: decisions[uid] = reason
            else: selected.append((uid, bundle))
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
                    families=families, selection=selection(), support_resolutions=meter.resolutions,
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
        return Prepared(history, result['packets'][0], config, dict(exploratory=True), profile=VERSION).preview()
    return dict(result, request_policy=POLICY, provider=config['provider'], model=config['model'],
                source=deepcopy(history._anchor), view=deepcopy(history._ctx.manifest['evidence_state']),
                fits=False, body_bytes=None, body_byte_limit=LIMIT,
                authorization='Not admissible; no grant or provider request.')

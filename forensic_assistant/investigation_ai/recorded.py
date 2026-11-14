"""Operation-scoped recorded investigation service; no provider or case access.

Replays the checked transcript once through analysis, B2, and C1/D1 validators.
Public projections are defensive copies. Explicit verify() rereads the source;
local reuse never substitutes for worker, commit, or publication verification.
"""
from copy import deepcopy
from pathlib import Path
import re
import stat
import time
from . import packets as b1, synthesis as s1, relationships as s2, autonomous
from . import decomposition, question_assessment as s3, synthesis_consumer as consumer, organization
from .state import State, Budget
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
    facts = s1._Reducer(recorded_view=s1.validate_evidence_state(manifest.get('evidence_state')))
    retained = State(Budget())
    accepted = set()
    def consume(state, delta, exposure):
        nonlocal retained
        facts.consume(state, delta, exposure)
        retained = state
        accepted.add((delta['id'], delta['disclosure_sha256'], delta['batch']))
    if manifest.get('engine') not in (autonomous.ENGINE, decomposition.ENGINE, consumer.ENGINE):
        raise ValueError('Not a supported incremental transcript')
    autonomous._replay(manifest, events, identity, _on_validated=consume)
    decision = decomposition.validate_journal(manifest, events)
    factual = facts.finish()
    ctx = b1.Context(retained, factual, s2._build(factual), manifest,
                     decision.get('mapping') if decision['status'] == 'accepted' else None, accepted)
    original = s3._assess(manifest['question'], identity, ctx.related)
    org = None
    if manifest['engine'] == consumer.ENGINE:
        # B2's persisted zero-batch terminal predates view-seeded S1 projections.
        # Validate that exact historical representation; the public projection
        # still retains the independently validated manifest read-view authority.
        replay_ctx = ctx
        if not accepted:
            empty = s1._Reducer().finish()
            replay_ctx = b1.Context(retained, empty, s2._build(empty), manifest, ctx.mapping, accepted)
        proposals = consumer._replay(manifest, events, replay_ctx)
        if manifest.get('organization_profile') is not None:
            org = organization._replay(manifest, events, proposals)
    after, later = _read(root, identity)
    if anchor != _anchor(after, later):
        raise ValueError('D2_SOURCE_CHANGED')
    return History(ctx, anchor, original, decision['status'], root, events=events, organization=org)


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


class History:
    """Internal trusted reconstruction handle, not a serialized import interface."""
    def __init__(self, ctx, anchor, original, mapping_status, root=None, *, events=(), organization=None):
        self._ctx, self._anchor, self._original = ctx, deepcopy(anchor), deepcopy(original)
        self._mapping_status, self._root = mapping_status, root
        self._events, self._organization = deepcopy(events), deepcopy(organization)
        self._restored = {}
        self._restored_seal = digest(self._restored)
        self._seal = self._digest()

    def _digest(self):
        ctx = self._ctx
        return digest([ctx.manifest, ctx.factual, ctx.related, ctx.mapping,
                       ctx.state.records, ctx.state.exposed, sorted(ctx.accepted),
                       self._anchor, self._original, self._mapping_status, self._events, self._organization])

    def _intact(self):
        if self._digest() != self._seal or digest(self._restored) != self._restored_seal:
            raise ValueError('D2_TRUSTED_STATE_CHANGED')

    def verify(self):
        self._intact()
        if self._root is not None:
            m, es = _read(self._root, self._anchor['run_id'])
            if _anchor(m, es) != self._anchor:
                raise ValueError('D2_SOURCE_CHANGED')

    def _check(self):
        """Compatibility hook; always retain the independent source check."""
        self.verify()

    def binding(self):
        self._intact()
        return dict(source=deepcopy(self._anchor), view=deepcopy(self._ctx.factual['evidence_state']))

    def factual_state(self):
        self._intact()
        return deepcopy(self._ctx.factual)

    def relationship_state(self):
        self._intact()
        return deepcopy(self._ctx.related)

    def question_assessment(self):
        self._intact()
        return deepcopy(self._original)

    def organization_state(self):
        self._intact()
        return deepcopy(self._organization)

    def explanation_pages(self):
        from . import explanation
        self._intact()
        if self._organization is None:
            return []
        session = explanation._Session(explanation._TOKEN, self._ctx.manifest,
                                       self._ctx.factual, self._organization)
        pages, cursor = [], None
        while True:
            page = explanation.page(session, cursor)
            pages.append(page)
            if len(pages) > explanation.MAX_STATEMENTS + 1:
                raise ValueError('RECORDED_REPORT_PAGE_LIMIT')
            cursor = page['next_cursor']
            if cursor is None:
                return pages

    def report_state(self):
        self._intact()
        manifest = self._ctx.manifest
        terminal = next((e['data'] for e in reversed(self._events) if e['kind'] == 'terminal'), {})
        execution = dict(manifest_status=manifest['status'], terminal_present=bool(terminal),
            recorded={k: deepcopy(terminal[k]) for k in ('termination', 'primary_termination',
                'analysis_coverage', 'controller_diagnostic', 'limitations', 'cleanup') if k in terminal})
        return dict(factual=self.factual_state(), related=self.relationship_state(),
            original_assessment=self.question_assessment(), question=manifest['question'], engine=manifest['engine'],
            frontiers=dict(manifest_chain=deepcopy(manifest['chain']),
                           accepted=sorted([list(v) for v in self._ctx.accepted])),
            organization=self.organization_state(), explanation_pages=self.explanation_pages(), execution=execution,
            historical_proposals=deepcopy((terminal.get('synthesis') or {}).get('accepted', [])))

    def recorded_inputs(self):
        """Defensive inputs for destination protection, never live-case access."""
        self._intact()
        return deepcopy([self._ctx.manifest, list(self._ctx.state.records.values())])

    def _restore(self, clause, meter):
        identity = clause['id']
        if identity not in self._restored:
            self._restored[identity] = b1._rehydrate(clause, self._ctx, meter)
            self._restored_seal = digest(self._restored)
        else:
            meter.check()
        return self._restored[identity]

    def restore_all_support(self):
        self._intact()
        b1._validate_context(self._ctx)
        meter = b1.Meter(b1.Limits(), time.monotonic)
        restored = {}
        for clause in self._ctx.factual['clauses']:
            bundle = self._restore(clause, meter)
            if bundle is None:
                raise ValueError('RECORDED_REPORT_SUPPORT_UNAVAILABLE')
            restored[clause['id']] = bundle
        for relation in self._ctx.related['relationships']:
            if not set(relation['endpoints']) <= restored.keys():
                raise ValueError('RECORDED_REPORT_INCOMPLETE_DEPENDENCY')
        return deepcopy(restored)

    def restore_support(self, refs):
        """Original B1 support including relationship/contradiction closure, never aliases."""
        self._intact()
        clauses = {c['id']: c for c in self._ctx.factual['clauses']}
        edges = {r['id']: r for r in self._ctx.related['relationships']}
        units = {**clauses, **edges}
        if not set(refs) <= units.keys():
            raise ValueError('FINDINGS_UNKNOWN_ORIGINAL_REFERENCE')
        meter = b1.Meter(b1.Limits(), time.monotonic)
        needed = set(refs) & clauses.keys()
        for ref in refs:
            needed.update(edges.get(ref, {}).get('endpoints', []))
        conflicts = {}
        for edge in edges.values():
            if edge['predicate'] == 'incompatible_recorded_field':
                for cid in edge['endpoints']:
                    conflicts.setdefault(cid, []).append(edge)
        # Closure must preserve contrary endpoints even when not explicitly cited.
        pending = list(needed)
        while pending:
            cid = pending.pop()
            for edge in conflicts.get(cid, []):
                for endpoint in edge['endpoints']:
                    if endpoint not in needed:
                        needed.add(endpoint)
                        pending.append(endpoint)
        hydrated = {cid: self._restore(clauses[cid], meter) for cid in sorted(needed)}
        bundles = []
        for ref in refs:
            value = _closure(units[ref], clauses, hydrated, conflicts, meter)
            if value is None:
                raise ValueError('FINDINGS_SUPPORT_UNAVAILABLE')
            bundles.append(value)
        return deepcopy(bundles)

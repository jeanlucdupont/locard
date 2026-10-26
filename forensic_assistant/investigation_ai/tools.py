"""Nine fixed adapters. No names or SQL are resolved from model prose."""
import hashlib
import json
from forensic_assistant.retrieval.evidence import EvidenceQueries, get_evidence
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.correlation.investigation import investigate
from forensic_assistant.correlation.processes import process_tree
from forensic_assistant.correlation.sessions import session
from forensic_assistant.correlation.temporal import shift
from forensic_assistant.detections.engine import available_rules, detections
from forensic_assistant.llm.context import compact_record
from forensic_assistant.v2_cli import anchor_time
from .contracts import arguments
from .diagnostics import measure

AROUND_LIMITATIONS = frozenset((
    'Multiple source occurrences; cannot select an unambiguous source',
    'Host context missing or conflicting; cannot select same-host temporal neighbors',
    'Anchor has missing or multiple timestamps; select --timestamp-slot from show output',
))


def identity(prefix, value):
    return prefix + hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()[:24]

def compact(record):
    result = compact_record(record)
    result['artifact_type'] = record.get('artifact_type')
    result['source_type'] = record.get('source_type', 'evtx')
    result['kind'] = record.get('kind')
    context = record.get('context', {})
    if context:
        # Assertions remain attributed metadata, never independently verified facts.
        result['source_context'] = {k: context.get(k) for k in
                                    ('source_ids', 'hostname', 'username', 'volume_root', 'basis', 'conflicts')}
        result['source_context']['assertions'] = [
            {k: row.get(k) for k in ('source_id', 'hostname', 'username', 'volume_root', 'basis')}
            for row in context.get('source_assertions', [])[:8]]
        if len(context.get('source_assertions', [])) > 8:
            result.setdefault('truncated_fields', []).append('source assertions')
    if record.get('source_type') == 'browser':
        detail = record.get('detail', {})
        for key in ('browser_product', 'profile', 'context_id', 'url', 'title', 'target_path', 'current_path', 'full_path', 'state'):
            if key in detail:
                value = detail[key]
                if isinstance(value, str) and len(value) > 220:
                    value = value[:220]
                    result.setdefault('truncated_fields', []).append(key)
                result[key] = value
    for stamp in result.get('timestamps', []):
        original = next(
            (t for t in record.get('timestamps', []) if t['timestamp_utc'] == stamp['utc'] and t['source'] == stamp['type']),
            None
        )
        if original:
            stamp['slot'] = original['slot']
    if record.get('supporting_evidence_ids'):
        result['supporting_evidence_ids'] = record['supporting_evidence_ids']
    if record.get('warnings'):
        result['warnings'] = [str(v)[:200] for v in record['warnings'][:4]]
        if len(record['warnings']) > 4 or any(len(str(v)) > 200 for v in record['warnings'][:4]):
            result.setdefault('truncated_fields', []).append('warnings')
    return result

def envelope(db, name, raw, limit=50):
    rows = raw.get('evidence_records', raw.get('records', raw.get('nodes', [])))
    records = {r['id']: compact(get_evidence(db, r['id']) if db is not None and 'context' not in r else r)
               for r in rows[:limit]}
    semantic_ids = {r['evidence_id'] for r in raw.get('semantic_candidates', [])}
    if name == 'semantic_search':
        for eid, record in records.items():
            record['retrieval_basis'] = 'SEMANTICALLY_RETRIEVED' if eid in semantic_ids else 'DETERMINISTIC_EXPANSION_OF_SEMANTIC_CANDIDATE'
    relations = raw.get('correlated_evidence', raw.get('relationships', [])) + raw.get('unresolved_relationships', [])
    findings = raw.get('detections', [])
    # Required supporting records travel with facts; otherwise omit the object.
    for r in list(records.values()):
        for eid in r.get('supporting_evidence_ids', []):
            if eid not in records and len(records) < limit:
                records[eid] = compact(get_evidence(db, eid))
    all_relations = []
    all_detections = []
    omitted = max(0, len(relations) - 100) + max(0, len(findings) - 25)
    ambiguous = 0
    for r in relations[:100]:
        if not set(r.get('evidence_ids', [])) <= records.keys():
            omitted += 1
            continue
        contexts = [records[eid].get('source_context', {}) for eid in r.get('evidence_ids', [])]
        sources = {sid for ctx in contexts for sid in ctx.get('source_ids') or []}
        if len(sources) > 1 and (any(ctx.get('conflicts') or not ctx.get('hostname') for ctx in contexts)
                                 or len({ctx.get('hostname') for ctx in contexts}) != 1):
            omitted += 1
            ambiguous += 1
            continue
        value = {k: r[k] for k in (
            'relationship',
            'status',
            'evidence_ids',
            'reason',
            'limitations',
            'matched_fields',
            'source_id',
            'target_id'
        ) if k in r}
        if len(sources) > 1:
            value['limitations'] = [*value.get('limitations', []),
                                    'Cross-source relationship; host context may include analyst assertions']
        value['relationship_id'] = identity('REL:', value)
        all_relations.append(value)
    for r in findings[:25]:
        ids = r.get('evidence_ids', [])
        for eid in ids:
            if eid not in records and len(records) < limit:
                records[eid] = compact(get_evidence(db, eid))
        if not set(ids) <= records.keys():
            omitted += 1
            continue
        value = {k: r[k] for k in (
            'detection_id',
            'rule_id',
            'rule_name',
            'rule_version',
            'severity',
            'evidence_ids',
            'reason',
            'limitations',
            'correlation_status',
            'matched_fields'
        ) if k in r}
        value.setdefault('detection_id', identity('DET:', value))
        all_detections.append(value)
    limits = [str(v)[:300] for v in raw.get('limits', [])[:8]]
    limits_omitted = len(raw.get('limits', [])) > 8 or any(len(str(v)) > 300 for v in raw.get('limits', [])[:8])
    if raw.get('reason'):
        limits.append(str(raw['reason'])[:300])
        limits_omitted |= len(str(raw['reason'])) > 300
    if limits_omitted:
        limits.append('Limitation text was truncated; inspect deterministic results for full limitations')
    if any(r.get('source_context', {}).get('conflicts') or
           len(r.get('source_context', {}).get('source_ids') or []) > 1 for r in records.values()):
        limits.append('Source/host context is ambiguous; records must not be attributed to a single source or host')
    if any(r.get('source_context', {}).get('basis') not in (None, 'artifact field', 'unknown') for r in records.values()):
        limits.append('Source metadata includes analyst assertions; these are not independently verified artifact facts')
    if any(r.get('truncated_fields') for r in records.values()):
        limits.append('Some evidence fields are truncated; inspect the original records')
    if omitted:
        limits.append(f'{omitted} relationship/detection objects omitted because support was unavailable, ambiguous or outside result bounds')
    if ambiguous:
        limits.append('Cross-source relationships omitted: host attribution is missing, conflicting or ambiguous')
    return {
        'tool': name,
        'behavior': 'semantic' if name == 'semantic_search' else 'deterministic',
        'records': list(records.values()),
        'relationships': all_relations,
        'detections': all_detections,
        'limitations': limits,
        'returned_count': len(records),
        'truncated': bool(raw.get('truncated') or len(rows) > limit or omitted or limits_omitted),
        'semantic_candidates': raw.get('semantic_candidates', []),
        'label': 'UNTRUSTED FORENSIC EVIDENCE'
    }

def execute(db, name, args, config, model=None):
    args = arguments(name, args)
    q = EvidenceQueries(db)
    if 'evidence_id' in args:
        if args['evidence_id'] not in config.get('known_ids', []):
            raise ValueError('Evidence anchor was not grounded in this investigation')
        if not db.execute('SELECT 1 FROM evidence_records WHERE evidence_id=?', (args['evidence_id'],)).fetchone():
            raise ValueError('Evidence ID is outside the active case')
    limit = args.get('limit', args.get('max_nodes', 50))
    if name == 'search_evidence':
        filters = dict(args)
        if filters.get('hostname'):
            filters['strict_host'] = True
        raw = q.search(**filters).as_dict()
    elif name == 'timeline':
        raw = q.search(**args, timeline=True, strict_host=bool(args.get('hostname'))).as_dict()
    elif name == 'show_evidence':
        raw = {'records': [get_evidence(db, args['evidence_id'])]}
    elif name == 'around':
        anchor = get_evidence(db, args['evidence_id'])
        from forensic_assistant.retrieval.evidence import same_host_window
        try:
            stamp = anchor_time(anchor, args.get('timestamp_slot'))
            window = same_host_window(anchor, stamp, args['seconds'], direction=args['direction'])
        except ValueError as exc:
            if str(exc) not in AROUND_LIMITATIONS: raise
            return envelope(db, name, {'records': [], 'limits': [str(exc)]}, limit)
        raw = q.search(
            **window,
            timeline=True,
            limit=limit,
            nearest_to=stamp
        ).as_dict()
    elif name == 'process_tree':
        raw = process_tree(db, **args)
    elif name == 'session':
        from forensic_assistant.correlation.models import get_event
        anchor = get_event(db, args['evidence_id'])
        if anchor['kind'] != 'logon' or not anchor.get('target_logon_key'):
            raise ValueError('Session needs a successful-logon anchor')
        raw = session(db, anchor['target_logon_key'], anchor_id=anchor['id'], max_hours=args['max_hours'], limit=limit)
    elif name == 'detections':
        if args['rule_id'] not in config['rule_ids']:
            raise ValueError('Detection rule is not in the frozen registry')
        raw = detections(db, **args, candidate_limit=100)
    elif name == 'investigate_evidence':
        kwargs = dict(args)
        kwargs['max_candidates'] = kwargs.pop('limit')
        raw = investigate(db, **kwargs)
    elif name == 'semantic_search':
        if not config.get('semantic_enabled'):
            raise ValueError('Semantic retrieval is not enabled')
        from forensic_assistant.semantic.index import search
        if model is None:
            from forensic_assistant.semantic.model import LocalModel
            model = LocalModel(config['model_path'])
        kwargs = dict(args)
        question = kwargs.pop('query')
        if kwargs.get('hostname'):
            kwargs['strict_host'] = True
        found = search(db, config['index_root'], model, question,
                       _read_view_proof=config.get('_read_view_proof'), **kwargs)
        raw = {
            'records': [get_evidence(db, r['evidence_id']) for r in found['results']],
            'semantic_candidates': found['results'],
            'truncated': found['candidate_pool_truncated'],
            'relationships': [],
            'detections': [],
            'limits': ['Semantic expansion is limited to five candidate anchors; similarity is not correlation']
        }
        seen = {r['id'] for r in raw['records']}
        for hit in found['results'][:5]:
            expanded = investigate(db, hit['evidence_id'], max_candidates=50)
            for record in expanded['evidence_records']:
                if record['id'] not in seen and len(raw['records']) < 50:
                    seen.add(record['id'])
                    raw['records'].append(record)
                elif record['id'] not in seen:
                    raw['truncated'] = True
            raw['relationships'].extend(expanded['correlated_evidence'] + expanded['unresolved_relationships'])
            raw['detections'].extend(expanded['detections'])
            raw['limits'].extend(expanded['limits'])
        limit = 50
    else:
        raise ValueError('Unknown forensic operation')
    return envelope(db, name, raw, limit)

def initial(db, question, config, model=None):
    from forensic_assistant.semantic.hybrid import retrieve
    profile = config.get('_profile')
    searcher = None
    if config.get('_read_view_proof') is not None:
        from functools import partial
        from forensic_assistant.semantic.index import search
        searcher = partial(search, _read_view_proof=config['_read_view_proof'])
    with measure(profile, 'initial_retrieval'):
        plan, context = retrieve(
            Queries(db),
            question,
            config.get('date_hint'),
            20,
            index_root=config.get('index_root') if config.get('semantic_enabled') else None,
            model_path=config.get('model_path'),
            model=model,
            searcher=searcher
        )
    # Availability is measured from this same read snapshot, not guessed by the LLM.
    with measure(profile, 'inventory'):
        browser_count = db.execute("SELECT count(*) FROM evidence_records WHERE source_type='browser'").fetchone()[0]
    if browser_count:
        context = dict(context)
        rows = list(context.get('evidence_records', []))
        seen = {r['id'] for r in rows}
        browser_rows = EvidenceQueries(db).search(artifact='browser', limit=10)
        context['evidence_records'] = rows[:40] + [r for r in browser_rows.records if r['id'] not in seen]
        context['limits'] = [*context.get('limits', []),
                             'Initial browser sample is bounded context, not an exhaustive download investigation']
        context['truncated'] = bool(context.get('truncated') or browser_rows.truncated or len(rows) > 40)
    with measure(profile, 'source_hydration'):
        result = envelope(db, 'initial_retrieval', context, 50)
    result['plan'] = {k: v for k, v in plan.items() if k not in ('semantic_results', 'selection_reasons')}
    result['plan']['browser_available'] = browser_count > 0
    result['semantic_used'] = bool(plan.get('semantic_coverage') == 'searched')
    if result['semantic_used']:
        result['semantic_candidates'] = plan['semantic_results']['results']
        for record in result['records']:
            record['retrieval_basis'] = plan.get('selection_reasons', {}).get(record['id'], ['deterministic_expansion'])
    return result

"""Deterministic planning first; semantic hits never establish relationships."""
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from forensic_assistant.retrieval.v1_planner import retrieve_question
from forensic_assistant.correlation.investigation import Assembly,investigate
from .documents import snapshot

@contextmanager
def bounded_hydration(db):
    # V3 expansion reuses V2 hydration. Reject oversized rows before copying a
    # hundred full payloads into Python; deterministic commands retain their limits.
    previous=db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,2*1024*1024)
    try:yield
    finally:db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,previous)


def precise(question):
    return bool(re.search(r'(?:EVTX|MFT|PREFETCH|REGISTRY):|\b(?:event\s*(?:id)?\s*[:=]?\s*\d+|process[- ]tree|logon[- ]?id|session\s*[:=]|user\s+\S+|path\s+|\d{1,2}:\d{2}|\d{4}-\d\d-\d\d|(?:\d{1,3}\.){3}\d{1,3})|[a-z]:[\\/]',question,re.I))


def retrieve(queries,question,date_hint=None,limit=30,*,index_root=None,model_path=None,model=None,searcher=None):
    if precise(question):return retrieve_question(queries,question,date_hint,limit)
    if index_root is None or (searcher is None and not (Path(index_root)/'CURRENT').exists()):
        plan,context=retrieve_question(queries,question,date_hint,limit)
        plan={**plan,'semantic_coverage':'unavailable; deterministic retrieval only'}
        return plan,context
    from .index import search
    from .model import LocalModel
    with snapshot(queries.db),bounded_hydration(queries.db):
        try:plan,context=retrieve_question(queries,question,date_hint,limit)
        except ValueError as exc:
            if not question.strip() or len(question.encode())>1000:raise
            plan={'operation':'conceptual','deterministic_note':str(exc)}
            context=Assembly(queries.db,100).output({})
        try:
            model=model or LocalModel(model_path)
            filters={}
            process=re.search(r'\b[\w.-]+\.exe\b',question,re.I)
            host=re.search(r'\bhost(?:name)?\s+([\w.-]+)',question,re.I)
            if process:filters['process']=process.group()
            if host:filters['hostname']=host.group(1);filters['strict_host']=True
            hits=(searcher or search)(queries.db,index_root,model,question,limit=min(limit,30),**filters)
        except (ValueError,OSError,ImportError) as exc:
            if context['evidence_records']:
                plan={**plan,'semantic_coverage':'unavailable','semantic_reason':str(exc)}
                return plan,context
            raise ValueError('Semantic retrieval unavailable: '+str(exc)) from exc
        reasons={e['id']:['deterministic_match' if e['id'] in context['priorities']['anchors'] else 'deterministic_expansion'] for e in context['evidence_records']}
        existing={e['id']:e for e in context['evidence_records']}
        # Reuse the engine's statuses unchanged. Semantic anchors are not exact anchors.
        for hit in hits['results'][:5]:
            eid=hit['evidence_id']
            expanded=investigate(queries.db,eid,max_candidates=50)
            for e in expanded['evidence_records']:
                if e['id'] not in existing and len(existing)<100:existing[e['id']]=e
            for group,ids in expanded['priorities'].items():
                target='semantic' if group=='anchors' else group
                dest=context['priorities'].setdefault(target,[])
                for item in ids:
                    if item in existing and item not in dest:dest.append(item)
                    reasons.setdefault(item,[])
                    reason='semantic_similarity' if item==eid else 'deterministic_expansion'
                    if reason not in reasons[item]:reasons[item].append(reason)
            for section in ('correlated_evidence','unresolved_relationships','detections'):
                for value in expanded[section]:
                    if value not in context[section]:context[section].append(value)
            context['limits'].extend(expanded['limits'])
        context['evidence_records']=list(existing.values())
        context['candidate_count']=len(existing)
        context['candidate_count_is_lower_bound']=True
        context['limits']=sorted(set(context['limits']+['Semantic expansion limited to five hits and 100 evidence records']))
        context['artifact_distribution']={k:sum(e.get('source_type')==k for e in existing.values()) for k in ('evtx','mft','prefetch','registry')}
        context['selection_reasons']=reasons
        context['semantic_retrieval']=True
        return {**plan,'semantic_coverage':'searched','semantic_results':hits,'selection_reasons':reasons},context

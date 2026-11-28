"""Operational progress only; never evidence authority or semantic quality scoring."""
import json
from .workspace import signature

CONTRACT='investigative-progress-v1'
PREFIX='LOCARD OPERATIONAL PROGRESS (not evidence): '
SEARCHES=frozenset(('search_evidence','timeline','around','discover_security_signals','discover_execution_behaviors','activity_overview'))
CAPABILITIES={
 'evtx':['discover_execution_behaviors','activity_overview','search_evidence','timeline'],
 'defender':['discover_security_signals','activity_overview','search_evidence'],
 'registry':['discover_execution_behaviors','search_evidence','timeline'],
 'prefetch':['discover_execution_behaviors','search_evidence','timeline'],
 'mft':['search_evidence','timeline'],'browser':['search_evidence','timeline','activity_overview']}


def message(value):return PREFIX+json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)


def availability(adapter,deadline,cancel):
    """One bounded presence probe per authorized family/source; no evidence disclosure.

    Uses the existing scoped retrieval predicates, not a source-wide count. Failed
    or timed-out probes mean unknown, never absence. The worker owns the read view.
    """
    import time,sqlite3
    from forensic_assistant.retrieval.evidence import EvidenceQueries
    from .tools import exclusive_end
    scope=adapter.scope;out={f:'unknown' for f in scope['families']}
    adapter.db.set_progress_handler(lambda:int(cancel.is_set() or time.monotonic()>=deadline),1000)
    try:
        for family in out:
            absent=True
            for source in scope['source_ids']:
                if cancel.is_set() or time.monotonic()>=deadline:absent=False;break
                try:
                    result=EvidenceQueries(adapter.db,hydrate=lambda _:{}).search(artifact=family,source_scope=source,
                        start=scope['start'],end=exclusive_end(scope['end']),limit=1,exact_count=False)
                except sqlite3.OperationalError:
                    if not cancel.is_set() and time.monotonic()<deadline:raise
                    absent=False;break
                if result.records:out[family]='available';absent=False;break
            if absent:out[family]='unavailable'
    finally:adapter.db.set_progress_handler(None,0)
    return out


class Progress:
    def __init__(self,workspace,scope,view,turn):
        self.workspace=workspace
        self.turn=turn
        self.binding=signature(dict(authorization=scope,view=view))
        self.available=json.loads(workspace.meta('artifact_availability') or '{}')

    def alternatives(self,exclude=None):
        return [dict(artifact=f,tools=[t for t in CAPABILITIES[f] if t!=exclude])
                for f,state in sorted(self.available.items()) if state=='available' and f in CAPABILITIES]

    def assess(self,operation,tool,args,result,*,new_ids=(),frontier=0,consolidated=False,population=None):
        key=signature(dict(binding=self.binding,tool=tool,arguments=args,population=population))
        previous=json.loads(self.workspace.meta('progress:'+key) or 'null')
        coverage=result.get('coverage',result.get('content_search',result.get('object_search',{})))
        continuation=result.get('next_offset',coverage.get('next_offset'))
        if continuation is None:continuation=coverage.get('next_cursor',result.get('next_cursor',result.get('next_after')))
        complete=coverage.get('complete',result.get('complete'))
        if complete is None and type(result.get('has_more')) is bool:complete=not result['has_more'] and not args.get('offset',0)
        exhausted=continuation is None and (complete is True or coverage.get('remaining_complete') is True or result.get('has_more') is False)
        # Only stable forensic outputs may prove a repeat; model prose isn't compared semantically.
        stable=dict(result)
        for field in ('elapsed_seconds','duration_seconds','note_id'):stable.pop(field,None)
        result_digest=signature(stable)
        new_fields=0
        for row in [result,*result.get('records',[])]:
            eid=row.get('evidence_id')
            for field in [*row.get('fields',[]),*row.get('original_fields',[])]:
                if eid and not field.get('truncated') and not field.get('redacted') and not self.workspace.db.execute(
                    'SELECT 1 FROM fields WHERE eid=? AND pointer=? AND event<? AND preview=0 LIMIT 1',
                    (eid,field['field'],frontier)).fetchone():new_fields+=1
        state='unknown';reason='productivity_not_established'
        if new_ids or new_fields:state='productive';reason='new_original_references'
        elif previous and previous.get('turn')!=self.turn:state='unknown';reason='analyst_turn_reconsideration'
        elif tool=='show_evidence':state='productive';reason='original_rehydration_available_for_current_context'
        elif tool=='verify_observation' and result.get('verified'):
            state='unknown' if previous else 'productive';reason='reverification_permitted' if previous else 'independent_verification'
        elif tool=='note':
            state='nonproductive_repeat' if previous else 'productive';reason='identical_structured_note' if previous else 'new_structured_note_not_semantic_novelty'
        elif tool=='memory':
            state='unknown' if consolidated else 'nonproductive_repeat' if previous and previous['result_digest']==result_digest else 'productive'
            reason='memory_recovery_after_consolidation' if consolidated else 'identical_memory_result' if state=='nonproductive_repeat' else 'memory_information_recovered'
        elif tool in SEARCHES:
            if previous and previous['result_digest']==result_digest and exhausted:
                state='nonproductive_repeat';reason='completed_search_unchanged_scope'
            elif not previous and (complete is not None or continuation is not None):state='productive';reason='new_query_or_page_coverage'
        family=args.get('artifact',result.get('scope',{}).get('artifact'))
        if tool in ('discover_security_signals','discover_execution_behaviors') and family is None:family='evtx'
        if tool=='activity_overview':family={'browser_downloads':'browser','prefetch_executables':'prefetch','defender_groups':'defender'}.get(args.get('kind'),'evtx')
        frontier_key=signature(dict(binding=self.binding,tool=tool,arguments={k:v for k,v in args.items() if k not in ('offset','evtx_after','object_after')},population=population))
        value=dict(contract=CONTRACT,turn=self.turn,artifact=family,frontier_key=frontier_key,operation=operation,key=key,binding=self.binding,tool=tool,state=state,reason=reason,
            previous_operation=previous['operation'] if previous else None,result_digest=result_digest,
            new_evidence_ids=sorted(new_ids),new_fields=new_fields,new_coverage=tool in SEARCHES and previous is None and complete is not None,
            search_complete=complete,continuation_available=continuation is not None,exhausted=exhausted,
            read_view_unchanged=True,artifact_signal_state=coverage.get('state'),
            artifact_availability=self.available,
            limitation='Coverage belongs to this query, not the entire artifact family. Operational progress is not forensic verification.')
        if state=='nonproductive_repeat':
            value.update(guidance='This unchanged operation returned no new evidence or coverage. Choose a relevant authorized alternative; do not infer absence of suspicious activity.',alternatives=self.alternatives(tool))
        return value

    def completion(self,*,retrieved,inspected,verified,repetitions,intent,challenge_used):
        db=self.workspace.db
        pending=db.execute("SELECT count(*) FROM meta WHERE key>='progress-frontier:' AND key<'progress-frontier;' AND json_extract(value,'$.continuation_available')=1").fetchone()[0]
        questions=db.execute("SELECT count(*) FROM notes n WHERE kind='open_question' AND status IN ('active','unresolved') AND NOT EXISTS(SELECT 1 FROM notes x WHERE x.supersedes=n.id)").fetchone()[0]
        alternatives=self.alternatives('discover_security_signals')
        family_coverage={f:('available_query_scope_only' if self.workspace.meta('progress-family:'+f) else 'available_not_queried') if state=='available' else state for f,state in self.available.items()}
        possible=intent=='broad' and not retrieved and repetitions>0 and bool(alternatives)
        return dict(contract='investigative-completion-v1',provider_final=True,objective_assessed='not_deterministically_established',
            coverage='authorized_scope_empty' if self.available and not retrieved and not pending and all(v=='unavailable' for v in self.available.values()) else 'partial_or_unknown',
            records_retrieved=retrieved,original_inspections=inspected,verifications=verified,nonproductive_repetitions=repetitions,
            continuation_frontiers=pending,unresolved_questions=questions,artifact_availability=self.available,family_coverage=family_coverage,
            alternatives=alternatives,recovery_eligible=possible and not challenge_used,recovery_unresolved=possible and challenge_used,
            limitation='A final response is conversational termination, not proof of objective completion or forensic coverage.')

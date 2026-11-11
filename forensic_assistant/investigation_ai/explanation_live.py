"""Bounded reference-only explanation updates from confirmed C1 revisions."""
from copy import deepcopy
import sys
import time

from . import explanation as d1, organization as c1, synthesis as s1
from . import explanation_status as diagnostic
from .transcript import digest, MAX_BYTES, JournalPublicationError

PROFILE='local-explanation-v1'
COMPACT_PROFILE='local-explanation-v2'
COMPACT_CHECKPOINT='explanation-checkpoint-v2'
CONTRACT='explanation-revision-v1'
CHECKPOINT='explanation-checkpoint-v1'
FRONTIER='explanation-frontier-v1'
ORDER='affected-reference-order-v1'
LIMITS=dict(checkpoints=9,per_checkpoint=32,operations=288,visits=2048,
            admissions=192,event_bytes=8192,journal_bytes=65536,seconds=1.,slice=.100,
            state_bytes=131072,edges=2048,pending=192,heap=4*1024*1024)


def receipt_reference(receipt):
    """Bind a wire reference to the complete, independently reconstructed receipt."""
    if (receipt['contract']!='organization-commit-v1' or receipt['profile']!=c1.PROFILE
        or receipt['rules']!=c1.RULES):
        raise ValueError('Unsupported C1 receipt rules')
    return {**{k:deepcopy(receipt[k]) for k in
        ('contract','profile','rules','run_id','read_view','event','revision','digest','source_frontier')},
        'receipt_digest':digest(receipt)}


def event_size(cp, event):
    value=dict(sequence=event['sequence'],kind='explanation_checkpoint',data=cp,previous=event['previous'])
    value['hash']=digest(value)
    return d1._size(value)+1


def owned_bytes(value):
    seen=set()
    def size(v):
        if id(v) in seen:return 0
        seen.add(id(v));n=sys.getsizeof(v)
        if isinstance(v,dict):n+=sum(size(k)+size(x) for k,x in v.items())
        elif isinstance(v,(tuple,list,set)):n+=sum(size(x) for x in v)
        return n
    return size(value)


def _section(entity):
    if entity['kind']=='finding':return 'interpretations' if entity['finding_type']=='deterministic_interpretation' else 'observations'
    if entity['kind']=='relationship':return 'current' if entity['current_final'] else 'historical'
    if entity.get('role')=='provisional_objective':return 'objectives'
    if entity['kind']=='hypothesis' or entity.get('role') in ('b2_group','b2_relationship_candidate'):return 'hypotheses'
    if entity.get('role')=='b2_next_objective':return 'actions'
    if entity['kind']=='question' and entity.get('role')!='original_question':return 'questions'
    return None


class Sources:
    """Ephemeral borrowed committed graph; no evidence copies retained by reducer."""
    def __init__(self, manifest, org, facts):
        self.entities=org.entities
        self.clauses={}
        for k,v in org.entities.items():
            if v['kind']!='finding' or k not in facts.clauses:continue
            original=facts.clauses[k];lineage=v['dependencies'][0]['lineage']
            if any(ref not in original['lineage'] for ref in lineage):raise ValueError('Unaccepted source lineage')
            self.clauses[k]={**original,'lineage':lineage}
        self.session=object.__new__(d1._Session)
        s=self.session;s.manifest=manifest;s.clauses=self.clauses;s.entities=self.entities
        s.objective_entities=[self.entities[k] for k in sorted(self.entities)
            if self.entities[k].get('assessment') or self.entities[k].get('original_assessment')]
        s.original=next(v for v in self.entities.values() if v.get('role')=='original_question')
        s.organization=dict(coverage=org.coverage,state_digest=digest(org.state()),
            incomplete=not org.coverage.get('processing_complete',False),
            limitations=['Organization is not evidence, authorization, forensic completeness or a final report.',
                        'Recorded read view only; current case equality and parent cleanup are not established.'])
        s.binding=dict(run_id=manifest['investigation_id'],read_view=org.sources.view)

    def statement(self, key, section):
        entity=self.entities.get(key)
        dependencies=[] if entity is None else entity.get('endpoints',[])+entity.get('support_ids',[])
        if any(k not in self.clauses for k in dependencies):return None
        if entity and entity['kind']=='finding':
            if key not in self.clauses:return None
            clause=self.clauses[key];s1._validate_render_clause(clause)
            if (entity['read_view']!=clause['evidence_state'] or entity['qualifications']!=clause['qualifications'] or
                entity['dependencies'][0]!=c1._Sources(self.session.manifest)._dependency(clause)):
                raise ValueError('Changed explanation original support')
        if entity and entity['kind']=='relationship' and entity['membership_frontier']!=self.session.organization['coverage'].get('relationship_frontier'):
            section='coverage'
        return section,self.session._statement(section,key)


class Reducer:
    def __init__(self, run_id, view, profile=PROFILE):
        if profile not in (PROFILE,COMPACT_PROFILE):raise ValueError('Unknown explanation profile')
        self.profile=profile
        self.waiting=set();self.omitted_keys=set()
        self.state=dict(contract=CONTRACT,profile=profile,run_id=run_id,read_view=deepcopy(view),
            revision=0,frontier=None,items={},pending=[],operations=0,visits=0,admitted=[],
            coverage={},stop=None,indexes={},omitted=[])

    def observe(self,receipt):
        keys=sorted(self.waiting|self.omitted_keys|set(receipt['changed']['entities']))
        self.waiting=set(keys[:LIMITS['pending']])
        self.omitted_keys=set(keys[LIMITS['pending']:])

    def commit(self,prepared):
        target,cp=prepared
        if cp['previous_digest']!=digest(self.state):raise ValueError('Stale explanation predecessor')
        self.state=target;self.waiting=set(target['pending']);self.omitted_keys=set(target['omitted'])

    def prepare(self, receipt, sources, *, clock=time.monotonic, deadline=float('inf'), replay=None, charged_visits=None, event=None):
        started=clock();measuring=time.perf_counter();old=self.state
        self.last_visits=old['visits'] if charged_visits is None else charged_visits
        self.timings=dict(candidate_seconds=0.,dependency_seconds=0.,serialization_seconds=0.)
        if replay is not None:self.last_visits=replay['charged_visits_before']
        if replay is not None and (type(replay['examined']) is not int or not 0<=replay['examined']<=LIMITS['pending'] or
            replay['stop'] not in (None,'time_limit','operation_limit','dependency_limit','pending_dependency',
                                  'admission_limit','index_edge_limit','event_byte_limit')):
            raise ValueError('Invalid explanation prefix')
        if type(self.last_visits) is not int or not old['visits']<=self.last_visits<=LIMITS['visits']:
            raise ValueError('Invalid charged explanation visits')
        charged_before=self.last_visits
        compact=self.profile==COMPACT_PROFILE
        if compact and event is None:raise ValueError('Compact checkpoint requires event identity')
        binding=receipt_reference(receipt) if compact else receipt
        if old['revision']>=LIMITS['checkpoints']:return None,'checkpoint_limit'
        changed=set(receipt['changed']['entities'])|set(old['pending'])|self.waiting|set(old['omitted'])|self.omitted_keys
        changed.update(k for k,deps in old['indexes'].items() if changed.intersection(deps))
        changed.update(('coverage','original_assessment'))
        # Objective associations and membership qualifiers are canonical content.
        if any(sources.entities.get(k,{}).get('role') in ('original_question','provisional_objective') for k in changed):
            changed.update(old['items'])
        candidates=[]
        rank={k:i for i,k in enumerate(('interpretations','observations','objectives','coverage','current','historical','hypotheses','questions','actions'))}
        for key in changed:
            section='coverage' if key=='coverage' else 'objectives' if key=='original_assessment' else _section(sources.entities[key]) if key in sources.entities else None
            if section:
                candidates.append((section,key,digest(sources.entities.get(key,sources.session.organization['coverage']))))
        candidates.sort(key=lambda x:(rank[x[0]],x[1]))
        omitted=[k for _,k,_ in candidates[LIMITS['pending']:]]
        candidates=candidates[:LIMITS['pending']]
        target=deepcopy(old);target['visits']=charged_before
        operations=[];visited=0;done=[];stop=None
        self.timings['candidate_seconds']=time.perf_counter()-measuring
        # Preserve v1's estimator for historical replay. V2 measures complete events.
        operation_bytes=d1._size(receipt)+1024
        def checkpoint(current, ops, completed, examined, reason):
            # Full logical state retains the authenticated receipt under both profiles.
            result=deepcopy(current)
            result['pending']=[k for _,k,_ in candidates if k not in completed]
            result['omitted']=omitted
            result['revision']=old['revision']+1
            result['frontier']=dict(contract=FRONTIER,receipt=receipt,
                statement_contract=d1.STATEMENT,statement_rules=d1.RULES,ordering=ORDER)
            result['coverage']=dict(c1_complete=sources.session.organization['incomplete'] is False,
                final_assessment_available=bool(sources.session.original.get('original_assessment')),
                final_assessment_represented=bool(sources.session.original.get('original_assessment')) and 'original_assessment' in completed,
                pending=len(result['pending']),omitted=len(omitted),accepted=len(result['items']),omissions_relevance='not_evaluated',
                relationship_frontier=sources.session.organization['coverage'].get('relationship_frontier'))
            result['stop']=reason
            wire=dict(contract=COMPACT_CHECKPOINT if compact else CHECKPOINT,profile=self.profile,ordering=ORDER,receipt=binding,
                previous_revision=old['revision'],previous_digest=digest(old),revision=result['revision'],
                candidate_digest=digest([candidates,omitted]),operations=ops,examined=examined,
                applied=len(ops),stop=reason,result_digest=digest(result),charged_visits_before=charged_before)
            return result,wire
        allowance=LIMITS['operations']-(0 if receipt['final'] else 32)
        visit_cap=LIMITS['visits']-(0 if receipt['final'] else 128)
        wanted=replay['examined'] if replay is not None else len(candidates)
        for section,key,_ in candidates[:wanted]:
            if replay is None and (clock()>=deadline or clock()-started>=LIMITS['slice']):stop='time_limit';break
            if len(operations)>=32 or target['operations']>=allowance:stop='operation_limit';break
            entity=sources.entities.get(key,{})
            cost=1+len(entity.get('dependencies',[]))+len(entity.get('endpoints',[]))+len(entity.get('support_ids',[]))
            if entity.get('kind') in ('finding','relationship'):
                cost+=sum(1+len((e.get('assessment') or e.get('original_assessment') or {}).get('propositions',[]))
                    for e in sources.session.objective_entities)
            if target['visits']+cost>visit_cap:stop='dependency_limit';break
            target['visits']+=cost;self.last_visits=target['visits'];visited+=1
            resolving=time.perf_counter()
            result=sources.statement(key,section)
            self.timings['dependency_seconds']+=time.perf_counter()-resolving
            if result is None:stop='pending_dependency';break
            section,statement=result
            previous=target['items'].get(key)
            if previous and previous['id']==statement['id']:done.append(key);continue
            if statement['id'] not in target['admitted'] and len(target['admitted'])>=192:stop='admission_limit';break
            ref=dict(id=statement['id'],section=section,source_revision=receipt['revision'])
            dependencies=sorted(set(entity.get('endpoints',[])+entity.get('support_ids',[])+statement['objective_associations']))
            if (len(target['items'])+int(key not in target['items'])+
                sum(len(v) for k,v in target['indexes'].items() if k!=key)+len(dependencies)>LIMITS['edges']):
                stop='index_edge_limit';break
            op=dict(kind='update_coverage' if key=='coverage' else 'admit' if previous is None else
                    'retire_current_membership' if previous['section']=='current' and section!='current' else 'replace',
                    key=key,old=previous,new=ref)
            if not compact and operation_bytes+d1._size(op)+1>LIMITS['event_bytes']:
                stop='event_byte_limit';break
            operation_bytes+=d1._size(op)+1
            predecessor=deepcopy(target) if compact else None
            target['items'][key]=ref;target['operations']+=1
            target['indexes'][key]=dependencies
            if statement['id'] not in target['admitted']:target['admitted'].append(statement['id'])
            if compact:
                prospective=checkpoint(target,operations+[op],done+[key],visited,'event_byte_limit')
                if event_size(prospective[1],event)>LIMITS['event_bytes']:
                    target=predecessor;stop='event_byte_limit';break
            operations.append(op);done.append(key)
        target['pending']=[k for _,k,_ in candidates if k not in done]
        target['omitted']=omitted
        target['revision']+=1
        target['frontier']=dict(contract=FRONTIER,receipt=receipt,
            statement_contract=d1.STATEMENT,statement_rules=d1.RULES,ordering=ORDER)
        target['coverage']=dict(c1_complete=sources.session.organization['incomplete'] is False,
            final_assessment_available=bool(sources.session.original.get('original_assessment')),
            final_assessment_represented=bool(sources.session.original.get('original_assessment')) and 'original_assessment' in done,
            pending=len(target['pending']),omitted=len(omitted),accepted=len(target['items']),omissions_relevance='not_evaluated',
            relationship_frontier=sources.session.organization['coverage'].get('relationship_frontier'))
        if replay is not None:stop=replay['stop']
        target['stop']=stop
        serializing=time.perf_counter()
        cp=dict(contract=CHECKPOINT,profile=PROFILE,ordering=ORDER,receipt=receipt,
            previous_revision=old['revision'],previous_digest=digest(old),revision=target['revision'],
            candidate_digest=digest([candidates,omitted]),operations=operations,examined=visited,
            applied=len(operations),stop=stop,result_digest=digest(target),charged_visits_before=charged_before)
        if compact:target,cp=checkpoint(target,operations,done,visited,stop)
        self.peak_owned=owned_bytes((old,target,cp,candidates,self.waiting,self.omitted_keys,sources.clauses,sources.entities,
                                     locals().get('statement'),locals().get('predecessor'),locals().get('prospective'),binding))
        if d1._size(target)>LIMITS['state_bytes'] or self.peak_owned>LIMITS['heap']:return None,'memory_limit'
        self.timings['serialization_seconds']+=time.perf_counter()-serializing
        if replay is not None and (digest(cp)!=digest(replay) if compact else cp!=replay):
            raise ValueError('Explanation checkpoint mismatch')
        return (target,cp),stop


class Live:
    def __init__(self, transcript, organizer, facts):
        self.transcript=transcript;self.organizer=organizer;self.facts=facts
        self.reducer=Reducer(transcript.id,organizer.sources.view,transcript.manifest.get('explanation_profile',PROFILE))
        self.elapsed=0.;self.journal_bytes=0;self.last_receipt=None;self.checkpoint=None;self.stops=[]
        self.metrics=dict(callbacks=0,prepare_seconds=0.,append_seconds=0.,peak_owned_heap=0)
        self.visits=0;self.disabled=False
        self.observed=None
        self.diagnostics=dict(contract=diagnostic.CONTRACT,attempts=[],omitted_attempts=0,time_limit_exceeded=False)

    def _diagnostic(self, receipt, outcome, reason=None, cp=None, details=None):
        # Bounded numerical telemetry only; no source values, keys or model prose.
        rows=self.diagnostics['attempts']
        if len(rows)>=diagnostic.MAX_ATTEMPTS:
            self.diagnostics['omitted_attempts']=min(256,self.diagnostics['omitted_attempts']+1)
            return
        rows.append(dict(c1_revision=receipt['revision'],outcome=outcome,reason=diagnostic.reason(reason),
            event_size_basis='measured' if details else 'unavailable',
            candidate_operations_considered=cp['examined'] if cp else None,
            prepared_operations=cp['applied'] if cp else None,
            committed_operations=cp['applied'] if cp and outcome.startswith('committed_') else 0,
            details=details))

    def update(self, receipt, *, deadline, remaining_analysis=0, remaining_synthesis=0):
        if receipt is None or self.disabled:return
        started=time.monotonic();self.metrics['callbacks']+=1
        try:
            if self.last_receipt==receipt:return
            org=self.organizer;transcript=self.transcript
            if (receipt!=org.last_receipt or receipt['digest']!=digest(org.reducer.state()) or
                receipt['event']!=c1._frontier(transcript) or transcript.publication['status']!='confirmed' or
                receipt['run_id']!=transcript.id or receipt['read_view']!=self.reducer.state['read_view']):
                raise ValueError('Unconfirmed C1 receipt')
            if self.last_receipt and receipt['revision']<=self.last_receipt['revision']:raise ValueError('Stale C1 receipt')
            if self.observed!=receipt:
                self.reducer.observe(receipt);self.observed=deepcopy(receipt)
            if self.elapsed>=1 or started>=deadline:
                self.stops.append('time_limit');self._diagnostic(receipt,'admission_rejected','time_limit');return
            try:
                sources=Sources(transcript.manifest,org.reducer,self.facts)
                prepared,reason=self.reducer.prepare(receipt,sources,charged_visits=self.visits,
                    event=dict(sequence=transcript.count,previous=transcript.chain),
                    deadline=min(deadline,started+1-self.elapsed,started+LIMITS['slice']))
            except (ValueError,KeyError,TypeError):
                self.disabled=True;self.stops.append('preparation_failed')
                self._diagnostic(receipt,'admission_rejected','preparation_failed');return
            self.visits=max(self.visits,self.reducer.last_visits)
            for key,value in self.reducer.timings.items():self.metrics[key]=self.metrics.get(key,0.)+value
            self.metrics['prepare_seconds']+=time.monotonic()-started
            if prepared is None:
                self.stops.append(reason);self._diagnostic(receipt,'admission_rejected',reason);return
            target,cp=prepared
            heap=owned_bytes((self.reducer.state,self.reducer.waiting,self.reducer.omitted_keys,self.observed,self.last_receipt,
                              self.stops,self.metrics,self.diagnostics,target,cp,sources.clauses,sources.entities))
            self.metrics['peak_owned_heap']=max(self.metrics['peak_owned_heap'],heap,self.reducer.peak_owned)
            if heap>LIMITS['heap']:
                self.stops.append('memory_limit');self._diagnostic(receipt,'admission_rejected','memory_limit',cp);return
            event=dict(sequence=transcript.count,kind='explanation_checkpoint',data=cp,previous=transcript.chain)
            event['hash']=digest(event);size=d1._size(event)+1
            reserve=remaining_analysis*1264*1024+remaining_synthesis*96*1024+512*1024+65536
            slots=remaining_analysis*6+remaining_synthesis*5+3+(9-org.reducer.revision)+1
            details=dict(event_bytes=size,event_limit=8192,local_bytes=self.journal_bytes,
                local_remaining_bytes=max(0,65536-(0 if receipt['final'] else 8192)-self.journal_bytes),
                global_bytes=transcript.size,global_limit=MAX_BYTES,future_reserved_bytes=reserve,
                remaining_event_slots=max(0,256-transcript.count),future_reserved_slots=slots)
            admission_reason=diagnostic.admission(details)
            if admission_reason:
                # Keep legacy aggregate codes unchanged; v1 diagnostics disambiguate.
                self.stops.append('journal_reservation')
                self._diagnostic(receipt,'admission_rejected',admission_reason,cp,details);return
            if time.monotonic()>=deadline or self.elapsed+time.monotonic()-started>=1:
                self.stops.append('time_limit')
                self._diagnostic(receipt,'admission_rejected','time_limit',cp,details);return
            writing=time.monotonic()
            try:transcript.append('explanation_checkpoint',cp)
            except JournalPublicationError:
                self._diagnostic(receipt,'publication_uncertain','checkpoint_append',cp,details)
                raise
            except (OSError,ValueError):
                self._diagnostic(receipt,'publication_uncertain','checkpoint_append',cp,details)
                transcript._uncertain('explanation_checkpoint_append')
            self.metrics['append_seconds']+=time.monotonic()-writing
            try:self.reducer.commit(prepared)
            except BaseException:
                # The durable event can be replayed, but this process must not
                # append a terminal summary describing the predecessor state.
                self._diagnostic(receipt,'publication_uncertain','commit_after_publication',cp,details)
                transcript._uncertain('explanation_commit_after_publication')
            self.journal_bytes+=size;self.last_receipt=deepcopy(receipt)
            self.checkpoint=c1._frontier(transcript)
            self._diagnostic(receipt,'committed_prefix' if reason else 'committed_complete',reason,cp,details)
            if reason:self.stops.append(reason)
        finally:
            spent=time.monotonic()-started;self.elapsed+=spent
            if self.elapsed>LIMITS['seconds']:
                self.disabled=True
                self.diagnostics['time_limit_exceeded']=True
                if 'local_time_overrun' not in self.stops:self.stops.append('local_time_overrun')
            if receipt['final']:self.metrics['finalization_seconds']=self.metrics.get('finalization_seconds',0.)+spent

    def summary(self):
        upstream=not (not self.organizer.reducer.coverage.get('processing_complete',False) or self.organizer.disabled or
                      self.organizer.finalization['status']!='checkpoint_committed')
        status=diagnostic.project(self.reducer.state,self.organizer.last_receipt,
            upstream if self.organizer.last_receipt else None,finalized=True)
        return dict(contract=CONTRACT,profile=self.reducer.profile,revision=self.reducer.state['revision'],
            digest=digest(self.reducer.state),checkpoint=self.checkpoint,
            journal_bytes=self.journal_bytes,elapsed_seconds=self.elapsed,stops=self.stops,
            metrics=self.metrics,charged_visits=self.visits,coverage=self.reducer.state['coverage'],
            source_frontier=self.last_receipt['source_frontier'] if self.last_receipt else None,
            c1_revision=self.last_receipt['revision'] if self.last_receipt else None,
            stale=bool(self.organizer.last_receipt and status['currentness']!='current'),
            upstream_partial=not upstream,status=status,diagnostics=deepcopy(self.diagnostics),
            cleanup='not_confirmed_by_explanation')


class Replay:
    def __init__(self, manifest):
        if manifest['explanation_profile'] not in (PROFILE,COMPACT_PROFILE):raise ValueError('Unknown explanation profile')
        self.manifest=manifest;self.reducer=Reducer(manifest['investigation_id'],manifest['evidence_state'],manifest['explanation_profile'])
        self.receipt=None;self.sources=None;self.checkpoint=None;self.bytes=0;self.ended=False
        self.statements={};self.clauses={};self.entities={};self.used=set()
        self.diagnostics=None
        self.execution_outcome=None

    def source(self, receipt, org, facts):
        self.receipt=receipt;self.sources=Sources(self.manifest,org,facts)
        self.reducer.observe(receipt)

    def consume(self,event):
        cp=event['data']
        expected=receipt_reference(self.receipt) if self.receipt is not None and self.reducer.profile==COMPACT_PROFILE else self.receipt
        same_receipt=(digest(cp['receipt'])==digest(expected) if self.reducer.profile==COMPACT_PROFILE else cp['receipt']==expected)
        if (self.receipt is None or not same_receipt or
            self.receipt['revision'] in self.used or event['sequence']!=self.receipt['event']['sequence']+1 or
            event['previous']!=self.receipt['event']['hash']):raise ValueError('Invalid explanation receipt')
        size=d1._size(event)+1
        if size>8192 or self.bytes+size>65536:raise ValueError('Explanation journal budget')
        prepared,_=self.reducer.prepare(self.receipt,self.sources,replay=cp,event=event)
        if prepared is None:raise ValueError('Unreplayable explanation checkpoint')
        target,_=prepared
        for op in cp['operations']:
            key=op['key'];section,statement=self.sources.statement(key,op['new']['section'])
            self.statements[key]=deepcopy(statement)
            if key in self.sources.entities:self.entities[key]=deepcopy(self.sources.entities[key])
            if key=='original_assessment':self.entities[self.sources.session.original['id']]=deepcopy(self.sources.session.original)
            for dep in statement['dependencies']:
                cid=dep.get('source_unit') or dep.get('clause_id')
                if cid in self.sources.clauses:self.clauses[cid]=deepcopy(self.sources.clauses[cid])
            if key in self.sources.clauses:self.clauses[key]=deepcopy(self.sources.clauses[key])
        self.reducer.state=target;self.bytes+=size;self.used.add(self.receipt['revision'])
        self.reducer.waiting=set(target['pending'])
        self.reducer.omitted_keys=set(target['omitted'])
        self.checkpoint=dict(sequence=event['sequence'],hash=event['hash'])

    def terminal(self,data):
        summary=data.get('explanation')
        if summary is None or summary['profile']!=self.reducer.profile or summary['digest']!=digest(self.reducer.state) or summary['revision']!=self.reducer.state['revision'] or summary['journal_bytes']!=self.bytes or summary['checkpoint']!=self.checkpoint:
            raise ValueError('Invalid terminal explanation')
        if type(summary.get('charged_visits')) is not int or not self.reducer.state['visits']<=summary['charged_visits']<=LIMITS['visits']:
            raise ValueError('Invalid terminal explanation resources')
        if 'diagnostics' in summary:
            diagnostic.validate(summary['diagnostics'])
            self.diagnostics=deepcopy(summary['diagnostics'])
        self.execution_outcome=data.get('termination')
        self.ended=True

    def finish(self,organization):
        state=deepcopy(self.reducer.state)
        status=diagnostic.project(state,self.receipt,not organization['incomplete'] if self.receipt else None,
                                  finalized=self.ended)
        stale=bool(self.receipt and status['currentness']!='current')
        return dict(state=state,checkpoint=self.checkpoint,journal_bytes=self.bytes,mode='persisted',
            incomplete=not self.ended or stale or bool(state['pending']) or bool(state['omitted']) or organization['incomplete'],
            stale=stale,terminal_present=self.ended,statements=self.statements,
            clauses=self.clauses,entities=self.entities,status=status,diagnostics=self.diagnostics,
            execution_outcome=self.execution_outcome)


def reconstruct(root, identity):
    from .transcript import load
    manifest,_=load(root,identity)
    result=c1.reconstruct(root,identity,_explanation=True)
    if manifest.get('explanation_profile') is None:
        return dict(mode='retrospective',enabled=False,persisted_checkpoints=0)
    return result['explanation']


def session(root, identity):
    from .transcript import load
    manifest,_=load(root,identity)
    result=reconstruct(root,identity)
    if result['mode']!='persisted':raise ValueError('No persisted explanation profile; use retrospective --explanation')
    state=result['state'];s=object.__new__(d1._Session)
    s.manifest=manifest;s.clauses=result['clauses'];s.entities=result['entities']
    s.factual=dict(clauses=list(s.clauses.values()),evidence_state=state['read_view'])
    s.original=next((v for v in s.entities.values() if v.get('role')=='original_question'),{})
    s.organization=dict(entities=list(s.entities.values()),links=[],coverage=state['coverage'],
        read_view=state['read_view'],state_digest=digest(state),incomplete=result['incomplete'])
    s.binding=dict(contract=CONTRACT,profile=state['profile'],run_id=identity,read_view=state['read_view'],
        revision=state['revision'],digest=digest(state),checkpoint=result['checkpoint'],statement_rules=d1.RULES,ordering=ORDER)
    s.candidates=[(v['section'],k) for k,v in sorted(state['items'].items())]
    s.context_candidates=set(state['items'])
    s._statement=lambda section,key:result['statements'][key]
    s._seal=lambda:digest([d1._Session._seal(s),result['statements']])
    s.seal=s._seal()
    return s,result


def page(s,result,cursor=None,*,canonical=False):
    from . import explanation_display as display
    view=d1.page(s,cursor) if canonical else display.page(s,cursor,byte_limit=14*1024)
    view['mode']='persisted'
    state=result['state'];frontier=state['frontier']
    view['live_status']=dict(enabled=True,revision=state['revision'],checkpoint=result['checkpoint'],
        c1_revision=frontier['receipt']['revision'] if frontier else None,
        source_frontier=frontier['receipt']['source_frontier'] if frontier else None,
        accepted=len(state['items']),pending=len(state['pending']),omitted=len(state['omitted']),stale=result['stale'],
        relationship_frontier=state['coverage'].get('relationship_frontier'),
        incomplete=result['incomplete'],final_assessment_available=state['coverage'].get('final_assessment_available',False),
        final_assessment_represented=state['coverage'].get('final_assessment_represented',False),
        resource_stop=state['stop'],status=result['status'],execution_outcome=result['execution_outcome'],
        cleanup='not_confirmed_by_explanation')
    if d1._size(view)>d1.PAGE_BYTES:raise ValueError('Live display budget')
    return view


def render(view):
    from . import explanation_display as display
    status=view['live_status']
    header=('Local explanation enabled; persisted revision '+str(status['revision'])+'.\n'+
            '\n'.join(diagnostic.lines(status['status']))+'\nRecorded investigation outcome: '+
            d1._safe(status['execution_outcome'] or 'unavailable (no terminal record)')+
            '.\nCleanup not confirmed by explanation.\n')
    result=header+(d1.render(view) if view['contract']==d1.CONTRACT else display.render(view))
    if len(result.encode('utf-8'))>d1.PAGE_BYTES:raise ValueError('Live text budget')
    return result

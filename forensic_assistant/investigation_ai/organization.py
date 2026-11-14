"""C1 reference-only organization. No provider, database, or authorization execution."""
from copy import deepcopy
import time

from . import synthesis as s1, relationships as s2, decomposition
from .projection import same
from .state import encoded, State, Budget
from .transcript import digest, load, validate_evidence_state, MAX_BYTES

CONTRACT = 'investigative-organization-v1'
RULES = 'organization-rules-v2'
CHECKPOINT = 'organization-checkpoint-v1'
DEPENDENCY = 'organization-dependency-v1'
PROFILE = 'local-organization-v2'
FINALIZATION = 'organization-finalization-v1'
FRONTIER = 'relationship-frontier-v1'
LIMITS = dict(entities=256, links=512, revisions=8, checkpoints=9, per_checkpoint=128,
              operations=1024, visits=4096, view_bytes=256*1024, event_bytes=8192,
              journal_bytes=64*1024, seconds=2)


class LegacyOrganizationProfile(ValueError):
    """A v1 checkpoint must not be replayed with v2 membership rules."""


def _bytes(value):
    return len(encoded(value).encode('utf-8'))


def _text(value):
    # JSON escaping preserves Unicode and makes terminal controls inert.
    import json
    return json.dumps(str(value), ensure_ascii=False)[1:-1]


class _Sources:
    """Private adapter fed only by the existing accepted-delta/decision validators."""
    def __init__(self, manifest):
        self.manifest = manifest
        self.view = validate_evidence_state(manifest['evidence_state'])
        self.entities = {}
        self.links = {}
        self.fact_ids = set()
        self.theme_members = set()
        self.b2 = {}
        self.requests = {}
        self.related = None
        self.coverage = {}
        self.question_id = digest([CONTRACT, manifest['investigation_id'], 'question'])
        self._entity(self.question_id, 'question', 'analyst_input_unverified',
                     {'contract':'manifest', 'id':manifest['investigation_id']},
                     text=manifest['question'], role='original_question')

    def _entity(self, identity, kind, classification, origin, **fields):
        value = dict(id=identity, kind=kind, classification=classification, status='active',
                     run_id=self.manifest['investigation_id'], read_view=self.view,
                     introduced_by=origin, **fields)
        self.entities[identity] = value
        return identity

    def _edge(self, kind, left, right, classification, origin):
        if left not in self.entities or right not in self.entities:
            raise ValueError('Organization endpoint unavailable')
        body = dict(kind=kind, endpoints=[left,right], classification=classification,
                    origin=origin, read_view=self.view)
        self.links[digest(body)] = dict(body,id=digest(body))

    def _dependency(self, clause):
        support = clause['supports'][0]
        return dict(contract=DEPENDENCY, source_contract=s1.CONTRACT, unit_id=clause['id'],
                    evidence_id=support['evidence_id'], read_view=self.view,
                    pointer=support.get('field',{}).get('pointer'),
                    descriptor={k:deepcopy(v) for k,v in support.get('field',{}).items() if k!='value'},
                    interpretation_id=support.get('interpretation_id'),
                    provenance=deepcopy(support['provenance']),
                    source_context=deepcopy(support['context'].get('source_context')),
                    lineage=deepcopy(clause['lineage']))

    def analysis(self, reducer, delta, exposure, source_event=None):
        if type(reducer) is not s1._Reducer or reducer.previous != delta['id']:
            raise ValueError('Expected accepted reducer frontier')
        if delta['disclosure_sha256'] != digest(exposure) or not same(delta['evidence_state'],self.view):
            raise ValueError('Organization delta binding')
        factual = reducer.finish()
        self.related = s2._build(factual)  # Existing bounded derivation, not a new rule.
        for clause in factual['clauses']:
            s1._validate_render_clause(clause)
            if not same(clause['evidence_state'],self.view):raise ValueError('Cross-view clause')
            cid=clause['id']; dep=self._dependency(clause)
            self.fact_ids.add(cid)
            self._entity(cid,'finding',clause['validation'],
                         {'contract':s1.CONTRACT,'id':cid}, predicate=clause['predicate'],
                         rule=clause['rule'], finding_type=clause['type'], dependencies=[dep],
                         qualifications=clause['qualifications'])
            bucket=digest([RULES,'navigation',clause['predicate']])
            self._entity(bucket,'theme','organizational_only',{'contract':RULES,'id':bucket},
                         text=clause['predicate'], role='navigation')
            self._edge('contains_reference',bucket,cid,'navigation_only',{'contract':RULES})
            self._edge('context_for',cid,self.question_id,'organizational_only',{'contract':RULES})
        frontier=dict(contract=FRONTIER,delta_id=delta['id'],batch=delta['batch'],
                      event=deepcopy(source_event),event_status='recorded' if source_event else 'unknown',
                      disclosure_sha256=delta['disclosure_sha256'])
        current={rel['id'] for rel in self.related['relationships']}
        for entity in self.entities.values():
            if entity['kind']=='relationship':
                entity['current_final']=entity['id'] in current
                entity['membership']='current_final' if entity['current_final'] else 'historical_only'
                entity['membership_frontier']=delta['id']
        for rel in self.related['relationships']:
            rid=rel['id']
            prior=self.entities.get(rid,{})
            present=deepcopy(prior.get('present_frontiers',[]))
            if not any(f['delta_id']==delta['id'] for f in present):present.append(frontier)
            self._entity(rid,'relationship','validated_recorded_comparison',
                         {'contract':s2.CONTRACT,'id':rid}, predicate=rel['predicate'],rule=rel['rule'],
                         endpoints=rel['endpoints'], assumptions=rel['assumptions'],
                         qualifications=rel['qualifications'], semantics=rel['semantics'],
                         derivation='deterministic_accepted_frontier_reconstruction',
                         first_frontier=present[0]['delta_id'],last_frontier=present[-1]['delta_id'],
                         present_frontiers=present,current_final=True,membership='current_final',
                         membership_frontier=delta['id'],
                         lineage_references=list(rel['endpoints']))
            for endpoint in rel['endpoints']:
                self._edge('registered_conflict' if rel['predicate']=='incompatible_recorded_field'
                           else 'references_validated_relationship',rid,endpoint,
                           'validated_recorded_comparison',{'contract':s2.CONTRACT,'id':rid})
        origin={'contract':'analysis-delta-v1','id':delta['id'],'batch':delta['batch'],
                'request_ordinal':delta['counters']['ai_requests'],
                'disclosure_sha256':delta['disclosure_sha256']}
        for kind, rows in [('hypothesis',delta['findings']['hypotheses']),
                           ('question',delta['findings']['model_proposed_unknowns'])]:
            for index,row in enumerate(rows):
                oid=digest([CONTRACT,origin,kind,index])
                source={**origin,'index':index}
                body=dict(text=row if isinstance(row,str) else row['statement'],
                          alternatives=[] if isinstance(row,str) else row['alternatives'],
                          support_granularity='record_only',
                          dependencies=[] if isinstance(row,str) else [dict(contract=DEPENDENCY,
                              evidence_id=eid,read_view=self.view,source_contract='analysis-delta-v1',
                              unit_id=delta['id'],role='model_citation_not_entailment') for eid in row['evidence_ids']],
                          semantic_key=digest([kind,row]), role='analysis_proposal')
                self._entity(oid,kind,'unverified',source,**body)
                self._edge('context_for',oid,self.question_id,'organizational_only',source)
        self.coverage.update(observations=sum(c['type']=='observation' for c in factual['clauses']),
                             interpretations=sum(c['type']=='deterministic_interpretation' for c in factual['clauses']),
                             relationships=len(self.related['relationships']),
                             relationship_coverage=deepcopy(self.related['coverage']),
                             source_clock_limitations=deepcopy(self.related['limitations']),
                             validated_batches=reducer.batches)
        self.coverage['relationships_meaning']='latest_s2_snapshot'
        self.coverage['relationship_frontier']=delta['id']

    def synthesis(self, packet, decision):
        # Caller has already recomputed the exact decision with the B2 validator.
        if decision['status']!='accepted':raise ValueError('Rejected proposal is not organization input')
        body=packet['content']
        if not same(body['view'],self.view):raise ValueError('Cross-packet view')
        by_alias={s['alias']:s for s in body['supports']}
        request_number=self.requests.setdefault(body['request_id'],len(self.requests)+1)
        for unit in decision['units']:
            item=unit['item'];uid=unit['id'];refs=[];legend=[]
            for alias in item['support_refs']:
                support=by_alias[alias];cid=support['clause_id']
                if cid not in self.fact_ids:raise ValueError('Unavailable accepted support')
                refs.append(cid)
                legend.append(dict(request_id=body['request_id'],packet_digest=packet['packet_digest'],
                    alias=alias,clause_id=cid,evidence_id=support['evidence_id'],
                    pointer=support['field']['pointer'],request_number=request_number,
                    label=support['field'].get('label',support['field']['pointer'])))
            origin=dict(contract='synthesis-proposal-v1',request_id=body['request_id'],
                        packet_digest=packet['packet_digest'],id=uid)
            self._entity(uid,'theme' if item['kind']=='group' else 'hypothesis' if item['kind']=='hypothesis'
                         else 'question' if item['kind'] in ('question','next_objective') else 'proposal',
                         unit['classification'],origin,role='b2_'+item['kind'],
                         text=deepcopy(item['payload']), support_ids=refs, alias_legend=legend,
                         binding=deepcopy(body['binding']),semantic_key=unit['semantic_key'],
                         validated_relationship=unit['validated_relationship'])
            self.b2[uid]=unit['semantic_key']
            self._edge('context_for',uid,self.question_id,'organizational_only',origin)
            if unit['validated_relationship'] is not None:
                self._edge('references_validated_relationship',uid,unit['validated_relationship'],
                           'reference_only_not_prose_entailment',origin)
            for cid in refs:
                self._edge('proposed_member' if item['kind']=='group' else 'cites_original_support',
                           uid,cid,'unverified',origin)
                if item['kind']=='group':self.theme_members.add(cid)
        self.coverage['accepted_b2_proposals']=len(self.b2)

    def final(self, assessment, summary, synthesis_result):
        self._entity(self.question_id,'question','analyst_input_unverified',
                     {'contract':'manifest','id':self.manifest['investigation_id']},
                     text=self.manifest['question'],role='original_question',
                     original_assessment=deepcopy(assessment['original_assessment']),
                     limitations=assessment['limitations'])
        for row in assessment['scoped_objectives']:
            objective=row['objective'];oid=objective['id']
            self._entity(oid,'question','provisional_intent',
                         {'contract':decomposition.CONTRACT,'id':oid},role='provisional_objective',
                         text=objective['text'],objective=deepcopy(objective),
                         assessment=deepcopy(row['assessment']),limitations=[row['limitation']] if row['limitation'] else [])
            self._edge('asks_about',oid,self.question_id,'provisional_intent',{'contract':decomposition.CONTRACT})
        proposals=[e for e in self.entities.values() if e.get('semantic_key')]
        groups={}
        for e in sorted(proposals,key=lambda e:e['id']):
            prior=groups.setdefault(e['semantic_key'],e['id'])
            if prior!=e['id']:self._edge('duplicate_of',e['id'],prior,'organizational_only',{'contract':RULES})
        self.coverage.update(authorized_references=len(self.manifest['authorization']['evidence_ids']),
            examined_references=len(summary.get('inspected_ids',[])),
            examined_families=summary.get('inspected_artifact_families',[]),
            rejected_proposals=summary.get('rejected_requests',0),
            duplicate_proposals=len(proposals)-len(groups),
            unresolved_objectives=sum(row['assessment'] is None for row in assessment['scoped_objectives']),
            synthesis_omissions=deepcopy(synthesis_result.get('omissions',[])),
            original_question_fully_answered=False,forensic_completeness='not_established')
        self.coverage['accepted_model_proposals']=len(proposals)
        self.coverage['unrepresented_supports']=sorted(self.fact_ids-{cid for e in self.entities.values() for cid in e.get('support_ids',[])})
        self.coverage['unassessed_candidates']=self.related['coverage']['unassessed_candidates'] if self.related else 0
        gap_id=digest([RULES,self.manifest['investigation_id'],'recorded_coverage'])
        self._entity(gap_id,'gap','recorded_limitation',{'contract':RULES,'id':gap_id},
                     text='Coverage limitations do not establish absence of evidence.',
                     unresolved_objectives=self.coverage['unresolved_objectives'],
                     unassessed_candidates=self.coverage['unassessed_candidates'])
        self._edge('context_for',gap_id,self.question_id,'recorded_limitation',{'contract':RULES})


class _Reducer:
    def __init__(self, sources, *, clock=time.monotonic):
        self.sources=sources;self.clock=clock;self.elapsed=0.;self.operations=0;self.visits=0
        self.entities={};self.links={};self.revisions={};self.revision=0;self.frontier=None
        self.journal_bytes=0;self.stops=[];self.last_checkpoint=None;self.coverage={}

    def state(self):
        return dict(contract=CONTRACT,rules=RULES,run_id=self.sources.manifest['investigation_id'],
            read_view=self.sources.view,revision=self.revision,frontier=self.frontier,
            entities=[self.entities[k] for k in sorted(self.entities)],
            links=[self.links[k] for k in sorted(self.links)],entity_revisions=self.revisions,
            coverage=self.coverage,operations=self.operations,dependency_visits=self.visits)

    def candidates(self):
        # No prose comparison: stable-ID dictionary diff, entities before links.
        priority={'finding':0,'question':1,'theme':2,'relationship':3,'hypothesis':4,'proposal':5,'gap':6}
        ordered=sorted(self.sources.entities.items(),key=lambda row:(priority[row[1]['kind']],row[0]))
        # B2 question/theme entities also carry supports; all factual nodes precede them.
        return [('entity',k,v) for k,v in ordered if not same(self.entities.get(k),v)] + [
            ('link',k,v) for k,v in sorted(self.sources.links.items()) if k not in self.links]

    def prepare(self, frontier, *, final=False, deadline=float('inf'), replay=None):
        started=self.clock();previous=digest(self.state());candidates=self.candidates()
        if self.revision>=LIMITS['checkpoints']:return None,'checkpoint_limit'
        target=deepcopy(self);target.sources=self.sources;target.clock=self.clock
        count=0;reason=None;oplimit=LIMITS['operations']-(0 if final else 128)
        wanted=replay['applied'] if replay is not None else LIMITS['per_checkpoint']
        if type(wanted) is not int or not 0<=wanted<=LIMITS['per_checkpoint']:raise ValueError('Invalid checkpoint prefix')
        for kind,key,value in candidates:
            if count>=wanted:reason='operation_prefix';break
            if replay is None and (self.elapsed+self.clock()-started>=2 or self.clock()>=deadline):reason='time_limit';break
            if target.operations>=oplimit:reason='operation_limit';break
            visits=1+len(value.get('dependencies',[]))+len(value.get('endpoints',[]))+len(value.get('support_ids',[]))
            if target.visits+visits>LIMITS['visits']:reason='dependency_limit';break
            table=target.entities if kind=='entity' else target.links
            if key not in table and len(table)>=LIMITS['entities' if kind=='entity' else 'links']:reason=kind+'_limit';break
            revision=target.revisions.get(key,0)+1
            if revision>LIMITS['revisions']:reason='revision_limit';break
            if kind=='entity' and not set(value.get('support_ids',[])+value.get('endpoints',[]))<=set(target.entities):
                reason='unavailable_endpoint';break
            if kind=='link' and not set(value['endpoints'])<=set(target.entities):reason='unavailable_endpoint';break
            old=table.get(key);table[key]=deepcopy(value)
            if _bytes(target.state())>LIMITS['view_bytes']-16384:
                if old is None:del table[key]
                else:table[key]=old
                reason='view_byte_limit';break
            target.revisions[key]=revision;target.operations+=1;target.visits+=visits;count+=1
        else:reason=None
        if replay is not None and count!=wanted:raise ValueError('Impossible checkpoint prefix')
        target.revision+=1;target.frontier=deepcopy(frontier)
        finding_ids={k for k,v in target.entities.items() if v['kind']=='finding'}
        member_ids={e['endpoints'][1] for e in target.links.values() if e['kind']=='proposed_member'}
        target.coverage={**deepcopy(self.sources.coverage),
            'organized_findings':len(finding_ids),'ai_theme_members':len(finding_ids & member_ids),
            'unassigned_findings':sorted(finding_ids-member_ids),
            'known_unprocessed':len(candidates)-count,'processing_complete':count==len(candidates),
            'unavailable_support':0,'relevance_of_omissions':'not_evaluated'}
        relationships=[e for e in target.entities.values() if e['kind']=='relationship']
        assessed=[e for e in relationships if e.get('membership_frontier')==target.coverage.get('relationship_frontier')]
        target.coverage.update(relationships_current_final=sum(e.get('current_final',False) for e in assessed),
            relationships_historical_only=sum(not e.get('current_final',False) for e in assessed),
            relationships_accumulated_distinct=len(relationships),
            relationships_membership_pending=len(relationships)-len(assessed))
        if _bytes(target.state())>LIMITS['view_bytes']:return None,'view_byte_limit'
        cp=dict(contract=CHECKPOINT,profile=PROFILE,rules=RULES,frontier=frontier,
                previous_revision=self.revision,previous_digest=previous,
                candidate_digest=digest(candidates),ordering='dependency_entities_then_links_v1',
                applied=count,revision=target.revision,result_digest=digest(target.state()),
                coverage=target.coverage,stop_reason=reason,final=final)
        # Detailed coverage belongs in reconstructed view, not repeated checkpoint payload.
        cp['coverage']={k:target.coverage[k] for k in ('organized_findings','ai_theme_members','known_unprocessed','processing_complete')}
        if replay is not None:
            if replay['stop_reason'] not in (None,'operation_prefix','time_limit','operation_limit','dependency_limit',
                    'entity_limit','link_limit','revision_limit','unavailable_endpoint','view_byte_limit'):
                raise ValueError('Unknown organization stop reason')
            cp['stop_reason']=replay['stop_reason']
            if not same(cp,replay):raise ValueError('Organization checkpoint mismatch')
        target.elapsed=self.elapsed+max(0,self.clock()-started)
        return (target,cp),reason

    def commit(self, prepared):
        target,cp=prepared
        if cp['previous_digest']!=digest(self.state()):raise ValueError('Stale organization revision')
        self.__dict__.update(target.__dict__);self.last_checkpoint=deepcopy(cp)


def _frontier(transcript):
    return dict(sequence=transcript.count-1,hash=transcript.chain)


def commit_receipt(before, after, checkpoint, event):
    """Reference-only receipt, constructed at the confirmed checkpoint boundary."""
    changed={kind:sorted(k for k,v in after[kind].items() if before[kind].get(k)!=v)
             for kind in ('entities','links')}
    return dict(contract='organization-commit-v1',profile=PROFILE,rules=RULES,
        run_id=after['run_id'],read_view=after['read_view'],revision=checkpoint['revision'],
        previous_digest=checkpoint['previous_digest'],digest=checkpoint['result_digest'],
        source_frontier=checkpoint['frontier'],event=event,changed=changed,final=checkpoint['final'])


def _receipt_state(reducer):
    return dict(run_id=reducer.sources.manifest['investigation_id'],read_view=reducer.sources.view,
                entities=reducer.entities,links=reducer.links)


class Live:
    """Lower-priority local observer. Call only after authoritative event persistence."""
    def __init__(self, transcript):
        self.transcript=transcript;self.sources=_Sources(transcript.manifest)
        self.reducer=_Reducer(self.sources);self.disabled=False
        self.finalization=dict(contract=FINALIZATION,status='unavailable',anchor=False,checkpoint=False)
        self.last_receipt=None

    def update(self, source_update, *, final=False, deadline=float('inf'), remaining_analysis=0, remaining_synthesis=0):
        if final:self.finalization['status']='unavailable' if self.disabled else 'skipped_resource'
        if self.disabled:return
        started=time.monotonic()
        previous_elapsed=self.reducer.elapsed
        try:
            if self.reducer.elapsed>=2 or started>=deadline:
                self.reducer.stops.append('time_limit');return
            source_update()
            self.reducer.elapsed+=time.monotonic()-started
            if final:
                # Tiny finalization anchor; authoritative content stays in existing events.
                if self.transcript.size+1024+512*1024>MAX_BYTES or self.transcript.count+3>256:
                    self.reducer.stops.append('journal_reservation');return
                before=self.transcript.size
                self.finalization['status']='anchor_append_failed'
                self.transcript.append('organization_final',{'profile':PROFILE})
                self.finalization.update(anchor=True,status='anchor_committed')
                self.reducer.journal_bytes+=self.transcript.size-before
            prepared,reason=self.reducer.prepare(_frontier(self.transcript),final=final,deadline=deadline)
            if prepared is None:self.reducer.stops.append(reason);return
            target,cp=prepared
            event=dict(sequence=self.transcript.count,kind='organization_checkpoint',data=cp,previous=self.transcript.chain)
            event['hash']=digest(event);size=_bytes(event)+1
            # Worst-size authoritative events take precedence. No new journal capacity.
            mandatory=(remaining_analysis*6+remaining_synthesis*5+3)
            # Result and delta may each reach the journal's per-event ceiling.
            # Other analysis records are bounded by prompt/response contracts.
            # B2 already reserves a 96-KiB complete cycle in its own admission gate.
            reserve=remaining_analysis*(2*600+64)*1024+remaining_synthesis*96*1024+512*1024+64*1024
            allowance=64*1024-(0 if final else 8192)
            if (size>8192 or self.reducer.journal_bytes+size>allowance or
                self.transcript.size+size+reserve>MAX_BYTES or
                self.transcript.count+1+mandatory>256):
                self.reducer.stops.append('journal_reservation');return
            self.transcript.append('organization_checkpoint',cp)
            target.journal_bytes=self.reducer.journal_bytes+size
            before=_receipt_state(self.reducer)
            self.reducer.commit(prepared)
            if final:self.finalization.update(checkpoint=True,status='checkpoint_committed')
            self.last_receipt=commit_receipt(before,_receipt_state(self.reducer),cp,_frontier(self.transcript))
            return deepcopy(self.last_receipt)
        except KeyboardInterrupt:
            if final:self.finalization['status']='interrupted'
            self.reducer.stops.append('cancelled');raise
        except (ValueError,OSError,RuntimeError):
            if final and self.finalization['anchor']:self.finalization['status']='final_checkpoint_failed'
            self.reducer.stops.append('organization_failed');self.disabled=True
        finally:
            # Charge skipped preparation and durable I/O too, not only committed work.
            self.reducer.elapsed=previous_elapsed+max(0,time.monotonic()-started)

    def summary(self):
        return dict(contract=CONTRACT,profile=PROFILE,revision=self.reducer.revision,
                    digest=digest(self.reducer.state()),frontier=self.reducer.frontier,
                    elapsed_seconds=round(self.reducer.elapsed,6),view_bytes=_bytes(self.reducer.state()),
                    journal_bytes=self.reducer.journal_bytes,stops=sorted(set(self.reducer.stops)),
                    finalization=deepcopy(self.finalization))


def reconstruct(root, identity, *, _explanation=False):
    """Validate original B2 history first; no grant renewal, provider or database access."""
    from . import synthesis_consumer as b2, autonomous
    manifest,events=load(root,identity)
    validated_b2=b2.reconstruct(root,identity,_validate_organization=False)
    return _replay(manifest, events, validated_b2, _explanation=_explanation)


def _replay(manifest, events, validated_b2, *, _explanation=False):
    """Replay C1/D1 against the same validated B2 source frontier."""
    from . import synthesis_consumer as b2, autonomous
    identity = manifest['investigation_id']
    explanation_observer=None
    if manifest.get('explanation_profile') is not None:
        from .explanation_live import Replay
        explanation_observer=Replay(manifest)
    profile=manifest.get('organization_profile')
    if profile=='local-organization-v1':
        raise LegacyOrganizationProfile('Legacy C1 v1 checkpoints require their original rules; v2 will not reinterpret their digests')
    if profile not in (None,PROFILE):raise ValueError('Unknown organization profile')
    if manifest.get('engine')!=b2.ENGINE:raise ValueError('Organization requires B2 history')
    sources=_Sources(manifest);org=_Reducer(sources);facts=s1._Reducer();state=State(Budget())
    exposure=None;packet=None;last_source=None;terminal=None
    pending=False;mode='recorded' if profile else 'retrospective';last_kind=None;final_seen=False;stops=[]
    final_checkpoint=False;final_diagnostic=None
    for event in events:
        work_started=time.monotonic();previous_elapsed=org.elapsed
        kind,data=event['kind'],event['data']
        if kind=='result':state.ingest(data['response']['result'],operation=data['operation'])
        elif kind=='exposure':exposure=data['content'];state.disclose(exposure)
        elif kind=='validated_delta':
            facts.consume(state,data,exposure)
            sources.analysis(facts,data,exposure,dict(sequence=event['sequence'],hash=event['hash']));pending=True
        elif kind=='synthesis_prepared':packet=data['packet']
        elif kind=='synthesis_decision' and data['status']=='accepted':
            sources.synthesis(packet,data);pending=True
        elif kind=='organization_final':
            if not profile:raise ValueError('Unprofiled organization final')
            if final_seen:raise ValueError('Duplicate organization final')
            final_seen=True
            if data!={'profile':PROFILE}:raise ValueError('Invalid organization final anchor')
            decision=decomposition.validate_journal(manifest,events)
            related=sources.related if sources.related is not None else s2._build(facts.finish())
            expected=decomposition.assess(manifest['question'],identity,related,decision)
            final_synthesis=validated_b2
            if facts.batches==0 and not any(e['kind']=='terminal' for e in events):
                # Live execution never plans B2 without accepted analysis. B2's
                # retrospective preview is not evidence that planning took place.
                final_synthesis={**validated_b2,'omissions':[]}
            sources.final(expected,state.summary(),final_synthesis);pending=True
            org.journal_bytes+=_bytes(event)+1
        elif kind=='rejected':state.rejected+=1
        elif kind=='organization_checkpoint':
            size=_bytes(event)+1
            if (not profile or not pending or last_source is None or data['frontier']!=last_source
                    or type(data['final']) is not bool or data['final']!=(last_kind=='organization_final')
                    or size>8192 or org.journal_bytes+size>64*1024):
                raise ValueError('Invalid organization frontier')
            prepared,_=org.prepare(last_source,final=data['final'],replay=data)
            if prepared is None:raise ValueError('Unreplayable checkpoint')
            before=_receipt_state(org)
            org.commit(prepared);org.journal_bytes+=size;pending=False
            if explanation_observer is not None:
                receipt=commit_receipt(before,_receipt_state(org),data,dict(sequence=event['sequence'],hash=event['hash']))
                explanation_observer.source(receipt,org,facts)
            if data['final']:final_checkpoint=True
            if data['stop_reason']:stops.append(data['stop_reason'])
        elif kind=='explanation_checkpoint':
            if explanation_observer is None:raise ValueError('Unprofiled explanation checkpoint')
            explanation_observer.consume(event)
        elif kind=='terminal':
            if explanation_observer is not None:explanation_observer.terminal(data)
            terminal=data
            if not profile:
                sources.final(data['question_decomposition'],data['state'],data['synthesis']);pending=True
            else:
                summary=data.get('organization')
                if (summary is None or summary['digest']!=digest(org.state()) or summary['revision']!=org.revision
                        or summary['profile']!=PROFILE or summary['contract']!=CONTRACT
                        or summary['frontier']!=org.frontier or summary['journal_bytes']!=org.journal_bytes):
                    raise ValueError('Invalid terminal organization')
                stops.extend(summary.get('stops',[]))
                final_diagnostic=summary.get('finalization')
                if final_diagnostic is not None:
                    if (set(final_diagnostic)!={'contract','status','anchor','checkpoint'} or
                        final_diagnostic['contract']!=FINALIZATION or
                        type(final_diagnostic['anchor']) is not bool or type(final_diagnostic['checkpoint']) is not bool or
                        final_diagnostic['anchor']!=final_seen or final_diagnostic['checkpoint']!=final_checkpoint or
                        final_diagnostic['status'] not in ('unavailable','skipped_resource','anchor_append_failed',
                            'anchor_committed','checkpoint_committed','interrupted','final_checkpoint_failed') or
                        (final_diagnostic['status']=='checkpoint_committed')!=final_checkpoint):
                        raise ValueError('Invalid organization finalization diagnostic')
        if kind!='organization_checkpoint':
            last_source=dict(sequence=event['sequence'],hash=event['hash']);last_kind=kind
        if mode=='retrospective' and pending:
            org.elapsed=previous_elapsed+max(0,time.monotonic()-work_started)
            prepared,reason=org.prepare(last_source,final=kind=='terminal')
            if reason:stops.append(reason)
            if prepared is not None:org.commit(prepared)
            else:org.stops.append(reason)
            pending=False
        org.elapsed=previous_elapsed+max(0,time.monotonic()-work_started)
    result=org.state()
    result.update(mode=mode,state_digest=digest(org.state()),
                  processing_stops=sorted(set(stops+org.stops)),
                  resource_use=dict(operations=org.operations,dependency_visits=org.visits,
                      retrospective_revisions=org.revision if not profile else 0,
                      persisted_organization_checkpoints=sum(e['kind']=='organization_checkpoint' for e in events),
                      organization_revision=org.revision,
                      organization_processing_complete=not pending and result['coverage'].get('processing_complete',False)
                          and (not profile or final_checkpoint)),
                  incomplete=terminal is None or pending or not result['coverage'].get('processing_complete',False)
                      or bool(profile and not final_checkpoint),
                  finalization=dict(contract=FINALIZATION,anchor_committed=final_seen,
                      checkpoint_committed=final_checkpoint,terminal_present=terminal is not None,
                      final_s3_available=bool(terminal and terminal.get('question_decomposition')),
                      recorded_diagnostic=final_diagnostic,forensic_completeness='not_established'),
                  limitations=['Organization is not evidence, authorization, forensic completeness or a final report.',
                               'Recorded read view only; current case equality and parent cleanup are not established.'])
    if _bytes(result)>LIMITS['view_bytes']:raise ValueError('Organization view byte limit')
    if explanation_observer is not None and _explanation:
        result['explanation']=explanation_observer.finish(result)
    return result


def render_view(view):
    lines=['Investigation organization — '+view['mode'],
           '  Reference organization only; no new forensic conclusions.']
    entities=view['entities'];labels={e['id']:'F'+str(i+1) for i,e in enumerate(e for e in entities if e['kind']=='finding')}
    caveats=set()
    def membership(e):
        if e.get('membership_frontier')!=view['coverage'].get('relationship_frontier'):return 'pending'
        return e['membership']
    sections=[('Original question and provisional objectives',lambda e:e['kind']=='question' and e.get('role') in ('original_question','provisional_objective')),
              ('Validated finding references and deterministic interpretations',lambda e:e['kind']=='finding'),
              ('Current validated S2 relationships',lambda e:e['kind']=='relationship' and membership(e)=='current_final'),
              ('Earlier-frontier relationships — historical derivations',lambda e:e['kind']=='relationship' and membership(e)=='historical_only'),
              ('Relationship membership pending — organization incomplete',lambda e:e['kind']=='relationship' and membership(e)=='pending'),
              ('AI-proposed themes — unverified',lambda e:e.get('role')=='b2_group'),
              ('AI-proposed relationship explanations — unverified',lambda e:e['kind']=='proposal'),
              ('Hypotheses and alternatives — unverified',lambda e:e['kind']=='hypothesis'),
              ('Outstanding questions / next objectives — unverified',lambda e:e['kind']=='question' and e.get('role') not in ('original_question','provisional_objective'))]
    for heading,predicate in sections:
        selected=[e for e in entities if predicate(e)]
        if heading.startswith('Relationship membership pending') and not selected:continue
        lines+=['',heading]
        if heading.startswith('Earlier-frontier') and selected:
            lines.append('  Derived when the accepted evidence frontier was smaller; absent from the final sparse relationship graph. This does not invalidate the recorded-time comparison.')
        if not selected:lines.append('  None recorded.')
        for e in selected:
            if e['kind']=='finding':
                dep=e['dependencies'][0]
                lines.append('  '+labels[e['id']]+': '+e['predicate']+'; '+_text(dep.get('pointer') or dep.get('interpretation_id')))
                caveats.update(e['qualifications'])
            else:
                content=e.get('text',e.get('predicate',''))
                if isinstance(content,dict):content='; '.join(k+': '+str(v) for k,v in content.items())
                lines.append('  '+_text(content))
            if e['kind']=='relationship':
                lines.append('    References: '+', '.join(labels.get(k,'unavailable') for k in e['endpoints']))
                lines.append('    Derived at accepted batches: '+', '.join(str(f['batch']) for f in e['present_frontiers']))
                caveats.update(e.get('qualifications',[]))
            if e.get('alternatives'):lines.append('    Alternatives: '+_text(e['alternatives']))
            for key in ('original_assessment','assessment','binding'):
                if e.get(key):lines.append('    '+key+': '+_text(e[key].get('status','not_assessable')))
            caveats.update(x for x in e.get('limitations',[]) if x)
            caveats.update(e.get('assumptions',[]))
            if e.get('role')=='provisional_objective':
                objective=e['objective']
                lines.append('    Provisional intent; eligible: '+str(objective['eligible']))
                if objective.get('unresolved'):lines.append('    Unresolved roles: '+_text(objective['unresolved']))
            if e.get('alias_legend'):
                lines.append('    Request '+str(e['alias_legend'][0]['request_number'])+' aliases (this request only):')
                for alias in e['alias_legend']:
                    lines.append('      '+alias['alias']+' = '+labels.get(alias['clause_id'],'support')+' '+_text(alias['label']))
    lines+=['','Accepted findings unassigned to an AI theme',
            '  '+', '.join(labels.get(k,k) for k in view['coverage'].get('unassigned_findings',[])),
            '', 'Coverage (no completeness percentage)',
            *('  '+key+': '+str(value) for key,value in view['coverage'].items() if type(value) in (int,bool) and key!='relationships'),
            '  Source/clock coverage and forensic completeness remain limited; omissions are not irrelevant.',
            '', 'Qualifications and uncertainty',*('  '+_text(q) for q in sorted(caveats)),
            'Organization incomplete: '+str(view['incomplete']),
            'Organization processing stops: '+_text(view.get('processing_stops',[])),
            'Organization resources: '+_text(view['resource_use'])]
    return '\n'.join(lines)

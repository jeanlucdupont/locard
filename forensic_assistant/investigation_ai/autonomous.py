"""Opt-in Stage A. Derived incremental deltas, no restart continuation."""
from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path
import re
import time
import uuid

from . import contracts, disclosure, autonomous_policy as policy
from .state import State, Budget, encoded
from .transcript import Transcript, digest, load, validate_evidence_state
from .runner import ForensicWorker
from .narrative import build

ENGINE='incremental-stage-a-v1'
DELTA='analysis-delta-v1'


def prepare(handoff, assessment, client, *, decompose=False, synthesize=False,follow_up=False,extended=False):
    if extended and not follow_up:raise ValueError('Extended investigation requires follow-up')
    if follow_up and (decompose or synthesize):raise ValueError('Follow-up discovery currently uses the standalone analysis workflow')
    if synthesize and not decompose:raise ValueError('Synthesis requires decomposition')
    # Do not spend unaccounted compatibility requests inside a six-request grant.
    from forensic_assistant.ai.investigation_preflight import require
    require(client.config,provider=client.provider_name,model=client.model_name)
    path=Path(handoff['case']['path']).resolve(strict=True);info=path.stat()
    ids=[h['id'] for h in handoff['hints']]
    if not ids:raise ValueError('Assessment contains no evidence references for autonomous inspection')
    sources=set();families=set();hints={}
    for eid in ids:
        record=assessment['records'][eid]
        current=record.get('source_context',{})
        if not current.get('source_ids'):
            raise ValueError('Autonomous authorization requires explicit source IDs for every selected reference')
        sources.update(current['source_ids']);families.add(eid.split(':')[0].lower())
        # Scheduling hints only: never put these historical values into model evidence.
        hints[eid]=encoded(record.get('match',{}))[:2048]
    grant = dict(contract=policy.CONTRACT,case=str(path),file_identity=[info.st_dev,info.st_ino],
        objective=handoff['question'],assessment_id=handoff['assessment_id'],assessment_digest=handoff['assessment_digest'],
        provider=client.provider_name,model=client.model_name,source_ids=sorted(sources),families=sorted(families),
        evidence_ids=ids,tools=['show_evidence'],start=handoff['scope']['start'],end=handoff['scope']['end'],
        temporal_policy=policy.TEMPORAL,view_policy='pinned read transaction established after approval; no restart continuation',
        limits=dict(requests=6,steps=8,seconds=300,records=200,prompt_bytes=5600,tool_calls=6,tool_seconds=45,output_tokens=1024))
    if decompose:
        from .decomposition import messages
        messages(grant['objective'])  # Reject oversized questions before approval.
        grant['contract'] = policy.S4_CONTRACT
        grant['limits']['requests'] = 7
        grant['allocations'] = deepcopy(policy.S4_ALLOCATION)
    if handoff.get('selection'):
        grant['selection']=deepcopy(handoff['selection'])
        explicit_source=assessment['plan'].get('source_id')
        allowed_sources=[explicit_source] if explicit_source else sorted(sources)
        if grant['selection']['selected_ids']!=ids or grant['selection']['source_ids']!=allowed_sources or not sources<=set(allowed_sources):
            raise ValueError('Seed selection does not match assessment source/reference authority')
        grant['source_ids']=allowed_sources
    if synthesize:
        grant['contract']=policy.B2_CONTRACT
        grant['limits']=deepcopy(policy.B2_LIMITS)
        grant['allocations']=deepcopy(policy.B2_ALLOCATION)
    if follow_up:
        from . import follow_up as follow
        from . import context_inspection as context
        grant.update(contract=context.CAPACITY_CONTRACT,tools=['show_evidence','follow_up','inspect_context'],
                     follow_up=deepcopy(follow.LIMITS),context_inspection=deepcopy(context.LIMITS))
        grant['limits']['prompt_bytes']=context.INPUT_BYTES
        if grant.get('selection'):grant['families']=grant['selection']['eligible_families']
    if extended:
        from .extended import authorize as extend
        grant=extend(grant)
    return grant,hints


def start(handoff,assessment,client,confirm,*,status=None,batch_progress=None,decompose=False,synthesize=False,live_explanation=False,follow_up=False,extended=False):
    if live_explanation and not synthesize:raise ValueError('Live explanation requires synthesis')
    grant,hints=prepare(handoff,assessment,client,decompose=decompose,synthesize=synthesize,follow_up=follow_up,extended=extended)
    from .supervision import run as supervised
    from forensic_assistant.ai.backend import ModelBackend
    # Capture cached provider configuration before approval; never probe here.
    descriptor=client.descriptor() if isinstance(client,ModelBackend) else None
    if confirm(deepcopy(grant)) is not True:
        if grant.get('selection'):
            from forensic_assistant import activity
            activity.event('INVESTIGATION_AUTHORIZATION','cancelled',required=True,assessment_id=grant['assessment_id'],
                           selection=grant['selection'],provider_requests=0,evidence_lookups=0)
        return None
    started=time.monotonic()
    grant.update(id=uuid.uuid4().hex,issued=time.time());grant['expires']=grant['issued']+grant['limits']['seconds']
    from forensic_assistant.assessment_handoff import authorize
    from .state import execution_budget
    return supervised({'case_path':grant['case'],'semantic_enabled':False,'_stage_a':grant,'_stage_a_hints':hints,
        '_stage_a_handoff':authorize(handoff,lambda _:True),'_stage_a_started':started,'_stage_a_deadline':started+grant['limits']['seconds'],
        '_live_explanation':live_explanation},
        grant['objective'],grant['case']+'.investigations',client=client,budget=execution_budget({'_stage_a':grant}),status=status,batch_progress=batch_progress,prepared_backend=descriptor)


def choose(pending,hints,previous,selection=None,inspected=()):
    if selection:
        for eid in selection['requested_ids']:
            if eid in pending:return eid
        from collections import Counter
        counts=Counter(selection['buckets'][eid] for eid in inspected)
        bucket=min({selection['buckets'][eid] for eid in pending},key=lambda b:(counts[b],selection['bucket_order'].index(b)))
        pending={eid for eid in pending if selection['buckets'][eid]==bucket}
        if selection.get('temporal_order'):
            return min(pending,key=selection['temporal_order'].index)
    # Accepted unresolved questions/observations influence order, never authorization.
    text=' '.join(previous.get('model_proposed_unknowns',[]))+' '+ ' '.join(str(r['reported_value']) for r in previous.get('observed',[]))
    terms=set(re.findall(r'[a-z0-9_]{4,}',text.casefold()))-{'that','this','with','from','evidence','unknown'}
    return min(pending,key=lambda eid:(-len(terms & set(re.findall(r'[a-z0-9_]{4,}',hints.get(eid,'').casefold()))),eid))


def merge_findings(deltas):
    out={k:[] for k in ('observed','interpretations','deterministically_correlated','corroborated','unresolved_relationships','detections','hypotheses','model_proposed_unknowns')}
    for delta in deltas:
        for k in out:
            for value in delta['findings'].get(k,[]):
                if value not in out[k]:out[k].append(deepcopy(value))
    return out


def packet(state,question,previous,current_id,follow=False,current_ids=(),search_context=None,*,completed_context=None,final_analysis=False):
    from .failure_diagnostics import PacketFailure
    try:
        result=_packet_once(state,question,previous,current_id,follow,current_ids,search_context,completed_context=completed_context,final_analysis=final_analysis,minimal=state.budget.prompt_ceiling==24576)
        if not state.prompt_diagnostics.get('prior_support_fields_omitted'):return result
    except PacketFailure as exc:
        if exc.code!='PROMPT_BUDGET_EXHAUSTED':raise
    # A bounded deterministic repack, not a provider retry or new evidence read.
    return _packet_once(state,question,previous,current_id,follow,current_ids,search_context,minimal=True,completed_context=completed_context,final_analysis=final_analysis)


def _packet_once(state,question,previous,current_id,follow=False,current_ids=(),search_context=None,*,minimal=False,completed_context=None,final_analysis=False):
    from .failure_diagnostics import PacketFailure
    # Unresolved text is explicitly an unverified planning input, not evidence.
    context={'previous_unresolved_unverified':previous.get('model_proposed_unknowns',[])[:3],
             'byte_limits':'All response string maxLength values are local UTF-8 byte ceilings, not character allowances. Write short complete prose with margin; unknowns/alternatives target 100 bytes, hypotheses 240 bytes. Never shorten exact evidence IDs or pointers.',
             'batch_instruction':'Return a final action for this batch only. Cite current disclosed fields. Identify unresolved questions that guide the next authorized inspection. Hypotheses remain unverified.'}
    if follow:
        from .follow_up import INSTRUCTION
        context['batch_instruction']=INSTRUCTION
        if search_context and search_context.get('contextual'):
            from .context_inspection import INSTRUCTION as CONTEXT_INSTRUCTION
            context['batch_instruction']+=CONTEXT_INSTRUCTION
        context['follow_up_coverage']=deepcopy(search_context) if search_context else {'completed':[]}
        context['follow_up_coverage']['note']='Only the displayed neighborhoods were sampled. Empty and truncated results do not establish absence elsewhere.'
    if minimal:
        context['previous_unresolved_unverified']=previous.get('model_proposed_unknowns',[])[:3] if state.budget.calls>6 else []
        context['byte_limits']='All string limits are UTF-8 byte ceilings. Preserve exact IDs, pointers and values.'
        context['optional_context_omitted']=True
        if follow:
            coverage=context['follow_up_coverage']
            context['follow_up_coverage']={'searches_remaining':coverage.get('searches_remaining',0),
                'completed':[{k:v for k,v in row.items() if k in ('start','end','family','complete')} for row in coverage.get('completed',[])],
                'note':'Bounded samples only; omissions do not establish absence.'}
    if completed_context is not None:
        from . import progress
        context['completed_context']=progress.ledger(completed_context,limit=state.budget.calls)
        if state.budget.prompt_ceiling==24576:context['completed_context']=progress.summary(context['completed_context'],getattr(state,'work_calls',state.accepted),(search_context or {}).get('searches_remaining',0),final_analysis)
        context['batch_instruction']+=progress.INSTRUCTION
    if state.budget.calls>6:
        context['work_session']={'batch':getattr(state,'work_batch',1),'completed_operations':state.accepted,'completed_requests':getattr(state,'total_requests',0),'total_operations':18,'total_requests':18,'batch_requests':6,'batch_operations':6,'no_retries':True}
        context['batch_instruction']+=' These six-request/tool limits apply to this work batch. The application may continue pending authorized leads in later batches under the same grant. Prior findings and unresolved questions guide planning only; new citations must be represented in this request.'
    if final_analysis:
        context['batch_instruction']='Return final with grounded observations or explicit insufficient evidence. No tools are available. Do not invent findings.'
    transport=0
    if follow:
        from forensic_assistant.ai.openai_schema import instruct
        transport=len(instruct([{'role':'system','content':''}])[0]['content'].encode())+180
    overhead=len(encoded(context).encode())+80+transport
    original=state.budget;records=state.records
    state.packet_capacity=None
    if overhead>=original.prompt_bytes:
        from .state import SYSTEM
        from . import packet_capacity
        dummy=[{'role':'system','content':SYSTEM},{'role':'user','content':encoded({'controller':{'objective':question},'incremental':context,
            'UNTRUSTED FORENSIC EVIDENCE':{'records':[]}})}]
        n=sum(len(m['content'].encode()) for m in (instruct(dummy) if follow else dummy))
        state.packet_capacity=packet_capacity.measure(dummy,follow,original.prompt_bytes,n,0,0,cause='overhead')
        raise PacketFailure('PROMPT_BUDGET_EXHAUSTED')
    prior_ids=[r['evidence_ids'][0] for r in previous.get('observed',[])]+[i['evidence_ids'][0] for i in previous.get('interpretations',[])]
    prior_fields=[(r['evidence_ids'][0],r['field'],r['reported_value']) for r in previous.get('observed',[])]
    selected={current_id,*current_ids,*prior_ids}
    if completed_context:
        selected.add(completed_context[-1]['records'][0]['id'])
    state.records={k:v for k,v in records.items() if k in selected}
    state.budget=replace(original,prompt_bytes=original.prompt_bytes-overhead)
    try:
        try:messages,exposure,_=state.prompt(question,[],[],required_id=current_id,prior_fields=prior_fields)
        except PacketFailure:
            if getattr(state,'minimum_messages',None):
                from . import packet_capacity
                minimum=deepcopy(state.minimum_messages)
                minimal_body=json.loads(minimum[1]['content']);minimal_body['incremental']=context
                minimum[1]['content']=encoded(minimal_body)
                required=sum(len(m['content'].encode()) for m in (instruct(minimum) if follow else minimum))
                state.packet_capacity=packet_capacity.measure(minimum,follow,original.prompt_bytes,required,1,0,cause='mandatory_evidence' if required>original.prompt_bytes else 'overhead')
            raise
        except ValueError as exc:
            code='PROMPT_BUDGET_EXHAUSTED' if str(exc)=='Prompt exceeds byte budget' else 'EVIDENCE_PACKET_VALIDATION_FAILED'
            raise PacketFailure(code) from exc
    finally:state.budget=original;state.records=records
    if completed_context is not None:
        full_ledger=progress.ledger(completed_context,exposure,limit=state.budget.calls)
        context['completed_context']=progress.summary(full_ledger,getattr(state,'work_calls',state.accepted),(search_context or {}).get('searches_remaining',0),final_analysis) if original.prompt_ceiling==24576 else full_ledger
    body=json.loads(messages[1]['content']);body['incremental']=context
    if follow:
        body['controller'].update(final_only=False,tools=(['follow_up','inspect_context'] if search_context and search_context.get('contextual') else ['follow_up']),calls_remaining=max(0,6-getattr(state,'work_calls',state.accepted)))
    if final_analysis:body['controller'].update(final_only=True,tools=[],calls_remaining=0)
    messages[1]['content']=encoded(body)
    size=sum(len(m['content'].encode()) for m in (instruct(messages) if follow else messages))
    if size>original.prompt_bytes:raise PacketFailure('PROMPT_BUDGET_EXHAUSTED')
    # Earlier supports must be explicitly re-disclosed, never trusted from summaries.
    if current_id not in {g['id'] for g in exposure['records']}:raise PacketFailure('CURRENT_RECORD_NOT_DISCLOSED')
    state.prompt_diagnostics['prompt_bytes']=size
    state.prompt_diagnostics['optional_context_omitted']=minimal
    state.operation_ledger=full_ledger if completed_context is not None else None
    state.progress_summary=context.get('completed_context')
    from . import packet_capacity
    minimum=deepcopy(state.minimum_messages)
    minimum_body=json.loads(minimum[1]['content']);minimum_body['incremental']=context
    minimum[1]['content']=encoded(minimum_body)
    required=sum(len(m['content'].encode()) for m in (instruct(minimum) if follow else minimum))
    state.packet_capacity=packet_capacity.measure(messages,follow,original.prompt_bytes,required,1,state.prompt_diagnostics['omitted_candidate_fields'])
    return messages,exposure,size


def run(config,question,root,*,budget=None,client=None,dry_run=False,approval=None,worker_factory=ForensicWorker):
    from forensic_assistant import activity
    from forensic_assistant.ai.output_budget import final_output
    from forensic_assistant.ai.backend import model_operation
    from forensic_assistant.llm.client import LLMError
    status=config.get('_status') or (lambda _:None)
    controller_started=time.monotonic()
    status('authorization_validation')
    grant=config['_stage_a'];policy.validate(grant,config['case_path'])
    from . import decomposition as decomposition_service
    from . import synthesis_consumer as consumer
    from . import organization, explanation_live
    from . import follow_up as follow
    from . import extended as work
    extended_session=work.enabled(grant)
    discovery = follow.supported(grant)
    from . import context_inspection as context
    contextual=context.supported(grant)
    b2 = grant['contract'] == policy.B2_CONTRACT
    if config.get('_live_explanation',False) and not b2:
        raise ValueError('Live explanation requires the S4-B2 workflow')
    s4 = b2 or grant['contract'] == policy.S4_CONTRACT
    reserve = 20 if b2 else decomposition_service.RESERVE_SECONDS
    engine = consumer.ENGINE if b2 else decomposition_service.ENGINE if s4 else ENGINE
    synthesis_result=consumer.initial()
    decision = {'status':'not_attempted'}
    decomposition_requests = 0
    from .synthesis import _Reducer
    reducer = _Reducer() if s4 else None
    if config.get('_stage_a_handoff') is not None:
        status('handoff_validation')
        from forensic_assistant.assessment_handoff import validate as validate_handoff
        validate_handoff(config['_stage_a_handoff'],config['case_path'])
        policy.validate(grant,config['case_path'])
    if dry_run or approval is not None or question!=grant['objective']:raise ValueError('Invalid Stage A invocation')
    if client is None or client.provider_name!=grant['provider'] or client.model_name!=grant['model']:raise ValueError('PROVIDER_SCOPE_CHANGED')
    from .state import recorded_budget
    expected_budget=recorded_budget({'authorization':grant})
    budget=budget or expected_budget
    if budget!=expected_budget:raise ValueError('Stage A uses the approved fixed limits')
    if b2:budget=replace(budget,steps=10)
    deadline=min(config.get('_deadline',float('inf')),config.get('_stage_a_deadline',float('inf')),time.monotonic()+grant['limits']['seconds'])
    if b2 or extended_session:
        overall=config.get('_stage_a_deadline',deadline)
        deadline=min(deadline,overall-5)  # parent containment must finish by overall
        model_deadline=min(overall-20,time.monotonic()+max(0,grant['expires']-time.time())-20)
    else:model_deadline=deadline-reserve
    state=State(budget);state.compact_final=True;state.finalization_requested=True
    state.scope={'kind':'explicit','start':grant['start'],'end':grant['end']}
    identity=config.get('_investigation_id') or uuid.uuid4().hex
    status('transcript_init')
    transcript=Transcript(root,dict(engine=engine,authorization=grant,question=question,budgets=asdict(budget),
        evidence_fingerprint=None,rule_ids=[],schema=5,**({'progress_profile':'bounded-investigation-progress-v1'} if contextual else {}),**({'synthesis_guidance':'concise-v1','organization_profile':organization.PROFILE,
            **({'explanation_profile':explanation_live.COMPACT_PROFILE} if config.get('_live_explanation',False) else {})} if b2 else {})),investigation_id=identity)
    organizer=None;explainer=None
    deltas=[];pending=set(grant['evidence_ids']);requests=0;view=None;worker=None;stop='AUTHORIZED_PLAN_EXHAUSTED';sizes=[];usage=[];phase='operation'
    next_search=None;search_keys=set();search_proposed=0;search_executed=0;search_approved=0;disclosed_ids=set();inspected_seeds=set();search_results=[];context_calls=0;completed_context=[];duplicate_proposals=0;forced_seed=None;analyze_continuation=False;next_context=None;context_keys=set();operation='initial';operation_phase='startup';failure_diagnostic=None
    batch=1;batch_start=(0,0,0);checkpoints=[]
    def checkpoint(reason):
        value=work.receipt(batch,requests,state.accepted,search_executed,deltas,pending,state.records,reason,batch_start)
        transcript.append('work_batch_checkpoint',value)
        recorded,events=load(root,identity)
        _replay(recorded,events,identity)
        checkpoints.append(value)
        if config.get('_stage_a_checkpoint'):
            config['_stage_a_checkpoint'](dict(findings=merge_findings(deltas),state=state.summary(),work_batches=deepcopy(checkpoints),
                validated_batches=len(deltas),evidence_state=view,question=question,engine=engine))
        if config.get('_work_batch_progress'):config['_work_batch_progress'](value)
        return value
    def remaining():return min(45,max(.001,deadline-time.monotonic()))
    def guard():
        policy.validate(grant,config['case_path'])
        if time.monotonic()>=deadline:raise ValueError('RESOURCE_BUDGET_EXHAUSTED')
        if client.provider_name!=grant['provider'] or client.model_name!=grant['model']:raise ValueError('PROVIDER_SCOPE_CHANGED')
    try:
        guard();status('audit_init')
        activity.event('INVESTIGATION_START',required=True,investigation_id=identity)
        guard();status('worker_start')
        worker_config={k:v for k,v in config.items() if k not in ('_execution_clock','_startup_complete','_approval_clock_managed','_stage_a_checkpoint','_stage_a_hints','_stage_a_handoff','_work_batch_progress')}
        worker=worker_factory({**worker_config,'_transaction_view':True,'semantic_enabled':False,'_deadline':deadline})
        guard();status('read_transaction')
        initial=worker.call('initial',question=question,seconds=remaining())
        guard()
        view=validate_evidence_state(initial['evidence_state'])
        if initial.get('database_changes')!=0 or initial.get('fingerprint') is not None:
            raise ValueError('READ_VIEW_INCONSISTENT')
        transcript.manifest['evidence_state']=view
        transcript.manifest['schema']=initial.get('schema',5)
        transcript.append('initial',initial)
        if b2:organizer=organization.Live(transcript)
        if b2 and config.get('_live_explanation',False):explainer=explanation_live.Live(transcript,organizer,reducer)
        if config.get('_startup_complete'):config['_startup_complete']()
        if s4:
            guard()
            available = model_deadline - time.monotonic()
            if available <= 0:
                raise ValueError('RESOURCE_BUDGET_EXHAUSTED')
            state.steps += 1
            def charge_decomposition():
                nonlocal decomposition_requests
                decomposition_requests += 1
                if decomposition_requests > 1:
                    raise ValueError('RESOURCE_BUDGET_EXHAUSTED')
            status('decomposition')
            decision = decomposition_service.execute(client,question,grant,transcript,guard,available,
                charge=charge_decomposition,decision_store=decision)
            status('operation')
        while (pending or next_search or next_context) and requests<budget.calls and state.accepted<budget.calls and state.steps<budget.steps:
            if extended_session and (requests-batch_start[0]>=6 or state.accepted-batch_start[1]>=6):
                value=checkpoint('BATCH_RESOURCE_LIMIT')
                if batch>=3:stop='OVERALL_RESOURCE_EXHAUSTED';break
                guard()
                transcript.append('work_batch_started',dict(batch=batch+1,previous_checkpoint=digest(value)))
                batch+=1;batch_start=(requests,state.accepted,search_executed)
            state.work_calls=state.accepted-batch_start[1]
            state.work_requests=requests-batch_start[0]
            state.work_batch=batch;state.total_requests=requests
            if (s4 or discovery) and time.monotonic() >= model_deadline:
                stop = 'RESOURCE_BUDGET_EXHAUSTED'
                break
            guard();state.steps+=1;phase='operation';operation_phase='authorization'
            previous=merge_findings(deltas) if extended_session else (deltas[-1]['findings'] if deltas else {})
            operation='inspect_context' if next_context else ('follow_up' if next_search else 'show_evidence')
            if next_context:
                args=next_context;eid=args['evidence_id'];next_context=None
            elif next_search:
                args=next_search;eid=args['evidence_id']
                next_search=None
            else:
                eid=forced_seed or choose(pending,config.get('_stage_a_hints',{}),previous,grant.get('selection'),inspected_seeds)
                forced_seed=None
                args={'evidence_id':eid}
            policy.operation(grant,config['case_path'],operation,args)
            operation_phase='authorization_persistence'
            transcript.append('authorized_operation',dict(tool=operation,arguments=args,grant_id=grant['id'],
                based_on_delta=deltas[-1]['id'] if deltas else None))
            activity.event('TOOL_APPROVED',required=True,investigation_id=identity,tool_call_number=state.accepted+1,tool=operation,arguments_sha256=digest(args),approval='configured_policy')
            state.requested+=1;state.accepted+=1;status('operation')
            operation_seconds=min(remaining(),max(.001,model_deadline-time.monotonic())) if s4 or discovery else remaining()
            if operation=='follow_up':operation_seconds=min(5,operation_seconds)
            if operation=='follow_up':search_executed+=1
            if operation=='inspect_context':context_calls+=1
            operation_phase='worker_retrieval'
            response=worker.call(operation,args,known_ids=sorted(disclosed_ids) if operation=='inspect_context' else grant['evidence_ids'],seconds=operation_seconds)
            guard()
            if response.get('evidence_state')!=view or response.get('database_changes')!=0:raise ValueError('READ_VIEW_INCONSISTENT')
            operation_phase='result_validation'
            try:contracts.validate_output(response['result'])
            except ValueError as exc:
                from .failure_diagnostics import PacketFailure
                raise PacketFailure('EVIDENCE_PACKET_VALIDATION_FAILED') from exc
            rows=response['result']['records']
            if operation=='show_evidence' and any(r['id'] not in grant['evidence_ids'] for r in rows):raise ValueError('ADDITIONAL_SCOPE_REQUIRED')
            if (s4 or discovery) and operation=='show_evidence' and any(r['id'] != eid for r in rows):raise ValueError('ADDITIONAL_SCOPE_REQUIRED')
            if any(not follow.eligible(grant,r) for r in rows):raise ValueError('ADDITIONAL_SCOPE_REQUIRED')
            if operation=='follow_up':
                follow.validate_result(grant,response['result'],follow.record_window(grant,args,state.records))
                search_results.append(response['result']['plan'])
            if operation=='inspect_context':context.validate_result(grant,args,response['result'])
            operation_phase='result_persistence'
            transcript.append('result',dict(operation=operation,response=response))
            if operation=='inspect_context':completed_context.append(deepcopy(response['result']))
            activity.event('TOOL_COMPLETED',required=True,investigation_id=identity,tool_call_number=state.accepted,tool=operation)
            operation_phase='state_ingest'
            state.ingest(response['result'],operation=operation)
            operation_phase='seed_selection'
            if operation=='show_evidence':pending.remove(eid);inspected_seeds.add(eid)
            elif operation=='follow_up':
                for row in rows:pending.discard(row['id'])
            state.path.append({'operation':operation,'evidence_id':eid})
            if not rows:
                if not discovery:raise ValueError('CURRENT_RECORD_NOT_DISCLOSED')
                # No paid retry and no case-wide negative inference.
                if operation=='follow_up':stop='FOLLOW_UP_EMPTY';break
                continue
            operation_phase='packet_preparation'
            state.work_calls=state.accepted-batch_start[1]
            final_analysis=contextual and (requests-batch_start[0]>=5 or state.accepted-batch_start[1]>=6 or analyze_continuation)
            analyze_continuation=False
            current_ids=[r['id'] for r in rows]
            messages,exposure,size=packet(state,question,previous,current_ids[0],discovery,(current_ids+([eid] if operation=='follow_up' else [])) if discovery else (),
                dict(contextual=contextual,searches_remaining=2-(search_approved-batch_start[2]),completed=[{k:r[k] for k in ('start','end','family','complete','returned_ids') } for r in search_results]) if discovery else None,completed_context=completed_context if contextual else None,final_analysis=final_analysis);sizes.append(size)
            if discovery and len(disclosed_ids|{g['id'] for g in exposure['records']})>grant['follow_up']['distinct_disclosures']:raise ValueError('RESOURCE_BUDGET_EXHAUSTED')
            operation_phase='exposure_persistence'
            transcript.append('exposure',dict(content=exposure,prompt_bytes=size,prompt_sha256=digest(messages),
                **({'operation_ledger':state.operation_ledger,'analysis_only':final_analysis,**({'progress_summary':state.progress_summary,'packet_capacity':state.packet_capacity} if budget.prompt_ceiling==24576 else {})} if contextual else {}),
                allocation={k:state.prompt_diagnostics[k] for k in ('disclosed_records','compact_observations','compact_interpretations',
                    'omitted_candidate_fields','omitted_candidate_records','omitted_candidate_interpretations','prior_support_fields_omitted','optional_context_omitted')}))
            operation_phase='disclosure_validation'
            try:state.disclose(exposure)
            except ValueError as exc:
                from .failure_diagnostics import PacketFailure
                raise PacketFailure('EVIDENCE_PACKET_VALIDATION_FAILED') from exc
            guard()
            if (s4 or discovery) and time.monotonic() >= model_deadline:
                stop = 'RESOURCE_BUDGET_EXHAUSTED'
                break
            status('model');phase='provider';operation_phase='provider'
            # Use ordinary output allowance; no final synthesis request or hidden retry.
            if s4:
                transcript.append('analysis_request',dict(allocation='analysis',ordinal=requests+1,
                    grant_id=grant['id'],output_tokens=1024))
            if discovery:transcript.append('follow_up_model_attempt',dict(ordinal=requests+1,grant_id=grant['id']))
            requests+=1
            disclosed_ids.update(g['id'] for g in exposure['records'])
            old_timeout = getattr(client,'timeout',None)
            if s4 or discovery:
                client.timeout = max(.001,min(old_timeout or 120,model_deadline-time.monotonic()))
            request_started=time.monotonic()
            try:
                with model_operation('investigation'),final_output(False):raw=client.complete(messages,follow.schema(contextual) if discovery and not final_analysis else contracts.schema([]))
            finally:
                if s4 or discovery:
                    if old_timeout is None:del client.timeout
                    else:client.timeout=old_timeout
            from .completion_diagnostics import observed
            operation_phase='analysis_persistence'
            transcript.append('analysis_response_diagnostic',dict(ordinal=requests,**observed(client,request_started)))
            guard();usage.append(deepcopy(getattr(client,'last_metadata',{}).get('usage') or None))
            operation_phase='analysis_validation'
            try:
                proposal=follow.parse(raw,contextual) if discovery and not final_analysis else contracts.request(raw,[])
                if discovery and proposal['action']=='tool':
                    if proposal['tool']=='inspect_context':
                        scope=context.proposed(grant,proposal['arguments'],exposure)
                        transcript.append('context_proposed',dict(proposal=proposal,scope=scope,disclosure_sha256=digest(exposure)))
                        key=digest(scope)
                        if key in context_keys:
                            from .progress import continuation
                            duplicate_proposals+=1;state.rejected+=1
                            forced_seed=continuation(pending,requests-batch_start[0],state.accepted-batch_start[1])
                            transcript.append('redundant_context',dict(reason='CONTEXT_DUPLICATE',arguments=proposal['arguments'],
                                next_seed=forced_seed,model_attempt=requests,tool_calls=state.accepted))
                            if forced_seed is None:stop='CONTEXT_DUPLICATE';break
                            guard()
                            analyze_continuation=True
                            continue
                        if state.accepted>=budget.calls or requests>=budget.calls:stop='RESOURCE_BUDGET_EXHAUSTED';break
                        context_keys.add(key);next_context=proposal['arguments']
                        continue
                    search_proposed+=1
                    scope=follow.proposed(grant,proposal['arguments'],exposure)
                    transcript.append('follow_up_proposed',dict(proposal=proposal,scope=scope,disclosure_sha256=digest(exposure)))
                    key=digest(scope)
                    if key in search_keys:stop='FOLLOW_UP_DUPLICATE';break
                    if search_approved>=grant['follow_up']['searches'] or search_approved-batch_start[2]>=2 or state.accepted>=budget.calls or requests>=budget.calls:stop='RESOURCE_BUDGET_EXHAUSTED';break
                    search_keys.add(key);search_approved+=1;next_search=proposal['arguments']
                    continue
                findings=state.render(proposal['answer'])
            except ValueError as exc:
                from .rejection import rejected_response
                state.rejected+=1
                transcript.append('rejected',dict(stage='batch_validation',rejected_response=rejected_response(raw,exc,state)))
                stop='VALIDATION_FAILURE';break
            delta=dict(contract=DELTA,id=digest([identity,len(deltas),proposal]),evidence_state=view,
                disclosure_sha256=digest(exposure),proposal=proposal,findings=findings,batch=len(deltas)+1,
                counters=dict(ai_requests=requests,tool_calls=state.accepted),based_on=deltas[-1]['id'] if deltas else None)
            operation_phase='analysis_persistence'
            transcript.append('validated_delta',delta)  # Durable before scheduling next batch.
            deltas.append(delta)
            if reducer is not None:
                reducer.consume(state,delta,exposure)
            if organizer:
                receipt=organizer.update(lambda:organizer.sources.analysis(reducer,delta,exposure,organization._frontier(transcript)),
                    deadline=model_deadline,remaining_analysis=6-requests,remaining_synthesis=2)
                if explainer:explainer.update(receipt,deadline=model_deadline,remaining_analysis=6-requests,remaining_synthesis=2)
            if config.get('_stage_a_checkpoint'):
                config['_stage_a_checkpoint'](dict(findings=merge_findings(deltas),state=state.summary(),
                    validated_batches=len(deltas),evidence_state=view,question=question,engine=engine,**({'work_batches':deepcopy(checkpoints)} if extended_session else {})))
        if extended_session:
            status('finalization')
            reason='BATCH_RESOURCE_LIMIT' if (requests-batch_start[0]>=6 or state.accepted-batch_start[1]>=6) else 'NO_FURTHER_AUTHORIZED_LEADS' if not pending and not next_search and not next_context else 'SESSION_STOPPED'
            checkpoint(reason)
        operation_phase='finalization'
        if (pending or next_search or next_context) and stop=='AUTHORIZED_PLAN_EXHAUSTED':stop='RESOURCE_BUDGET_EXHAUSTED'
        if b2 and deltas and time.monotonic()<model_deadline:
            from . import packets, relationships
            factual=reducer.finish()
            ctx=packets.Context(state,factual,relationships._build(factual),transcript.manifest,
                decision.get('mapping') if decision['status']=='accepted' else None,
                {(d['id'],d['disclosure_sha256'],d['batch']) for d in deltas})
            def charge_synthesis():
                if state.steps>=9 or synthesis_result['attempts']>=2:raise ValueError('RESOURCE_BUDGET_EXHAUSTED')
                state.steps+=1
            def synthesis_checkpoint():
                if config.get('_stage_a_checkpoint'):
                    config['_stage_a_checkpoint'](dict(findings=merge_findings(deltas),state=state.summary(),
                        validated_batches=len(deltas),evidence_state=view,question=question,engine=engine,
                        synthesis=deepcopy(synthesis_result)))
            def organize_proposals(packet,accepted):
                if organizer:
                    receipt=organizer.update(lambda:organizer.sources.synthesis(packet,accepted),
                        deadline=model_deadline,remaining_synthesis=2-synthesis_result['attempts'])
                    if explainer:explainer.update(receipt,deadline=model_deadline,remaining_synthesis=2-synthesis_result['attempts'])
            consumer.execute(ctx,client,transcript,guard,model_deadline,status,charge_synthesis,
                             result=synthesis_result,checkpoint=synthesis_checkpoint,on_decision=organize_proposals)
        elif b2:
            synthesis_result.update(status='skipped_budget' if deltas else 'skipped_no_packet',termination='NO_ADMISSIBLE_SYNTHESIS')
    except KeyboardInterrupt:stop='ANALYST_CANCELLED'
    except Exception as exc:
        from .failure_diagnostics import classify,diagnostic
        stop=classify(exc,operation_phase)
        failure_diagnostic=diagnostic(stop,operation_phase,operation,state,len(deltas),requests)
        error_type=type(exc).__name__ if type(exc).__name__ in ('ValueError','OSError','TypeError','KeyError','RuntimeError','WorkerError','PacketFailure','LLMError') else 'Exception'
        transcript.append('stopped',dict(reason=stop,error_type=error_type,diagnostic=failure_diagnostic,
            **({'packet_capacity':state.packet_capacity} if operation_phase=='packet_preparation' and getattr(state,'packet_capacity',None) else {})))
        activity.event('TOOL_REJECTED','failure',required=True,investigation_id=identity,tool=operation,reason=stop)
    finally:
        primary_stop=stop
        if b2 or extended_session:status('finalization')
        if worker is not None:
            try:
                checked=worker.call('check',seconds=remaining())
                if checked.get('evidence_state')!=view:stop='READ_VIEW_INCONSISTENT'
            except (OSError,ValueError):stop='INTEGRITY_UNCONFIRMED'
            try:worker.close()
            except (OSError,RuntimeError):stop='CLEANUP_LIMITATION'
    findings=merge_findings(deltas)
    result=dict(engine=engine,investigation_id=identity,question=question,termination=stop,primary_termination=primary_stop,findings=findings,
        evidence_fingerprint=None,evidence_state=view,state=state.summary(),validated_batches=len(deltas),
        limitations=['Findings cover only this pinned read view. Plan completion is not forensic completeness.',
        'Only explicitly authorized assessment references were inspected; search is not enabled in Stage A.',
        'Out-of-window timestamps are bounded record context, not proof of activity inside the window.',
        'No restart continuation; hypotheses and unresolved questions remain unverified.'],
        metrics=dict(ai_requests=requests,prompt_bytes=sizes,usage=usage,usage_unknown=requests-sum(v is not None for v in usage)),
        answer_assessment=dict(status='PARTIAL',reason='Bounded assessed coverage; objective completeness is not independently established.'))
    if discovery:
        result['follow_up']=dict(proposed=search_proposed,approved=search_approved,executed=search_executed,completed=len(search_results),
            records_returned=len(state.records),records_disclosed=len(disclosed_ids),
            records_examined=len({e for row in findings['observed']+findings['interpretations'] for e in row['evidence_ids']}),
            leads_resolved=0,lead_resolution='Not deterministically assessed; matching records do not resolve an investigative question.',
            searches=search_results,unresolved_questions=findings['model_proposed_unknowns'])
        result['follow_up']['context_inspections']=context_calls
        from .progress import families
        result['follow_up'].update(context_completed=len(completed_context),redundant_context_proposals=duplicate_proposals,
            families_retrieved=families(state.records),families_disclosed=families(disclosed_ids),
            families_in_findings=families({e for row in findings['observed']+findings['interpretations'] for e in row['evidence_ids']}))
        if not findings['observed'] and not findings['interpretations']:
            result['follow_up']['no_findings_reason']=(
                'Accepted analysis contained no supported observations or interpretations. ' if deltas else
                'No analysis batch passed validation. ' if stop=='VALIDATION_FAILURE' else
                'No grounded analysis batch was accepted; tool proposals alone are not findings. ')+(
                'Coverage remains partial; termination: '+stop+'. See disclosure omissions and validation history.')
        result['limitations'][1]=('Bounded EVTX context inspection and temporal follow-up' if contextual else 'Temporal follow-up')+' only: at most two searches, three records each; candidate, time and disclosure limits apply. No filename/path pivots. Omitted records were not assessed.'
        result['limitations'].append('Searches cover bounded neighborhoods, not the entire approved window; proximity does not establish causality or successful execution.')
    if extended_session:
        if stop=='RESOURCE_BUDGET_EXHAUSTED':result['termination']='OVERALL_RESOURCE_EXHAUSTED'
        elif stop=='AUTHORIZED_PLAN_EXHAUSTED':result['termination']='NO_FURTHER_AUTHORIZED_LEADS'
        result['work_batches']=checkpoints
        result['limitations'][1]='Extended session: at most six bounded temporal searches, three records each; no filename/path pivots. Omitted records were not assessed.'
    if failure_diagnostic is not None:
        result['failure_diagnostic']=failure_diagnostic
        if failure_diagnostic['phase']=='packet_preparation' and getattr(state,'packet_capacity',None):result['packet_capacity']=state.packet_capacity
    result['controller_diagnostic']={'observer':'controller','elapsed_seconds':round(time.monotonic()-controller_started,6),
        'termination':stop,'worker_close_returned':worker is not None and stop!='CLEANUP_LIMITATION',
        'parent_cleanup_confirmation':'unavailable_in_child_journal'}
    if b2:
        result['synthesis']=synthesis_result
        result['analysis_coverage']={'termination':primary_stop,'authorized_references':len(grant['evidence_ids']),
            'completed_lookups':len(state.path),'validated_batches':len(deltas),'rejected_responses':state.rejected,
            'synthesis_basis':'accepted_partial_findings_only',
            'analysis_error_limited':primary_stop=='VALIDATION_FAILURE'}
    if s4:
        from . import relationships
        if decomposition_requests and decision['status'] == 'not_attempted':
            decision = {'status':'interrupted'}
        status('finalization')
        state.steps += 1
        result['state'] = state.summary()
        result['question_decomposition'] = decomposition_service.assess(
            question,identity,relationships._build(reducer.finish()),decision)
        result['metrics'].update(analysis_requests=requests,decomposition_requests=decomposition_requests,
            organization_requests=0,ai_requests=requests+decomposition_requests,
            decomposition_usage=decision.get('usage'),
            usage_unknown=result['metrics']['usage_unknown'] + int(bool(decomposition_requests) and decision.get('usage') is None))
        if b2:
            result['metrics'].update(synthesis_requests=synthesis_result['attempts'],
                ai_requests=requests+decomposition_requests+synthesis_result['attempts'],
                synthesis_usage=synthesis_result['usage'],usage_unknown=result['metrics']['usage_unknown']+synthesis_result['usage_unknown'])
    result['narrative']=build(findings,result['state'])
    if organizer:
        receipt=organizer.update(lambda:organizer.sources.final(result['question_decomposition'],result['state'],synthesis_result),
                         final=True,deadline=deadline)
        if explainer:explainer.update(receipt,deadline=deadline)
        result['organization']=organizer.summary()
        if explainer:result['explanation']=explainer.summary()
    cleanup_failure=None
    if stop=='CLEANUP_LIMITATION':
        from .lifecycle import CleanupError
        cleanup_failure=CleanupError('CLEANUP_LIMITATION: cannot confirm investigation worker cleanup; exit the shell')
        result['cleanup']={'status':'CLEANUP_LIMITATION','stage':'forensic_worker'}
        cleanup_failure.result=result
    try:
        transcript.finish(result)
        activity.event('INVESTIGATION_TERMINATION',required=True,investigation_id=identity,termination=stop)
    finally:
        if cleanup_failure is not None:raise cleanup_failure
    return result


def reconstruct(root,identity, *, _on_validated=None, _b2_checked=False):
    """Inspect validated recorded deltas, not resume or assert current-case equality."""
    manifest,events=load(root,identity)
    from . import decomposition
    from . import synthesis_consumer as consumer
    if manifest.get('engine') not in (ENGINE,decomposition.ENGINE,consumer.ENGINE):raise ValueError('Not a supported incremental transcript')
    if manifest['engine']==consumer.ENGINE and not _b2_checked:
        consumer.reconstruct(root,identity)
    if manifest['engine'] in (decomposition.ENGINE,consumer.ENGINE):
        decomposition.validate_journal(manifest,events)
    return _replay(manifest, events, identity, _on_validated=_on_validated)


def _replay(manifest, events, identity, *, _on_validated=None):
    """Validate analysis from a caller-owned, chain-validated recorded input."""
    from . import follow_up
    from .extended import validate_checkpoints
    validate_checkpoints(manifest,events)
    if follow_up.supported(manifest.get('authorization',{})):
        follow_up.validate_journal(manifest,events)
    from .state import recorded_budget
    state=State(recorded_budget(manifest));deltas=[];exposure=None
    for event in events:
        d=event['data']
        from .failure_diagnostics import validate as validate_diagnostic
        if event['kind']=='stopped' and 'diagnostic' in d:validate_diagnostic(d['diagnostic'])
        if event['kind']=='terminal' and 'failure_diagnostic' in d:validate_diagnostic(d['failure_diagnostic'])
        if event['kind']=='result':
            if d['response'].get('evidence_state')!=manifest['evidence_state'] or d['response'].get('database_changes')!=0:
                raise ValueError('Invalid recorded read view')
            contracts.validate_output(d['response']['result'])
            state.ingest(d['response']['result'],operation=d['operation'])
        elif event['kind']=='exposure':
            if 'allocation' in d:
                from .failure_diagnostics import validate_allocation
                validate_allocation(d['allocation'],d['content'])
            exposure=d['content'];state.disclose(exposure)
        elif event['kind']=='validated_delta':
            if d['contract']!=DELTA or d['evidence_state']!=manifest['evidence_state'] or d['disclosure_sha256']!=digest(exposure):raise ValueError('Invalid delta binding')
            if d['batch']!=len(deltas)+1 or d['id']!=digest([identity,len(deltas),d['proposal']]):raise ValueError('Invalid delta identity')
            contracts.request(encoded(d['proposal']),[])
            if state.render(d['proposal']['answer'])!=d['findings']:raise ValueError('Invalid recorded delta grounding')
            if d['based_on']!=(deltas[-1]['id'] if deltas else None):raise ValueError('Invalid delta chain')
            if _on_validated is not None:
                _on_validated(state, d, exposure)
            deltas.append(d)
    return dict(recorded_not_revalidated=True,validated_batches=len(deltas),findings=merge_findings(deltas))

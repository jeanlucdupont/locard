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


def prepare(handoff, assessment, client, *, decompose=False, synthesize=False):
    if synthesize and not decompose:raise ValueError('Synthesis requires decomposition')
    if client.provider_name!='openai' or not client.config.get('cloud_acknowledged'):
        raise ValueError('Autonomous Stage A requires acknowledged OpenAI configuration')
    # Do not spend unaccounted compatibility requests inside a six-request grant.
    from forensic_assistant.ai import readiness
    if readiness.status(client.config).get('investigation_compatibility')!='ready':
        raise ValueError('Verify OpenAI investigation compatibility before starting autonomous mode')
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
    if synthesize:
        grant['contract']=policy.B2_CONTRACT
        grant['limits']=deepcopy(policy.B2_LIMITS)
        grant['allocations']=deepcopy(policy.B2_ALLOCATION)
    return grant,hints


def start(handoff,assessment,client,confirm,*,status=None,decompose=False,synthesize=False,live_explanation=False):
    if live_explanation and not synthesize:raise ValueError('Live explanation requires synthesis')
    grant,hints=prepare(handoff,assessment,client,decompose=decompose,synthesize=synthesize)
    from .supervision import run as supervised
    from forensic_assistant.ai.backend import ModelBackend
    # Capture cached provider configuration before approval; never probe here.
    descriptor=client.descriptor() if isinstance(client,ModelBackend) else None
    if confirm(deepcopy(grant)) is not True:return None
    started=time.monotonic()
    grant.update(id=uuid.uuid4().hex,issued=time.time());grant['expires']=grant['issued']+300
    from forensic_assistant.assessment_handoff import authorize
    return supervised({'case_path':grant['case'],'semantic_enabled':False,'_stage_a':grant,'_stage_a_hints':hints,
        '_stage_a_handoff':authorize(handoff,lambda _:True),'_stage_a_started':started,'_stage_a_deadline':started+300,
        '_live_explanation':live_explanation},
        grant['objective'],grant['case']+'.investigations',client=client,budget=Budget(),status=status,prepared_backend=descriptor)


def choose(pending,hints,previous):
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


def packet(state,question,previous,current_id):
    # Unresolved text is explicitly an unverified planning input, not evidence.
    context={'previous_unresolved_unverified':previous.get('model_proposed_unknowns',[])[:3],
             'byte_limits':'All response string maxLength values are local UTF-8 byte ceilings, not character allowances. Write short complete prose with margin; unknowns/alternatives target 100 bytes, hypotheses 240 bytes. Never shorten exact evidence IDs or pointers.',
             'batch_instruction':'Return a final action for this batch only. Cite current disclosed fields. Identify unresolved questions that guide the next authorized inspection. Hypotheses remain unverified.'}
    overhead=len(encoded(context).encode())+80
    original=state.budget;records=state.records
    prior_ids=[r['evidence_ids'][0] for r in previous.get('observed',[])]+[i['evidence_ids'][0] for i in previous.get('interpretations',[])]
    selected={current_id,*prior_ids[:1]}
    state.records={k:v for k,v in records.items() if k in selected}
    state.budget=replace(original,prompt_bytes=original.prompt_bytes-overhead)
    try:messages,exposure,_=state.prompt(question,[],[])
    finally:state.budget=original;state.records=records
    body=json.loads(messages[1]['content']);body['incremental']=context;messages[1]['content']=encoded(body)
    size=sum(len(m['content'].encode()) for m in messages)
    if size>5600:raise ValueError('PROMPT_BUDGET_EXHAUSTED')
    # Earlier supports must be explicitly re-disclosed, never trusted from summaries.
    represented={(g['id'],i[1]) for g in exposure['records'] for i in g['observations']}
    prior={(r['evidence_ids'][0],r['field']) for r in previous.get('observed',[])}
    if current_id not in {g['id'] for g in exposure['records']}:raise ValueError('CURRENT_RECORD_NOT_DISCLOSED')
    if prior and not prior & represented:raise ValueError('PRIOR_SUPPORT_NOT_DISCLOSED')
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
    budget=budget or Budget()
    if budget!=Budget():raise ValueError('Stage A uses the approved fixed limits')
    if b2:budget=replace(budget,steps=10)
    deadline=min(config.get('_deadline',float('inf')),config.get('_stage_a_deadline',float('inf')),time.monotonic()+300)
    if b2:
        overall=config.get('_stage_a_deadline',deadline)
        deadline=min(deadline,overall-5)  # parent containment must finish by overall
        model_deadline=min(overall-20,time.monotonic()+max(0,grant['expires']-time.time())-20)
    else:model_deadline=deadline-reserve
    state=State(budget);state.compact_final=True;state.finalization_requested=True
    state.scope={'kind':'explicit','start':grant['start'],'end':grant['end']}
    identity=config.get('_investigation_id') or uuid.uuid4().hex
    status('transcript_init')
    transcript=Transcript(root,dict(engine=engine,authorization=grant,question=question,budgets=asdict(budget),
        evidence_fingerprint=None,rule_ids=[],schema=5,**({'synthesis_guidance':'concise-v1','organization_profile':organization.PROFILE,
            **({'explanation_profile':explanation_live.COMPACT_PROFILE} if config.get('_live_explanation',False) else {})} if b2 else {})),investigation_id=identity)
    organizer=None;explainer=None
    deltas=[];pending=set(grant['evidence_ids']);requests=0;view=None;worker=None;stop='AUTHORIZED_PLAN_EXHAUSTED';sizes=[];usage=[];phase='operation'
    def remaining():return min(45,max(.001,deadline-time.monotonic()))
    def guard():
        policy.validate(grant,config['case_path'])
        if time.monotonic()>=deadline:raise ValueError('RESOURCE_BUDGET_EXHAUSTED')
        if client.provider_name!=grant['provider'] or client.model_name!=grant['model']:raise ValueError('PROVIDER_SCOPE_CHANGED')
    try:
        guard();status('audit_init')
        activity.event('INVESTIGATION_START',required=True,investigation_id=identity)
        guard();status('worker_start')
        worker_config={k:v for k,v in config.items() if k not in ('_execution_clock','_startup_complete','_approval_clock_managed','_stage_a_checkpoint','_stage_a_hints','_stage_a_handoff')}
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
        while pending and requests<6 and state.accepted<6 and state.steps<8:
            if s4 and time.monotonic() >= model_deadline:
                stop = 'RESOURCE_BUDGET_EXHAUSTED'
                break
            guard();state.steps+=1;phase='operation'
            previous=deltas[-1]['findings'] if deltas else {}
            eid=choose(pending,config.get('_stage_a_hints',{}),previous);args={'evidence_id':eid}
            policy.operation(grant,config['case_path'],'show_evidence',args)
            transcript.append('authorized_operation',dict(tool='show_evidence',arguments=args,grant_id=grant['id'],
                based_on_delta=deltas[-1]['id'] if deltas else None))
            activity.event('TOOL_APPROVED',required=True,investigation_id=identity,tool_call_number=state.accepted+1,tool='show_evidence',arguments_sha256=digest(args),approval='configured_policy')
            state.requested+=1;state.accepted+=1;status('operation')
            operation_seconds = min(remaining(), max(.001,model_deadline-time.monotonic())) if s4 else remaining()
            response=worker.call('show_evidence',args,known_ids=grant['evidence_ids'],seconds=operation_seconds)
            guard()
            if response.get('evidence_state')!=view or response.get('database_changes')!=0:raise ValueError('READ_VIEW_INCONSISTENT')
            contracts.validate_output(response['result'])
            if any(r['id'] not in grant['evidence_ids'] for r in response['result']['records']):raise ValueError('ADDITIONAL_SCOPE_REQUIRED')
            if s4 and any(r['id'] != eid for r in response['result']['records']):
                raise ValueError('ADDITIONAL_SCOPE_REQUIRED')
            for record in response['result']['records']:
                source_ids=set(record.get('source_context',{}).get('source_ids',[]))
                if not source_ids or not source_ids<=set(grant['source_ids']) or record.get('source_type') not in grant['families']:
                    raise ValueError('ADDITIONAL_SCOPE_REQUIRED')
            transcript.append('result',dict(operation='show_evidence',response=response))
            activity.event('TOOL_COMPLETED',required=True,investigation_id=identity,tool_call_number=state.accepted,tool='show_evidence')
            state.ingest(response['result'],operation='show_evidence');pending.remove(eid)
            state.path.append({'operation':'show_evidence','evidence_id':eid})
            messages,exposure,size=packet(state,question,previous,eid);sizes.append(size)
            transcript.append('exposure',dict(content=exposure,prompt_bytes=size,prompt_sha256=digest(messages)))
            state.disclose(exposure);guard()
            if s4 and time.monotonic() >= model_deadline:
                stop = 'RESOURCE_BUDGET_EXHAUSTED'
                break
            status('model');phase='provider'
            # Use ordinary output allowance; no final synthesis request or hidden retry.
            if s4:
                transcript.append('analysis_request',dict(allocation='analysis',ordinal=requests+1,
                    grant_id=grant['id'],output_tokens=1024))
            requests+=1
            old_timeout = getattr(client,'timeout',None)
            if s4:
                client.timeout = max(.001,min(old_timeout or 120,model_deadline-time.monotonic()))
            request_started=time.monotonic()
            try:
                with model_operation('investigation'),final_output(False):raw=client.complete(messages,contracts.schema([]))
            finally:
                if s4:
                    if old_timeout is None:del client.timeout
                    else:client.timeout=old_timeout
            from .completion_diagnostics import observed
            transcript.append('analysis_response_diagnostic',dict(ordinal=requests,**observed(client,request_started)))
            guard();usage.append(deepcopy(getattr(client,'last_metadata',{}).get('usage') or None))
            try:
                proposal=contracts.request(raw,[]);findings=state.render(proposal['answer'])
            except ValueError as exc:
                from .rejection import rejected_response
                state.rejected+=1
                transcript.append('rejected',dict(stage='batch_validation',rejected_response=rejected_response(raw,exc,state)))
                stop='VALIDATION_FAILURE';break
            delta=dict(contract=DELTA,id=digest([identity,len(deltas),proposal]),evidence_state=view,
                disclosure_sha256=digest(exposure),proposal=proposal,findings=findings,batch=len(deltas)+1,
                counters=dict(ai_requests=requests,tool_calls=state.accepted),based_on=deltas[-1]['id'] if deltas else None)
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
                    validated_batches=len(deltas),evidence_state=view,question=question,engine=engine))
        if pending and stop=='AUTHORIZED_PLAN_EXHAUSTED':stop='RESOURCE_BUDGET_EXHAUSTED'
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
    except (OSError,ValueError,LLMError) as exc:
        reason=str(exc)
        stop=reason if reason in ('AUTHORIZATION_EXPIRED','AUTHORIZATION_CASE_CHANGED','ADDITIONAL_SCOPE_REQUIRED','PROVIDER_SCOPE_CHANGED','RESOURCE_BUDGET_EXHAUSTED','READ_VIEW_INCONSISTENT') else ('PROVIDER_FAILURE' if phase=='provider' else 'OPERATION_FAILURE')
        transcript.append('stopped',dict(reason=stop,error_type=type(exc).__name__))
        activity.event('TOOL_REJECTED','failure',required=True,investigation_id=identity,tool='show_evidence',reason=stop)
    finally:
        primary_stop=stop
        if b2:status('finalization')
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
    state=State(Budget());deltas=[];exposure=None
    for event in events:
        d=event['data']
        if event['kind']=='result':
            if d['response'].get('evidence_state')!=manifest['evidence_state'] or d['response'].get('database_changes')!=0:
                raise ValueError('Invalid recorded read view')
            contracts.validate_output(d['response']['result'])
            state.ingest(d['response']['result'],operation=d['operation'])
        elif event['kind']=='exposure':
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

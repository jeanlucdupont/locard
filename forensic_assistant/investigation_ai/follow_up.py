"""Opt-in temporal discovery. Original timestamps, not model-supplied indicators.

No evidence writes, provider calls or authorization renewal in this service.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import re
import time

from . import contracts, disclosure
from .transcript import digest
from forensic_assistant.retrieval.queries import required_time
from forensic_assistant.correlation.models import time_ns

CONTRACT = 'investigation-temporal-follow-up-v1'
LIMITS = dict(searches=2, returned_per_search=3, returned_total=6,
              distinct_disclosures=18, candidates_per_search=1000, search_seconds=5,
              radius_seconds=300, retries=0)
FAMILIES = ('browser', 'evtx', 'prefetch', 'mft', 'registry')
ARGS = contracts.obj({'evidence_id': contracts.string(160),
                      'field': contracts.string(128),
                      'family': contracts.enumeration(*FAMILIES)}, ('evidence_id', 'field', 'family'))
TOOL = contracts.obj({'action': contracts.enumeration('tool'),
                      'tool': contracts.enumeration('follow_up'), 'arguments': ARGS,
                      'reason': contracts.string(256)}, ('action', 'tool', 'arguments', 'reason'))
INSTRUCTION = ('You may instead return action tool, tool follow_up, arguments evidence_id, field, family, and reason. '
               'Use only a currently disclosed original /timestamps/N/utc or /timestamp_utc field. '
               'Locard searches up to five minutes either side inside the approved window and sources, returning at most three records. '
               'Two searches share six tool calls and six model attempts; no retries. '
               'Temporal proximity is not causality or execution. A search is not a finding. '
               'Return final to record observations for this batch; propose follow_up only when it can answer a concrete unresolved question.')


def supported(grant):
    from .context_inspection import CONTRACT as CONTEXT
    return grant.get('contract') in (CONTRACT,CONTEXT)


def shape(grant):
    from .context_inspection import CONTRACT as CONTEXT, LIMITS as CONTEXT_LIMITS
    contextual=grant.get('contract')==CONTEXT
    if contextual and grant.get('context_inspection')!=CONTEXT_LIMITS:raise ValueError('AUTHORIZATION_INVALID')
    if (not supported(grant) or grant.get('follow_up') != LIMITS
            or grant.get('tools') != (['show_evidence','follow_up','inspect_context'] if contextual else ['show_evidence','follow_up'])
            or not grant.get('families') or not set(grant['families']) <= set(FAMILIES)
            or grant.get('provider') != 'openai' or not grant.get('source_ids')
            or grant.get('limits') != dict(requests=6, steps=8, seconds=300, records=200,
                prompt_bytes=5600, tool_calls=6, tool_seconds=45, output_tokens=1024)):
        raise ValueError('AUTHORIZATION_INVALID')


def schema(contextual=False):
    result = contracts.schema([])
    result['oneOf'].insert(0, deepcopy(TOOL))
    if contextual:
        from .context_inspection import TOOL as CONTEXT_TOOL
        result['oneOf'].insert(0,deepcopy(CONTEXT_TOOL))
    return result


def parse(raw,contextual=False):
    value = contracts.loads(raw)
    if isinstance(value, dict) and value.get('action') == 'tool':
        if contextual and value.get('tool')=='inspect_context':
            from .context_inspection import TOOL as CONTEXT_TOOL
            contracts.validate(value,CONTEXT_TOOL)
        else:contracts.validate(value, TOOL)
        return value
    return contracts.request(raw, [])


def arguments(grant, args):
    shape(grant)
    contracts.validate(args, ARGS)
    if (not contracts.EID.fullmatch(args['evidence_id']) or args['family'] not in grant['families']
            or not re.fullmatch(r'/timestamps/(?:[0-9]|[12][0-9]|3[01])/utc|/timestamp_utc', args['field'])):
        raise ValueError('ADDITIONAL_SCOPE_REQUIRED')


def window(grant, args, value):
    arguments(grant, args)
    stamp = required_time(value)
    low, high = (required_time(grant[k]) for k in ('start', 'end'))
    if not time_ns(low) <= time_ns(stamp) < time_ns(high):
        raise ValueError('FOLLOW_UP_ANCHOR_OUTSIDE_WINDOW')
    # Shift whole seconds and retain the original nanosecond fractional digits;
    # datetime alone would silently reduce the derived interval to microseconds.
    dt = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    fmt = lambda d: d.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.')+stamp[20:29]+'Z'
    start = max((low, fmt(dt-timedelta(seconds=300))), key=time_ns)
    end = min((high, fmt(dt+timedelta(seconds=300))), key=time_ns)
    return dict(start=start, end=end, anchor=stamp, family=args['family'], source_ids=grant['source_ids'])


def proposed(grant, args, exposure):
    """Current request, not historical eligibility, authorizes the anchor premise."""
    arguments(grant, args)
    packet = disclosure.decode(exposure)
    for record in packet['records']:
        if record['id'] == args['evidence_id']:
            for observation in record['observations']:
                field = observation['field']
                if field['pointer'] == args['field']:
                    return window(grant, args, field['value'])
    raise ValueError('FOLLOW_UP_ANCHOR_NOT_DISCLOSED')


def record_window(grant, args, records):
    from .state import fields
    record = records.get(args['evidence_id'])
    if record is None:
        raise ValueError('FOLLOW_UP_ANCHOR_NOT_RETRIEVED')
    for pointer, value in fields(record):
        if pointer == args['field']:
            return window(grant, args, value)
    raise ValueError('FOLLOW_UP_ANCHOR_NOT_RETRIEVED')


def eligible(grant, record):
    sources = set(record.get('source_context', {}).get('source_ids', []))
    return bool(sources) and sources <= set(grant['source_ids']) and record.get('source_type') in grant['families']


def time_eligible(record, start, end):
    from .state import fields
    values = [v for p, v in fields(record) if re.fullmatch(r'/timestamps/\d+/utc|/timestamp_utc', p)]
    low, high = (time_ns(required_time(v)) for v in (start, end))
    return any(low <= time_ns(required_time(v)) < high for v in values)


def validate_result(grant, result, plan):
    if len(result['records']) > 3 or any(not eligible(grant, r) or r['source_type'] != plan['family'] for r in result['records']):
        raise ValueError('Invalid follow-up source/family')
    recorded = result.get('plan', {})
    if any(recorded.get(k) != v for k, v in plan.items()):
        raise ValueError('Invalid follow-up scope')
    if recorded.get('returned_ids') != [r['id'] for r in result['records']]:
        raise ValueError('Invalid follow-up identities')
    # The worker authorizes before projection. Replay also requires a retained
    # timestamp witnessing eligibility; omitted timestamps cannot prove scope.
    for record in result['records']:
        if not time_eligible(record, plan['start'], plan['end']):
            raise ValueError('Follow-up eligibility timestamp not retained')


def _search(db, grant, args, records):
    """Indexed bounded two-sided scan; authorize metadata before record content.

    Candidate entries are timestamp observations, not total matching records.
    Exhausting either side's 500-entry allowance is explicitly incomplete.
    The existing read-view interrupt and parent timeout bound SQL and projection.
    """
    from . import autonomous_policy as policy
    from .tools import envelope, compact
    from forensic_assistant.retrieval.evidence import get_evidence
    plan = record_window(grant, args, records)
    anchor = plan['anchor']; candidates = []
    started = time.monotonic(); complete = True
    for before in (True, False):
        clause = 't.timestamp_utc < ?' if before else 't.timestamp_utc >= ?'
        order = 'DESC' if before else 'ASC'
        rows = db.execute('SELECT t.timestamp_utc,t.evidence_id,t.slot FROM evidence_timestamps t INDEXED BY artifact_time '
            'CROSS JOIN evidence_records e ON e.evidence_id=t.evidence_id '
            'WHERE t.timestamp_utc>=? AND t.timestamp_utc<? AND '+clause+' AND e.source_type=? '
            'ORDER BY t.timestamp_utc '+order+',t.evidence_id '+order+',t.slot '+order+' LIMIT 501',
            (plan['start'], plan['end'], anchor, args['family'])).fetchall()
        complete &= len(rows) <= 500
        candidates.extend(tuple(row) for row in rows[:500])
    candidates.sort(key=lambda r: (abs(time_ns(required_time(r[0]))-time_ns(anchor)), r[0], r[1], r[2]))
    chosen = []; seen = set(records); evaluated = 0
    for stamp, eid, slot in candidates:
        if time.monotonic()-started >= LIMITS['search_seconds']:
            complete = False; break
        evaluated += 1
        if eid in seen: continue
        seen.add(eid)
        try:
            policy.record_scope(db, grant, eid, start=plan['start'], end=plan['end'])
        except ValueError as exc:
            if str(exc) != 'ADDITIONAL_SCOPE_REQUIRED': raise
            continue
        chosen.append(get_evidence(db, eid))
        if len(chosen) == 3:
            complete &= evaluated == len(candidates)
            break
    # Build the envelope empty: its ordinary relationship-support expansion must
    # not fetch additional records outside this search's independently checked IDs.
    result = envelope(db, 'follow_up', dict(records=[], truncated=not complete,
        limits=['Temporal neighbors are not causal or execution evidence. Previously retrieved records are excluded.']), limit=3)
    result['records'] = [compact(record) for record in chosen]
    result['returned_count'] = len(result['records'])
    result['relationships'] = []; result['detections'] = []
    result['truncated'] = not complete
    result['plan'] = dict(contract=CONTRACT, **plan, evaluated_candidates=evaluated,
        fetched_candidates=len(candidates), candidate_limit=1000, complete=complete,
        returned_ids=[r['id'] for r in result['records']], prior_records_excluded=True,
        limitation='Bounded temporal sample only; empty or incomplete results do not establish case-wide absence.')
    validate_result(grant, result, plan)
    return result


def search(db, grant, args, records):
    import threading
    timer=threading.Timer(LIMITS['search_seconds'],db.interrupt)
    timer.daemon=True;timer.start()
    try:return _search(db,grant,args,records)
    finally:timer.cancel();timer.join()


def validate_journal(manifest, events):
    """Validate recorded scope/dispatch and disclosure; never renew the grant."""
    grant = manifest['authorization']; shape(grant)
    exposure = None; pending = None; searches = []; calls = 0; requests = 0; records = {}; active = None
    ready = False; outstanding = False; context_keys=set(); context_calls=0
    from . import progress
    modern=manifest.get('progress_profile')==progress.PROFILE
    if manifest.get('progress_profile') not in (None,progress.PROFILE):raise ValueError('Unknown progress profile')
    completed=[];seeds=set(grant['evidence_ids']);forced=None;duplicate_count=0;last_context=None;analysis_only=False;continued=False;disclosed=set();finding_ids=set();redundancy_terminal=False
    for event in events:
        kind, data = event['kind'], event['data']
        if kind == 'exposure':
            if outstanding or active is not None:raise ValueError('Invalid follow-up disclosure sequence')
            exposure = data['content'];ready = True
            if modern:
                if data.get('operation_ledger')!=progress.ledger(completed,exposure):raise ValueError('Invalid operation ledger')
                analysis_only=requests>=5 or calls>=6 or continued
                continued=False
                if type(data.get('analysis_only')) is not bool or data['analysis_only']!=analysis_only:raise ValueError('Invalid final-analysis allocation')
        elif kind in ('follow_up_proposed','context_proposed'):
            if not outstanding or analysis_only:raise ValueError('Unrequested follow-up proposal')
            outstanding = False
            if kind=='context_proposed':
                from . import context_inspection as context
                contracts.validate(data['proposal'],context.TOOL)
                expected=context.proposed(grant,data['proposal']['arguments'],exposure)
            else:
                contracts.validate(data['proposal'], TOOL)
                expected = proposed(grant, data['proposal']['arguments'], exposure)
            if data['scope'] != expected or data['disclosure_sha256'] != digest(exposure):
                raise ValueError('Invalid follow-up origin')
            pending = data['proposal']['arguments']
            last_context=pending if kind=='context_proposed' else None
        elif kind=='redundant_context':
            if not modern or last_context is None or digest(last_context) not in context_keys:
                raise ValueError('Forged redundant context decision')
            expected=dict(reason='CONTEXT_DUPLICATE',arguments=last_context,next_seed=progress.continuation(seeds,requests,calls),
                          model_attempt=requests,tool_calls=calls)
            if data!=expected:raise ValueError('Invalid redundant context continuation')
            duplicate_count+=1;forced=data['next_seed'];pending=None;last_context=None
            redundancy_terminal=forced is None
        elif kind == 'authorized_operation':
            if redundancy_terminal:raise ValueError('Operation after terminal redundant proposal')
            if forced is not None:
                if data['tool']!='show_evidence' or data['arguments']!={'evidence_id':forced}:raise ValueError('Invalid continuation seed')
                forced=None;continued=True
            elif modern and last_context is not None and digest(last_context) in context_keys:
                raise ValueError('Missing redundant proposal decision')
            calls += 1
            if outstanding or active is not None or calls > 6 or data['grant_id'] != grant['id']: raise ValueError('Invalid follow-up allocation')
            if data['tool'] == 'follow_up':
                if pending != data['arguments']: raise ValueError('Unproposed follow-up')
                scope = record_window(grant, pending, records)
                key = digest(scope)
                if key in searches or len(searches) >= 2: raise ValueError('Invalid follow-up allocation')
                searches.append(key)
            elif data['tool']=='inspect_context':
                from . import context_inspection as context
                if pending!=data['arguments']:raise ValueError('Unproposed context inspection')
                context.proposed(grant,pending,exposure)
                key=digest(pending)
                if key in context_keys:raise ValueError('Duplicate context inspection')
                context_keys.add(key);context_calls+=1
            elif data['tool'] != 'show_evidence' or data['arguments'].get('evidence_id') not in grant['evidence_ids']:
                raise ValueError('Invalid seed authorization')
            active = data
        elif kind == 'result':
            result = data['response']['result']
            if active is None or data['operation'] != active['tool']: raise ValueError('Invalid follow-up result')
            for record in result['records']:
                if not eligible(grant, record): raise ValueError('Invalid follow-up source')
                if not time_eligible(record, grant['start'], grant['end']):raise ValueError('Invalid recorded temporal scope')
                if active['tool'] == 'show_evidence' and record['id'] != active['arguments']['evidence_id']:
                    raise ValueError('Invalid seed result')
            if active['tool'] == 'follow_up':
                validate_result(grant, result, scope)
                pending = None
            if active['tool']=='inspect_context':
                from . import context_inspection as context
                context.validate_result(grant,active['arguments'],result)
                pending=None;last_context=None
                completed.append(result)
            seeds.difference_update(r['id'] for r in result['records'])
            records.update((r['id'], r) for r in result['records'])
            if len(records)>18:raise ValueError('Invalid follow-up record allocation')
            active = None
        elif kind == 'follow_up_model_attempt':
            requests += 1
            if not ready or outstanding or data != dict(ordinal=requests, grant_id=grant['id']) or requests > 6:
                raise ValueError('Invalid follow-up model allocation')
            ready = False;outstanding = True
            disclosed.update(r['id'] for r in exposure['records'])
        elif kind == 'validated_delta' or (kind == 'rejected' and data.get('stage')=='batch_validation'):
            if not outstanding:raise ValueError('Unrequested follow-up analysis decision')
            outstanding = False
            if kind=='validated_delta':finding_ids.update(eid for row in data['findings']['observed']+data['findings']['interpretations'] for eid in row['evidence_ids'])
        elif kind == 'terminal':
            if data['metrics']['ai_requests'] != requests or data['state']['accepted_calls'] != calls:
                raise ValueError('Invalid follow-up terminal accounting')
            if modern:
                expected_families=dict(families_retrieved=progress.families(records),families_disclosed=progress.families(disclosed),families_in_findings=progress.families(finding_ids))
                if any(data['follow_up'].get(k)!=v for k,v in expected_families.items()):raise ValueError('Invalid evidence family accounting')
            if modern and data['follow_up'].get('redundant_context_proposals')!=duplicate_count:raise ValueError('Invalid duplicate accounting')
            if modern and data['follow_up'].get('context_completed')!=len(completed):raise ValueError('Invalid completion accounting')
            if 'context_inspections' in data.get('follow_up',{}) and data['follow_up']['context_inspections']!=context_calls:
                raise ValueError('Invalid context accounting')


def render(result, palette):
    from .presentation import safe, field_label, timestamp_text
    from .progress import families
    def text(value):
        return safe(re.sub(r'(https?://[^\s?#]+)[?#][^\s]*', r'\1?[query omitted]', str(value)))
    stats = result['follow_up']
    lines = [palette('heading', 'INVESTIGATION'), '', palette('warning', 'Status: Partial'),
        f"Evidence retrieved: {stats['records_returned']} records",
        f"Evidence disclosed: {stats['records_disclosed']} records",
        f"Evidence in accepted findings: {stats['records_examined']} records",
        f"Follow-up searches: {stats['executed']} executed / {stats['proposed']} proposed",
        f"Context inspections: {stats.get('context_inspections',0)}",
        'Artifact families retrieved: '+(', '.join(stats.get('families_retrieved',families(result['state'].get('retrieved_ids',[])))) or 'none'),
        'Artifact families disclosed: '+((', '.join(stats['families_disclosed']) or 'none') if 'families_disclosed' in stats else 'not recorded separately'),
        'Artifact families in accepted findings: '+(', '.join(stats.get('families_in_findings',families(e for row in result['findings']['observed']+result['findings']['interpretations'] for e in row['evidence_ids']))) or 'none'),
        'Context inspections completed: '+str(stats.get('context_completed',stats.get('context_inspections',0)))+'; redundant proposals rejected: '+str(stats.get('redundant_context_proposals',0)),
        'Context inspections not completed: '+str(stats.get('context_inspections',0)-stats.get('context_completed',stats.get('context_inspections',0))),
        '', palette('heading', 'Investigative observations')]
    if stats.get('no_findings_reason'):lines.append('  '+palette('warning',text(stats['no_findings_reason'])))
    qualifications=[]
    for row in result['findings'].get('observed', []):
        label, is_time = field_label(row)
        value = text(row['reported_value'])
        lines.extend(['  '+label+': '+palette('value', timestamp_text(value) if is_time else safe(value)),
                      '    Evidence: '+safe(', '.join(row['evidence_ids']))])
        if row.get('qualifier'):qualifications.append(text(row['qualifier']))
        if row.get('truncated_fields') or row.get('coverage_notes'):
            qualifications.append('Bounded record projection; some fields are truncated or omitted.')
    if qualifications:
        lines+=['',palette('heading','Observation qualifications')]+['  '+palette('forensic_note',q) for q in dict.fromkeys(qualifications)]
    for title,key in [('Deterministic interpretations — derived','interpretations'),
                      ('Evidence-backed relationships','deterministically_correlated'),
                      ('Corroborated evidence','corroborated'),
                      ('Unresolved relationships','unresolved_relationships'),
                      ('Detections — not proof of compromise','detections')]:
        if result['findings'].get(key):
            lines+=['',palette('heading',title)]
            for row in result['findings'][key]:
                lines+=['  '+text(row.get('text') or row.get('relationship') or row.get('rule_name','Recorded relationship')),
                        '    Evidence: '+text(', '.join(row['evidence_ids']))]
                if row.get('status'):lines.append('    Status: '+text(row['status']))
                if row.get('derivation_id'):lines.append('    Interpretation: '+text(row['derivation_id']))
                for note in row.get('limitations',[]):lines.append('    '+palette('forensic_note',text(note)))
    if result['findings'].get('hypotheses'):
        lines+=['',palette('heading','Hypotheses — unverified')]
        for row in result['findings']['hypotheses']:
            lines.append('  '+text(row['statement']))
            lines.extend('    Alternative: '+text(v) for v in row['alternatives'])
            lines.append('    Evidence: '+text(', '.join(row['evidence_ids'])))
    lines += ['', palette('heading', 'Unresolved questions')]
    lines += ['  '+text(q) for q in concise_questions(result['findings'].get('model_proposed_unknowns', []))]
    if not result['findings'].get('model_proposed_unknowns'):lines.append('  '+palette('unknown','No validated answer to the overall question; coverage remains partial.'))
    lines += ['', palette('heading', 'Coverage limitations')]
    lines += ['  '+palette('forensic_note', text(note)) for note in result['limitations']]
    lines += ['  '+palette('forensic_note','Source metadata is analyst-supplied; temporal proximity is not a verified host or causal relationship.')]
    for search in stats['searches']:
        lines.append('  '+text(search['family'])+': '+str(len(search['returned_ids']))+' returned; '+('bounded neighborhood completed' if search['complete'] else 'incomplete candidate/result coverage'))
    if result.get('failure_diagnostic'):
        from .failure_diagnostics import validate as validate_diagnostic
        detail=result['failure_diagnostic'];validate_diagnostic(detail)
        lines.append('  Phase: '+detail['phase']+'; operation: '+detail['operation']+'; code: '+detail['code'])
    failure=result['termination'] in ('EVIDENCE_PACKET_VALIDATION_FAILED','WORKER_FAILURE','INTERNAL_FAILURE','AUDIT_OR_PERSISTENCE_FAILURE','OPERATION_FAILURE','PROVIDER_FAILURE','VALIDATION_FAILURE','READ_VIEW_INCONSISTENT','INTEGRITY_UNCONFIRMED','CLEANUP_LIMITATION')
    lines += ['  Termination: '+palette('error' if failure else 'warning',safe(result['termination'])),
              '  Next suggested action: review recorded scope and omitted evidence before authorizing further work.']
    return '\n'.join(lines)


def concise_questions(questions):
    """Presentation-only conservative near-duplicate grouping; history is intact."""
    result=[];seen=[]
    for q in questions:
        tokens=set(re.findall(r"[\w]+",q.casefold()))-{'the','a','an','is','are','was','were','what','which','please','can','we'}
        if tokens in seen:continue
        seen.append(tokens);result.append(q)
    return result

"""Analyst-authorized deterministic assessment; one worker-owned read view per pass."""
import copy
import json
import time
import uuid
from collections import deque
from . import briefing
from .briefing_store import Store, digest, now
from .assessment_store import AssessmentStore
from .briefing_workflow import read_answer
from .interactive.console import safe
from .investigation_ai.runner import ForensicWorker, WorkerError

POLICY={'seconds':300,'queries':120,'candidates':100000,'records':500,'bytes':2*1024*1024,'leads':12,
        'records_per_query':10,'query_seconds':15}


def inventory(case,worker_factory):
    with worker_factory(dict(case_path=str(case),semantic_enabled=False,_transaction_view=True,
                             _briefing_initial=True,_briefing_all=True,_deadline=time.monotonic()+20)) as worker:
        result=worker.call('initial',question='',seconds=10)
        worker.call('check',seconds=5)
        return result['result']['available_artifacts']


def plan(revision,case,available,start,end):
    from .briefing_canonical import check_envelope
    from .briefing_semantics import technical
    briefing.window(start,end,source='explicit assessment authorization')
    canonical=revision['content'].get('canonical')
    if not canonical:raise ValueError('Accept the structured briefing before assessing the case')
    check_envelope(canonical)
    document=canonical['document'];leads={};excluded=[]
    for category,items in document['categories'].items():
        for i,item in enumerate(items):
            ref=f'{category}:{i}'
            if item['status']!='provided' or item['polarity']!='reported' or not item['value']:
                excluded.append({'field':ref,'value':item['value'],'reason':'Missing, ambiguous, approximate or non-affirmative entry'})
                continue
            kind=item['kind'];value=item['value']
            try:
                if kind=='activity' and len(value.encode())<=256:
                    kind='term';normalized=value
                else:normalized=technical(kind,value)
            except ValueError:
                excluded.append({'field':ref,'value':value,'reason':'Not a validated technical search indicator'});continue
            lead={'id':'A-'+digest([kind,normalized])[:16],'type':kind,'normalized':normalized,
                  'classification':'exact','negated':False,'occurrences':[{'original':value}],
                  'boundary_source_literal':True,'hostname_basis':'explicit_label'}
            routes=[briefing.query_for(lead,f,start,end,cross=True) for f in briefing.ARTIFACTS]
            if not any(routes):
                excluded.append({'field':ref,'value':value,'reason':'No supported deterministic search route'});continue
            if lead['id'] not in leads:
                if len(leads)>=POLICY['leads']:
                    excluded.append({'field':ref,'value':value,'reason':'Assessment lead limit'});continue
                lead['fields']=[];leads[lead['id']]=lead
            leads[lead['id']]['fields'].append(ref)
    rows=[]
    for lead in leads.values():
        for family in briefing.ARTIFACTS:
            query=briefing.query_for(lead,family,start,end,cross=True)
            status='unavailable' if family not in available else 'unsupported' if query is None else 'not_searched'
            rows.append(dict(lead_id=lead['id'],artifact=family,query=query,status=status,candidates=0,pages=0,
                             candidate_count_known=True,evidence_ids=[],cursor=None,seen_cursors=[],coverage={},limitations=[]))
    return dict(case=case,revision=revision['revision'],digest=revision['digest'],start=start,end=end,
                objectives=[r['value'] for r in document['categories']['objectives'] if r['value']],
                **({'editorial_summary':document['summary']['text']} if document['summary']['status']=='accepted' else {}),
                reported_times=copy.deepcopy(document['categories']['when']),
                leads=list(leads.values()),excluded=excluded,rows=rows,policy=dict(POLICY))


def plan_text(p):
    lines=['INITIAL CASE ASSESSMENT — proposed read-only discovery',f"Case: {p['case']['path']}",
           f"Briefing revision: {p['revision']}",'Investigation objectives:']
    lines += ['  '+v for v in p['objectives']] or ['  Structured objectives unavailable.']
    if p.get('editorial_summary'):
        from .assessment_display import prose
        lines += ['  Accepted editorial summary (unverified context, not structured objectives): '+prose(p['editorial_summary'])]
    from .assessment_display import reported_time
    lines += reported_time(p['reported_times'])
    lines += ['Authorized window: '+p['start']+' to '+p['end'], 'Proposed discovery:']
    for lead in p['leads']:
        families=[r['artifact'] for r in p['rows'] if r['lead_id']==lead['id'] and r['status']=='not_searched']
        lines.append('  '+lead['id']+' '+lead['occurrences'][0]['original']+' ['+('contextual search term' if lead['type']=='term' else lead['type'])+'] => '+(', '.join(families) or 'none available'))
    lines += ['  Excluded '+r['field']+': '+r['value']+' — '+r['reason'] for r in p['excluded']]
    lines += ['Limits: '+json.dumps(p['policy'],sort_keys=True),
              'Supported fields only; basename matches do not prove file identity or execution. No AI requests.']
    return '\n'.join(safe(line) for line in lines)


def timeline(records):
    rows=[]
    for eid,record in records.items():
        for stamp in record['match'].get('timestamps',[]):
            if stamp.get('timestamp_utc'):
                rows.append(dict(evidence_id=eid,artifact=record['artifact'],timestamp_utc=stamp['timestamp_utc'],
                    **{k:str(stamp.get(k,''))[:256] for k in ('slot','meaning','source','normalization_status')},
                    inherited_from_key=bool(stamp.get('inherited_from_key'))))
    return sorted(rows,key=lambda r:(r['timestamp_utc'],r['evidence_id'],r.get('slot','')))


def execute(p,store,*,worker_factory=ForensicWorker,progress=lambda text:None,parent=None):
    from .investigation_ai.conclusions import interpretations
    from . import activity
    started=time.monotonic();rows=copy.deepcopy(p['rows'])
    result=dict(kind='case_assessment',id=uuid.uuid4().hex,created=now(),case=store.identity,
        plan=copy.deepcopy(p),authorization={'approved':True,'at':now(),'plan_digest':digest(p)},
        parent=parent,status='RUNNING',rows=rows,records={},timeline=[],interpretations=[],
        metrics={'queries':0,'candidates':0,'bytes':0,'elapsed_seconds':0},evidence_state=None,
        integrity_verified=False,warnings=['Preliminary deterministic discovery, not a completed forensic examination.',
            'Analyst briefing statements are unverified. Matching indicators do not confirm the whole narrative.',
            'Historical read view only: current evidence equality is not established.',
            'Candidate counts cover instrumented EVTX/object searches; other SQL scan counts are not reported.'])
    if parent:result['warnings'].append('New read view: approved searches restarted; prior observations/cursors are not merged.')
    def notify(text):
        result['metrics']['elapsed_seconds']=time.monotonic()-started
        if hasattr(progress,'assessment_update'):progress.assessment_update(text,result)
        else:progress(text)
    store.save_assessment(result)
    eligible=[r for r in rows if r['status']=='not_searched']
    order={lead['id']:i for i,lead in enumerate(p['leads'])}
    eligible.sort(key=lambda r:(0 if 'object_basename' in r['query'] else 2 if 'evtx_text' in r['query'] else 1,
                                briefing.ARTIFACTS.index(r['artifact']),order[r['lead_id']]))
    queue=deque(eligible);used_bytes=0
    try:
        with worker_factory(dict(case_path=store.identity['path'],semantic_enabled=False,_transaction_view=True,
                _briefing_initial=True,_briefing_all=True,_deadline=started+POLICY['seconds'])) as worker:
            initial=worker.call('initial',question='',seconds=10);result['evidence_state']=initial.get('evidence_state')
            if not result['evidence_state']:raise WorkerError('Missing read view identity')
            current_families=initial['result']['available_artifacts']
            for row in rows:
                if row['status']=='not_searched' and row['artifact'] not in current_families:
                    row['status']='unavailable';row['limitations'].append('No records of this family in the execution read view')
                elif row['status']=='unavailable' and row['artifact'] in current_families:
                    row['status']='not_searched';row['limitations'].append('Family became available after planning; outside approved scope')
            queue=deque(r for r in queue if r['status']=='not_searched')
            while queue:
                m=result['metrics'];remaining=POLICY['seconds']-5-(time.monotonic()-started)
                if remaining<=0 or m['queries']>=POLICY['queries'] or m['candidates']+1000>POLICY['candidates'] or len(result['records'])+10>POLICY['records']:break
                row=queue.popleft();query=copy.deepcopy(row['query'])
                if row['cursor']:
                    query['object_after' if 'object_basename' in query else 'evtx_after']=row['cursor']
                m['queries']+=1
                row['status']='incomplete'
                notify(f"{row['artifact']} Searching — query {m['queries']}; {time.monotonic()-started:.1f}s elapsed")
                activity.event('BRIEFING_LOOKUP','pending',lead_id=row['lead_id'],artifact=row['artifact'])
                try:
                    reply=worker.call('briefing_search',query,seconds=min(POLICY['query_seconds'],remaining))
                    if reply.get('evidence_state')!=result['evidence_state']:raise WorkerError('Read view changed')
                    payload=reply['result']
                except WorkerError:
                    row['status']='failed';row['limitations'].append('Lookup failed; no absence conclusion.')
                    notify(f"{row['artifact']} failed — observed counts retained; no absence conclusion")
                    activity.event('BRIEFING_LOOKUP','failure',lead_id=row['lead_id'],artifact=row['artifact'])
                    check=worker.call('check',seconds=min(5,max(.001,remaining)))
                    if check.get('evidence_state')!=result['evidence_state']:raise WorkerError('Read view changed')
                    store.save_assessment(result);continue
                size=len(json.dumps(payload,ensure_ascii=True).encode())
                if used_bytes+size>POLICY['bytes']:
                    row['status']='incomplete';row['limitations'].append('Payload bound; last page not retained');break
                used_bytes+=size;m['bytes']=used_bytes
                coverage=payload.get('object_search',payload.get('content_search',{}))
                examined=coverage.get('examined')
                if isinstance(examined,int):row['candidates']+=examined;m['candidates']+=examined
                else:row['candidate_count_known']=False
                row['pages']+=1;row['coverage']=coverage;row['limitations']=payload.get('limitations',[])
                exposed={r['id']:r for r in payload['records']}
                for match in payload.get('matches',[]):
                    eid=match['evidence_id']
                    if eid not in row['evidence_ids']:row['evidence_ids'].append(eid)
                    if eid not in result['records']:
                        compact=exposed.get(eid,{})
                        result['records'][eid]=dict(artifact=row['artifact'],match=match,lead_ids=[],
                            source_context=compact.get('source_context',{}),
                            presentation={k:compact[k] for k in ('artifact_type','kind','provider','event_id','process_name','browser_product','profile','truncated_fields') if k in compact},matched_fields_by_lead={},relations='No causal relationship inferred')
                        for interpretation in interpretations(compact).values():
                            result['interpretations'].append(dict(evidence_id=eid,**interpretation))
                    record=result['records'][eid]
                    record['matched_fields_by_lead'][row['lead_id']]=match['matched_fields']
                    if row['lead_id'] not in record['lead_ids']:record['lead_ids'].append(row['lead_id'])
                complete=coverage.get('complete',not payload['coverage'].get('matching_total_is_lower_bound',False) and
                    (payload['coverage'].get('matching_total') or 0)<=len(payload.get('matches',[])))
                row['status']=('match' if row['evidence_ids'] else 'no_match') if complete else 'incomplete'
                cursor=coverage.get('next_cursor')
                if not complete and cursor and cursor not in row['seen_cursors']:
                    row['seen_cursors'].append(cursor);row['cursor']=cursor;queue.append(row)
                elif not complete and cursor:
                    row['limitations'].append('Repeated continuation stopped')
                else:row['cursor']=None
                m['elapsed_seconds']=time.monotonic()-started
                notify(f"{row['artifact']} {row['status']} — {row['candidates'] if row['candidate_count_known'] else 'unreported'} candidates examined; {len(row['evidence_ids'])} matching records; {m['elapsed_seconds']:.1f}s elapsed")
                activity.event('BRIEFING_LOOKUP','success',lead_id=row['lead_id'],artifact=row['artifact'],returned_count=len(payload.get('matches',[])))
                store.save_assessment(result)
            check=worker.call('check',seconds=5)
            result['integrity_verified']=check.get('evidence_state')==result['evidence_state']
            if not result['integrity_verified']:raise WorkerError('Read view changed')
        result['status']='COMPLETE' if result['metrics']['queries'] and all(r['status'] in ('match','no_match','unavailable','unsupported') for r in rows) else 'COMPLETE_WITH_LIMITATIONS'
    except KeyboardInterrupt:
        result['status']='CANCELLED';result['warnings'].append('Analyst interrupted discovery; retained observations are partial.')
    except (WorkerError,OSError,RuntimeError,ValueError):
        result['status']='FAILED';result['integrity_verified']=False;result['warnings'].append('Worker/read-view/persistence failure; final consistency or cleanup may be unconfirmed.')
    result['metrics']['elapsed_seconds']=time.monotonic()-started
    chronology=timeline(result['records'])
    result['timeline']=chronology[:2000]
    if len(chronology)>2000:result['warnings'].append('Timeline projection truncated at 2,000 observations; record timestamps remain in saved projections.')
    store.save_assessment(result)
    return result


def render(result,details=False):
    if result.get('message'):return result['message']
    if result['kind']=='assessment_history':
        return '\n'.join(safe(f"{r['id']}  {r['created']}  {r['status']}  briefing revision {r['revision']}") for r in result['assessments']) or 'No saved assessments.'
    from .assessment_display import render as display
    return display(result,details=details)

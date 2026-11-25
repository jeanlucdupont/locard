"""Explicit extended-session authority and deterministic work-batch receipts."""
from copy import deepcopy
from .transcript import digest

CONTRACT = 'investigation-context-extended-v1'
PROFILE = dict(batches=3, requests=6, operations=6, searches=2, retries=0)
LIMITS = dict(requests=18, steps=24, seconds=900, records=200,
              prompt_bytes=24576, tool_calls=18, tool_seconds=45, output_tokens=1024)
FOLLOW = dict(searches=6, returned_per_search=3, returned_total=18,
              distinct_disclosures=30, candidates_per_search=1000, search_seconds=5,
              radius_seconds=300, retries=0)


def enabled(grant):
    return grant.get('contract') == CONTRACT


def authorize(grant):
    from .context_inspection import CAPACITY_CONTRACT
    if grant['contract'] != CAPACITY_CONTRACT:
        raise ValueError('Extended investigation requires context follow-up')
    return {**grant, 'contract':CONTRACT, 'limits':deepcopy(LIMITS),
            'follow_up':deepcopy(FOLLOW), 'work_batches':deepcopy(PROFILE)}


def shape(grant):
    from . import follow_up, context_inspection
    if grant.get('limits') != LIMITS or grant.get('work_batches') != PROFILE or grant.get('follow_up') != FOLLOW:
        raise ValueError('AUTHORIZATION_INVALID')
    follow_up.shape({**grant, 'contract':context_inspection.CAPACITY_CONTRACT,
                    'limits':{**LIMITS, 'requests':6,'steps':8,'seconds':300,'tool_calls':6},
                    'follow_up':follow_up.LIMITS})


def receipt(number, requests, operations, searches, deltas, pending, records, reason, start=(0,0,0)):
    facts={digest(row):row for d in deltas for key in ('observed','interpretations') for row in d['findings'].get(key,[])}
    return dict(contract='investigation-work-batch-v1', batch=number,
                totals=dict(ai_requests=requests, operations=operations, searches=searches),
                batch_usage=dict(ai_requests=requests-start[0],operations=operations-start[1],searches=searches-start[2]),
                records_examined=sorted({e for row in facts.values() for e in row['evidence_ids']}),validated_findings=len(facts),
                validated_deltas=[d['id'] for d in deltas], findings_digest=digest([d['findings'] for d in deltas]),
                unresolved=list(dict.fromkeys(q for d in deltas for q in d['findings'].get('model_proposed_unknowns',[]))),
                pending_ids=sorted(pending), retrieved_ids=sorted(records), reason=reason)


def validate_checkpoints(manifest, events):
    """Recompute receipts from recorded operations/grounded deltas, not AI summaries."""
    if not enabled(manifest.get('authorization',{})):return
    shape(manifest['authorization'])
    pending=set(manifest['authorization']['evidence_ids']);records=set();deltas=[]
    requests=operations=searches=0;number=1;start=(0,0,0);closed=False;receipts=[];last_operation=None
    for event in events:
        kind,data=event['kind'],event['data']
        if kind in ('authorized_operation','follow_up_model_attempt') and closed:
            raise ValueError('Work after closed batch')
        if kind=='authorized_operation':
            operations+=1;searches+=int(data['tool']=='follow_up')
        elif kind=='follow_up_model_attempt':requests+=1
        elif kind=='result':
            ids={r['id'] for r in data['response']['result']['records']};records.update(ids);pending.difference_update(ids)
            if data['operation']=='show_evidence':pending.discard(last_operation['arguments']['evidence_id'])
        elif kind=='validated_delta':deltas.append(data)
        elif kind=='work_batch_checkpoint':
            expected=receipt(number,requests,operations,searches,deltas,pending,records,data.get('reason'),start)
            if data!=expected or data['reason'] not in ('BATCH_RESOURCE_LIMIT','NO_FURTHER_AUTHORIZED_LEADS','SESSION_STOPPED'):
                raise ValueError('Invalid work-batch checkpoint')
            if data['reason']=='NO_FURTHER_AUTHORIZED_LEADS' and pending:raise ValueError('Pending authorized leads')
            if data['reason']=='BATCH_RESOURCE_LIMIT' and max(requests-start[0],operations-start[1])<6:raise ValueError('Unexhausted batch')
            if closed:raise ValueError('Duplicate batch checkpoint')
            receipts.append(data)
            closed=True
        elif kind=='work_batch_started':
            if not closed or expected['reason']!='BATCH_RESOURCE_LIMIT' or not pending or number>=3 or data!={'batch':number+1,'previous_checkpoint':digest(expected)}:
                raise ValueError('Invalid work-batch transition')
            number+=1;start=(requests,operations,searches);closed=False
        elif kind=='terminal' and data.get('work_batches')!=receipts:
            raise ValueError('Invalid terminal work-batch accounting')
        if requests-start[0]>6 or operations-start[1]>6 or searches-start[2]>2:
            raise ValueError('Work-batch allocation exceeded')
        if requests>18 or operations>18 or searches>6:raise ValueError('Extended allocation exceeded')
        if kind=='authorized_operation':last_operation=data


def summary(value):
    t=value['totals']
    return (f"Batch {value['batch']} / 3 — {value['reason']}\n"
            f"AI requests: {t['ai_requests']} / 18 | Evidence operations: {t['operations']} / 18 | "
            f"Records retrieved: {len(value['retrieved_ids'])} | Records in findings: {len(value['records_examined'])} | Validated findings: {value['validated_findings']}\n"
            f"Unresolved questions (unverified): {len(value['unresolved'])} | Pending authorized seeds: {len(value['pending_ids'])}")

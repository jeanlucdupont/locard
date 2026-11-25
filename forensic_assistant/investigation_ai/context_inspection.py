"""Bounded EVTX context inspection in the existing authorized read view."""
import re
from . import contracts, disclosure

CONTRACT = 'investigation-context-follow-up-v1'
CAPACITY_CONTRACT = 'investigation-context-follow-up-v2'
INPUT_BYTES = 24576

def supported(grant):
    from .extended import CONTRACT as EXTENDED
    return grant.get('contract') in (CONTRACT,CAPACITY_CONTRACT,EXTENDED)

LIMITS = dict(family='evtx', categories=['event','actor','object','process'], fields=8, bytes=1800)
ARGS = contracts.obj({'evidence_id':contracts.string(160),
    'category':contracts.enumeration(*LIMITS['categories'])}, ('evidence_id','category'))
TOOL = contracts.obj({'action':contracts.enumeration('tool'), 'tool':contracts.enumeration('inspect_context'),
    'arguments':ARGS, 'reason':contracts.string(256)}, ('action','tool','arguments','reason'))
INSTRUCTION = (' Use inspect_context with arguments evidence_id, category (event, actor, object, process), and reason '
    'to inspect a disclosed EVTX record before declaring its context unavailable. It shares the six tool calls; '
    'it cannot search. Only newly disclosed original fields may support observations. Missing context is unknown.')


def category(name):
    name=re.sub('[^a-z0-9]','',str(name).casefold())
    if any(x in name for x in ('subject','account','user','logon','sid')):return 'actor'
    if any(x in name for x in ('object','access','permission','securitydescriptor','handle')):return 'object'
    if any(x in name for x in ('process','command','image','executable','parent')):return 'process'
    return 'event'


def arguments(grant,args):
    from .follow_up import shape
    shape(grant)
    if not supported(grant):raise ValueError('ADDITIONAL_SCOPE_REQUIRED')
    contracts.validate(args,ARGS)
    if not contracts.EID.fullmatch(args['evidence_id']) or not args['evidence_id'].startswith('EVTX:'):
        raise ValueError('ADDITIONAL_SCOPE_REQUIRED')


def proposed(grant,args,exposure):
    arguments(grant,args)
    if args['evidence_id'] not in {r['id'] for r in disclosure.decode(exposure)['records']}:
        raise ValueError('CONTEXT_RECORD_NOT_DISCLOSED')
    return dict(contract=CONTRACT,**args)


def inspect(db,grant,args,records):
    from . import autonomous_policy as policy, tools
    from forensic_assistant.retrieval.evidence import get_evidence
    from forensic_assistant.retrieval.event_data import payload
    arguments(grant,args)
    if args['evidence_id'] not in records:raise ValueError('CONTEXT_RECORD_NOT_RETRIEVED')
    policy.record_scope(db,grant,args['evidence_id'])
    raw=get_evidence(db,args['evidence_id'])
    entries,notes=payload(raw)
    # Event overview favors named contextual fields over unrelated bulk values.
    selected=sorted(entries,key=lambda e:(category(e['name'])!=args['category'] if args['category']!='event'
        else category(e['name'])=='event',e['ordinal']))
    if args['category']!='event':selected=[e for e in selected if category(e['name'])==args['category']]
    chosen=[]
    for entry in selected:
        item=dict(entry,truncated=False)
        if len(chosen)>=LIMITS['fields']:break
        if len(disclosure.encoded(chosen+[item]).encode())<=LIMITS['bytes']:chosen.append(item)
    record=tools.compact(raw)
    record['original_event_data']=chosen
    record['context_category']=args['category']
    record['event_data_limitations']=list(notes)
    if len(chosen)<len(entries):record['event_data_limitations'].append('Context is a bounded category selection; omitted fields are not evidence of absence.')
    if not chosen:record['event_data_limitations'].append('No complete fields for this category fit the retained-data bounds; context remains unknown.')
    # Existing projection qualifiers are conservative and must not be removed.
    record.setdefault('coverage_notes',[]).extend(record['event_data_limitations'])
    result=tools.envelope(db,'inspect_context',dict(records=[]),limit=1)
    result.update(records=[record],returned_count=1,relationships=[],detections=[],truncated=len(chosen)<len(entries),
        plan=dict(contract=CONTRACT,**args,selected_ordinals=[e['ordinal'] for e in chosen],
                  retained_fields=len(entries),omitted_fields=len(entries)-len(chosen),limitations=record['event_data_limitations']))
    validate_result(grant,args,result)
    return result


def validate_result(grant,args,result):
    from .follow_up import eligible,time_eligible
    arguments(grant,args);contracts.validate_output(result)
    rows=result['records'];plan=result.get('plan',{})
    if len(rows)!=1 or rows[0]['id']!=args['evidence_id']:raise ValueError('Invalid context identity')
    r=rows[0];entries=r.get('original_event_data',[])
    if type(entries) is not list or any(type(e) is not dict or set(e)!= {'ordinal','name','value','truncated'}
        or type(e['ordinal']) is not int or not 0<=e['ordinal']<256 or type(e['name']) is not str
        or (e['value'] is not None and type(e['value']) is not str) or e['truncated'] is not False for e in entries):
        raise ValueError('Invalid original context fields')
    if (r.get('source_type')!='evtx' or not eligible(grant,r) or not time_eligible(r,grant['start'],grant['end'])
        or r.get('context_category')!=args['category'] or any(plan.get(k)!=v for k,v in dict(contract=CONTRACT,**args).items())
        or len(entries)>8 or len(disclosure.encoded(entries).encode())>1800
        or plan.get('selected_ordinals')!=[e['ordinal'] for e in entries]
        or len(set(plan['selected_ordinals']))!=len(entries)
        or any(e.get('truncated') is not False or (args['category']!='event' and category(e['name'])!=args['category']) for e in entries)
        or type(plan.get('retained_fields')) is not int or not len(entries)<=plan['retained_fields']<=256
        or plan.get('omitted_fields')!=plan['retained_fields']-len(entries)):
        raise ValueError('Invalid context projection')

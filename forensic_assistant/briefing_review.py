"""Deterministic review annotations over structured entries, never narrative inference."""
CATEGORY_DEFINITIONS = {
    'incident': 'Analyst account of what happened, distinct from the AI summary.',
    'when': 'Dates/times, approximation and timezone; preserve unknowns.',
    'person': 'Individuals, not account identities.',
    'account': 'Windows/domain/application accounts.',
    'systems': 'Devices and hostnames.',
    'user_experience': 'What the user saw, attempted, experienced or reported.',
    'user_actions': 'Clicks/downloads/opening/execution attempts.',
    'files': 'Filenames, paths and attachments.',
    'websites': 'Observed domains/URLs; not necessarily delivery.',
    'origin': 'Reported delivery channel/source; retain suspected/confirmed-by-analyst/incomplete status.',
    'activity': 'Apps/scripts/commands/mechanisms/relationships.',
    'alerts': 'Security alerts/products/event IDs/enforcement actions.',
    'indicators': 'IPs/hashes/Registry keys and other indicators.',
    'scope': 'Affected systems/accounts.',
    'response': 'Human analyst/SOC/user/team response or remediation, not automatic product enforcement.',
    'records': 'Available screenshots/reports/logs/forensic sources.',
    'objectives': 'Questions to establish, not findings.',
    'context': 'Other context.'}


def category(candidate, fallback):
    """Categories are analyst-reviewable proposals, not truth assertions."""
    return candidate.get('category') or fallback,None


def assess(document, diagnostics=None):
    from .briefing_canonical import TYPE_CATEGORY
    diagnostics=diagnostics or {};categories=document['categories'];result={}
    rejected=diagnostics.get('rejected_items',[])
    for key,items in categories.items():
        rules=[r['rule'] for r in rejected if r.get('component')=='candidate' and
               (r.get('category')==key or TYPE_CATEGORY.get(r.get('candidate_type'))==key)]
        elsewhere=[source for source,values in categories.items() if source!=key and
                   any(TYPE_CATEGORY.get(v['kind'])==key for v in values)]
        state='populated' if items else 'validation_rejected' if rules else 'assigned_elsewhere' if elsewhere else 'coverage_unknown'
        if items and all(v['status']=='unknown' for v in items):state='explicit_unknown'
        if items and all(v['status']=='not_provided' for v in items):state='explicit_not_provided'
        if items and all(v['status']=='not_applicable' for v in items):state='explicit_not_applicable'
        result[key]={'state':state,'rejection_rules':sorted(set(rules)),'related_categories':elsewhere}
    # Relationships between category definitions warrant review, not new facts.
    related={'incident':('user_experience','user_actions','activity'),
             'user_experience':('user_actions','activity'), 'origin':('websites','user_actions'),
             'alerts':('response',)}
    for key,others in related.items():
        if not categories[key] and result[key]['state']=='coverage_unknown':
            present=[name for name in others if categories[name]]
            if present:result[key].update(state='possible_classification_gap',related_categories=present)
    summary=document['summary'];checks=[]
    if summary['text'] and summary['status']!='rejected':
        text=summary['text'].casefold()
        for key in ('person','systems'):
            missing=[i for i,item in enumerate(categories[key]) if item['value'] and item['polarity']!='negated'
                     and item['status'] in ('provided','approximate') and item['value'].casefold() not in text]
            if missing:checks.append({'rule':'possible_summary_entity_omission','category':key,'item_indexes':missing})
        checks.append({'rule':'analyst_summary_review'})
    return {'categories':result,'summary_checks':checks,
            'source_coverage':diagnostics.get('source_coverage'),
            'normalizations':diagnostics.get('normalizations',[]),
            'meaning':'Review annotations, not semantic entailment or evidence findings.'}


def move_metadata(original,source,index,target,new_index):
    """Keep proposal provenance attached to the moved item, not its old index."""
    for name in ('references','classification_origins'):
        mapping=original.get(name,{})
        moved=mapping.pop(f'{source}:{index}',None)
        shifted={}
        for key,value in mapping.items():
            parts=key.rsplit(':',1)
            if len(parts)==2 and parts[0]==source and parts[1].isdigit() and int(parts[1])>index:
                key=f'{source}:{int(parts[1])-1}'
            shifted[key]=value
        if moved is not None:shifted[f'{target}:{new_index}']=moved
        original[name]=shifted
    original.setdefault('category_reviews',[]).append({'from':source,'to':target,'item_index':new_index,
                                                     'decision':'analyst_category_change_not_value_verification'})



def remove_metadata(original,category,index):
    """Remove an item without attaching its references to the next item."""
    for name in ('references','classification_origins'):
        mapping=original.get(name,{})
        result={}
        for key,value in mapping.items():
            if key==f'{category}:{index}':continue
            parts=key.rsplit(':',1)
            if len(parts)==2 and parts[0]==category and parts[1].isdigit() and int(parts[1])>index:
                key=f'{category}:{int(parts[1])-1}'
            result[key]=value
        original[name]=result

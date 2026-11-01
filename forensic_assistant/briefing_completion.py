"""Bounded presentation synthesis over validated entries, without semantic inference."""
import re


def unknown_label(item):
    if item['kind']!='unknown':return item['kind'].replace('_',' ').capitalize()
    # Only explicit unknown phrases in the retained source, not model description.
    labels=[label for label,pattern in (
        ('Timezone',r'\b(?:time ?zone\s+(?:is\s+)?unknown|unknown\s+time ?zone)\b'),
        ('Account',r'\b(?:account(?: name)?\s+(?:is\s+)?unknown|unknown\s+account(?: name)?)\b'))
        if re.search(pattern,item['statement'],re.I)]
    return labels[0] if len(labels)==1 else 'Unspecified information'


def summary_diagnostic(packet):
    diagnostic=dict(packet.get('summary_diagnostic') or {'state':'not_requested' if packet.get('ai_status')=='not_requested' else 'not_generated','stage':'interpretation'})
    error=packet.get('ai_error')
    if error and diagnostic['stage']=='provider_request':
        diagnostic={'state':'response_unavailable','stage':error['stage'],'rule':error['category']}
    if diagnostic['state']=='accepted' and not packet.get('proposed_summary'):
        diagnostic={'state':'lost_before_assembly','stage':'canonical_assembly'}
    return diagnostic


def synthesize(document, labels):
    """Quote complete entries; preserve status, polarity, source and size bounds."""
    lines=['Analyst-reported entries; not verified. No sequence or causation inferred.']
    statements=[];entries=[]
    count=sum(len(v) for v in document['categories'].values())
    # Put people, host, time and experience ahead of long indicator inventories.
    order=('person','systems','when','incident','user_experience','user_actions',
           'activity','alerts','objectives','origin','response','account','scope',
           'files','websites','indicators','records','context')
    for category in order:
        for index,item in enumerate(document['categories'][category]):
            value=item['value'] or unknown_label(item)+': '+item['status'].replace('_',' ')
            line=labels[category]+' ['+item['status']+'; '+item['polarity']+']: '+value
            sources=statements if item['statement'] in statements else statements+[item['statement']]
            if len('\n'.join(lines+[line]))>1050 or len('\n'.join(sources))>2000:continue
            lines.append(line);statements=sources;entries.append(f'{category}:{index}')
    if not entries:return None
    lines.append(f'Included {len(entries)} of {count} entries. Review all categories and original statements.')
    return {'document':{'text':'\n'.join(lines),'statement':'\n'.join(statements),'status':'proposed'},
            'references':{'entries':entries},'included':len(entries),'total':count}

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
    prose=bool((document['categories']['person'] or document['categories']['systems']) and
               any(document['categories'][key] for key in ('user_experience','user_actions','activity','objectives')))
    introductions={'person':'The briefing names', 'systems':'The briefing identifies a system',
        'when':'Reported time information is', 'user_experience':'The reported user experience is',
        'user_actions':'Reported user activity is', 'activity':'The briefing reports activity',
        'alerts':'The reported security alert or action is', 'objectives':'The investigation objective is'}
    count=sum(len(v) for v in document['categories'].values())
    # Put people, host, time and experience ahead of long indicator inventories.
    order=('person','systems','when','incident','user_experience','user_actions',
           'activity','alerts','objectives','origin','response','account','scope',
           'files','websites','indicators','records','context')
    for category in order:
        for index,item in enumerate(document['categories'][category]):
            value=item['value'] or unknown_label(item)+': '+item['status'].replace('_',' ')
            line=labels[category]+' ['+item['status']+'; '+item['polarity']+']: '+value
            if prose:
                line=introductions.get(category,'The briefing lists '+labels[category].lower())+': "'+value+'" ['+item['status']+'; '+item['polarity']+'].'
            sources=statements if item['statement'] in statements else statements+[item['statement']]
            if len('\n'.join(lines+[line]))>1050 or len('\n'.join(sources))>2000:continue
            lines.append(line);statements=sources;entries.append(f'{category}:{index}')
    if not entries:return None
    if not prose:lines.append('Field inventory only; no coherent narrative synthesized.')
    lines.append(f'Included {len(entries)} of {count} entries. Review all categories and original statements.')
    return {'document':{'text':(' ' if prose else '\n').join(lines),'statement':'\n'.join(statements),'status':'proposed'},
            'references':{'entries':entries},'included':len(entries),'total':count}



def boundary_summary(text, limit):
    """A presentation hint at the known byte bound, not a sentence validator."""
    return len(text.encode('utf-8'))>=limit and not text.rstrip().endswith(('.', '!', '?', '…', '"', "'", '”', '’'))


def time_phrase_note(suggestion, document):
    """Explain an exact supported phrase without converting it to an exact time."""
    candidate=suggestion['candidate'];diagnostic=suggestion['diagnostic']
    if (candidate['type']!='ambiguous_time' or diagnostic.get('rule')!='invalid_technical_value'
        or diagnostic.get('literal_support')!='supported' or diagnostic.get('source_references')!='valid'):
        return None
    from .briefing_semantics import technical
    # Compare complete numeric tokens; don't equate 09:30 with 9:30 or infer AM/PM.
    tokens=re.findall(r'(?<![\w:])\d{1,2}:\d{2}(?::\d{2})?(?![\w:])',candidate['literal'])
    for items in document['categories'].values():
        for item in items:
            if item['kind']=='ambiguous_time' and item['value'] in tokens and item['polarity']==candidate['polarity']:
                try:technical('ambiguous_time',item['value'])
                except ValueError:continue
                return 'Source-supported time phrase; its numeric time is already listed. AM/PM and timezone are not inferred. Original phrase remains excluded from technical search inputs.'
    return 'Source-supported time phrase, not a valid exact time value. Retained for review; no timezone or exact timestamp inferred.'

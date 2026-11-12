"""Versioned concise projection; complete forensic context stays in details."""
from copy import deepcopy
from .transcript import digest
from .explanation import _safe


def unique(values):
    seen=set();result=[]
    for value in values:
        key=digest(value)
        if key not in seen:seen.add(key);result.append(deepcopy(value))
    return result


def view(result,prepared):
    packet=prepared.packet['content'];established=[]
    for entry in packet['interpretations']:
        established.append(dict(kind='registered_interpretation',text=entry['interpretation']['text'],reference=entry['alias'],record=entry['record_ref']))
    for leaf in packet['supports']:
        established.append(dict(kind='recorded_field',text=leaf['field'].get('label',leaf['field']['pointer'])+': '+str(leaf['field']['value']),
            reference=leaf['alias'],record=leaf['record_ref'],identity=[packet['view'],packet['records'][leaf['record_ref']],leaf['field'],leaf.get('timestamp')]))
    deduplicated=[];seen={}
    for entry in established:
        key=digest(entry.get('identity',[entry['kind'],entry['record'],entry['text']]))
        if key in seen:
            seen[key]['references'].append(entry['reference'])
        else:
            entry['references']=[entry['reference']];seen[key]=entry;deduplicated.append(entry)
    established=deduplicated
    validated=result.get('validated',{});proposals=[];seen_proposals=set()
    for proposal in validated.get('proposals',[]):
        item={k:v for k,v in proposal['item'].items() if k!='local_id'}
        key=digest([item,proposal['dependencies'],proposal['mandatory_qualifications']])
        if key not in seen_proposals:seen_proposals.add(key);proposals.append(deepcopy(proposal))
    return dict(contract='d2-quality-view-v1',established=established[:4],established_detail_count=max(0,len(established)-4),
        qualifications=unique(packet['qualifications']),reasoning_outcome=validated.get('reasoning_outcome'),
        abstention_reason=validated.get('abstention_reason',''),proposals=proposals,
        coverage=deepcopy(packet['coverage']),relationships=deepcopy(packet['relationships']),
        provider=prepared.config['provider'],model=prepared.config['model'],
        source=deepcopy(packet['source']),view=deepcopy(packet['view']),s3=prepared.history._original['status'],
        execution={k:deepcopy(v) for k,v in result.items() if k!='validated'},
        details=dict(packet=deepcopy(packet),validated=deepcopy(validated)))


def render(value):
    out=['Ephemeral D2 result — not saved','Established']
    for row in value['established']:
        text=row['text'];shown=text if len(text)<=180 else text[:180]+'… [display shortened; exact value in details]'
        out.append('  '+_safe(shown)+' ['+row['reference']+']')
    if value['established_detail_count']:out.append('  '+str(value['established_detail_count'])+' additional original fields in details.')
    out.extend('  Qualification: '+_safe(q) for q in value['qualifications'])
    out.append('Suggested, not proved')
    execution=value['execution']
    if execution['status']!='accepted':out.append('  No validated AI reasoning: '+_safe(execution.get('reason','unknown')))
    elif not value['proposals']:
        out.append('  '+_safe(value['reasoning_outcome'] or 'No material inference')+': '+_safe(value['abstention_reason']))
    else:
        for p in value['proposals']:out.append('  Unverified account: '+_safe(p['item']['statement']))
    if execution.get('diagnostic'):
        from .d2_diagnostics import line
        if execution['status']!='accepted':out.append('  Validation: '+line(execution['diagnostic']))
        out.append('  Usage availability: '+execution['diagnostic']['usage_availability']+'.')
    out.append('Alternatives and discriminators')
    for p in value['proposals']:
        item=p['item']
        out.extend('  Alternative: '+_safe(x) for x in item['alternatives'])
        if item.get('discriminator'):out.append('  Discriminator (unverified): '+_safe(item['discriminator']))
        out.extend('  Assumption (unverified): '+_safe(x) for x in item['assumptions'])
    if not value['proposals']:out.append('  None proposed.')
    out.append('Contradictions and gaps')
    conflicts=[r for r in value['relationships'] if r.get('predicate')=='incompatible_recorded_field']
    out.append('  Recorded contradiction relationships in this packet: '+str(len(conflicts))+'.')
    out.append('  Omitted/unsearched evidence is not established absent; packet coverage only.')
    out.append('Suggested next examination — not executed or authorized')
    next_steps=unique([p['item']['next_examination'] for p in value['proposals'] if p['item'].get('next_examination')])
    out.extend('  '+_safe(s) for s in next_steps)
    if not next_steps:out.append('  No examination proposed.')
    out+=['Coverage and authority','  Original S3: '+value['s3'],
          '  Source run: '+value['source']['run_id'],'  Frontier: '+str(value['source']['event_head']),
          '  Coverage: '+_safe(str(value['coverage'])),
          '  Provider: '+_safe(value['provider']+' / '+value['model']),
          '  Attempts: '+str(execution.get('attempts'))+'; lookups: '+str(execution.get('lookups'))+'; no retries.',
          '  Provider usage: '+_safe(str(execution.get('usage',{})))+'; missing usage is unknown.',
          '  Cleanup: '+execution.get('cleanup','unknown')+'. Complete provenance is available in --json.']
    return '\n'.join(out)

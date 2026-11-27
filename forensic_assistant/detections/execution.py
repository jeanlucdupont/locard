"""Whole-population execution discovery; derived candidates, never verdicts."""
from collections import Counter,defaultdict
import hashlib
import ntpath
import time
from copy import deepcopy
from .execution_cache import RANKING_VERSION
from forensic_assistant.retrieval.queries import required_time
from forensic_assistant.retrieval.evidence import get_evidence
from forensic_assistant.retrieval.event_data import payload
from .discovery import bounded,field,wire
from .execution_features import features,DEFINITIONS,VERSION
from .execution_observations import Population,FAMILIES,MEANINGS


def category(obs,analysis):
    f=set(analysis['features'])
    if 'encoded_argument' in f:return 'encoded_argument'
    if {'remote_reference','local_path'}<=f:return 'remote_and_local_resources'
    if 'interactive_parent_interpreter' in f:return 'recorded_parent_child'
    if 'nested_interpreter' in f:return 'nested_interpreters'
    if len(f)>=3:return 'multiple_structural_features'
    if obs['kind'] in ('configured_execution','user_entered_command'):return obs['kind']
    if obs['artifact']=='defender':return obs['kind']
    return 'structural_review' if f else 'ordinary_or_missing_context'


def digest(value):return hashlib.sha256(wire(value)).hexdigest()


def key(obs,analysis,mode,scope):
    command=obs['command']
    if command is None:
        content=sorted((name,x['value']) for name,x in obs['original_fields'].items())
    elif mode=='behavioral' and not analysis['analysis_truncated'] and 'quoting_ambiguity' not in analysis['features']:
        content=analysis['argument_pattern']
    else:content=command
    return 'EXEC:'+digest([VERSION,scope,mode,obs['kind'],obs['artifact_host'],obs['context_host'],obs['image'],obs['parent'],content])


def item_frequency(g,commands,images,pairs,patterns):
    return dict(executable=images[g['image_key']],exact_command=commands[g['command_key']] if g['command_key'] is not None else None,
                recorded_parent_child=pairs[g['pair']],literal_argument_pattern=patterns[g['pattern']])


def build_population(db,source,start,end,selected,mode,hostname,check,progress):
    started=time.monotonic()
    population=Population(db,source,start,end,hostname=hostname,check=check)
    scope=dict(source_id=source,start=start,end_exclusive=end,families=selected,hostname=hostname)
    groups={};commands=Counter();images=Counter();pairs=Counter();prevalence=Counter();patterns=Counter();kinds=Counter();categories=Counter();event_types=Counter()
    processed=with_command=truncated=0;last_progress=started
    for family in selected:
        for obs in population.rows(family):
            check();processed+=1
            if family=='evtx':event_types[(obs['context']['provider'],obs['context']['channel'],obs['context']['event_id'])]+=1
            command=obs['command'];with_command+=isinstance(command,str) and bool(command)
            analysis=features(command,obs['image'],obs['parent']);truncated+=analysis['analysis_truncated']
            image=obs['image'] or analysis['executable'];image_key=image or '<unknown>'
            command_key=digest(command) if command is not None else None
            pair=(obs['parent'],image);pattern=digest(analysis['argument_pattern'])
            if command_key is not None:commands[command_key]+=1
            images[image_key]+=1;pairs[pair]+=1;prevalence.update(analysis['features']);patterns[pattern]+=1;kinds[obs['kind']]+=1
            cat=category(obs,analysis);categories[cat]+=1
            gid=key(obs,analysis,mode,scope)
            group=groups.get(gid)
            if group is None:
                group=groups[gid]=dict(count=0,first=obs['first_time'],last=obs['last_time'],obs={k:obs[k] for k in ('evidence_id','artifact','image','parent')},analysis={k:analysis[k] for k in ('features','executable','basename')},category=cat,members=[],with_command=0,
                    image_key=image_key,command_key=command_key,pair=pair,pattern=pattern)
            group['members'].append((family,obs['evidence_id']));group['with_command']+=bool(command)
            group['count']+=1;group['first']=min(group['first'],obs['first_time']);group['last']=max(group['last'],obs['last_time'])
            if obs['evidence_id']<group['obs']['evidence_id']:group['obs']={k:obs[k] for k in ('evidence_id','artifact','image','parent')}
            if time.monotonic()-last_progress>=.5:
                progress(dict(processed=processed,groups=len(groups),phase='analyzing',elapsed_seconds=time.monotonic()-started));last_progress=time.monotonic()
    check()
    # Complete statistics precede selection. Frequency is only a tie-breaker.
    for gid,g in groups.items():
        f=set(g['analysis']['features'])
        g['score']=len(f)+2*int({'remote_reference','local_path'}<=f)+2*int('nested_interpreter' in f and 'chaining' in f)
    return dict(groups=groups,commands=commands,images=images,pairs=pairs,prevalence=prevalence,patterns=patterns,kinds=kinds,categories=categories,event_types=event_types,processed=processed,with_command=with_command,truncated=truncated,coverage=population.coverage)


def discover(db,source,start,end,*,families=FAMILIES,mode='behavioral',limit=5,offset=0,group_id=None,
             feature=None,category_filter=None,executable=None,parent=None,hostname=None,
             hydrate=None,byte_limit=12000,check=lambda:None,progress=lambda value:None,cache=None,authorization=None,presentation='detailed',diagnostics_sink=lambda value:None):
    started=time.monotonic();start,end=required_time(start),required_time(end)
    if start>=end or mode not in ('exact','behavioral') or type(offset) is not int or offset<0 or not 1<=limit<=10:raise ValueError('Invalid discovery bounds')
    if presentation not in ('compact','detailed'):raise ValueError('Unknown presentation')
    if byte_limit<4096:raise ValueError('Discovery response capacity too small')
    if feature is not None and feature not in DEFINITIONS:raise ValueError('Unknown behavioral feature')
    selected=tuple(f for f in FAMILIES if f in families)
    scope=dict(source_id=source,start=start,end_exclusive=end,families=selected,hostname=hostname)
    builder=lambda:build_population(db,source,start,end,selected,mode,hostname,check,progress)
    diagnostics=None
    if cache is not None:
        data,diagnostics=cache.resolve(db,authorization,[scope,mode,VERSION,RANKING_VERSION],builder,check)
        if diagnostics['cache_hit']:progress(dict(processed=data['processed'],groups=len(data['groups']),phase='reused',elapsed_seconds=time.monotonic()-started))
    else:data=builder()
    presentation_started=time.monotonic()
    groups=data['groups']
    commands=data['commands']
    images=data['images']
    pairs=data['pairs']
    prevalence=data['prevalence']
    patterns=data['patterns']
    kinds=data['kinds']
    categories=data['categories']
    event_types=data['event_types']
    processed=data['processed']
    with_command=data['with_command']
    truncated=data['truncated']
    matched={gid:g for gid,g in groups.items() if (feature is None or feature in g['analysis']['features']) and
        (category_filter is None or category_filter==g['category']) and
        (executable is None or executable.casefold() in ((g['obs']['image'] or g['analysis']['executable'] or '').casefold(),g['analysis']['basename'])) and
        (parent is None or parent.casefold() in ((g['obs']['parent'] or '').casefold(),ntpath.basename(g['obs']['parent'] or '').casefold()))}
    def rank(item):
        gid,g=item
        return (-g['score'],commands[g['command_key']] if g['command_key'] is not None else g['count'],pairs[g['pair']],gid)
    buckets=defaultdict(list)
    for item in sorted(matched.items(),key=rank):buckets[item[1]['category']].append(item)
    bucket_order=sorted(buckets,key=lambda name:rank(buckets[name][0]))
    ordered=[];index=0
    while True:
        added=False
        for name in bucket_order:
            if index<len(buckets[name]):ordered.append(buckets[name][index]);added=True
        if not added:break
        index+=1
    hydrate=hydrate or (lambda eid:get_evidence(db,eid))
    def item(obs,a,gid,g):
        check();record=hydrate(obs['evidence_id'])
        if obs['artifact']=='evtx' and 'original_event_data' not in record:record['original_event_data'],_=payload(record)
        originals=[];seen=set()
        names=['command','image','parent','pid','parent_pid','registry_path','value_name',*obs['original_fields']]
        for name in names:
            entry=obs['original_fields'].get(name)
            if not entry or entry['field'] in seen:continue
            value=record
            for part in entry['field'].split('/')[1:]:
                part=part.replace('~1','/').replace('~0','~')
                value=value[int(part)] if isinstance(value,list) else value[part]
            if value!=entry['value']:raise ValueError('Original projection mismatch')
            originals.append(field(entry['field'],value,name));seen.add(entry['field'])
            if len(originals)>=8:break
        decoding=a['decoded']
        if decoding:decoding={**decoding,'text':bounded(decoding['text'],256),'original_field':obs['original_fields'].get('command',{}).get('field'),'limitation':'Derived one-level static decoding; not execution or original evidence'}
        member_filter=dict(source_id=source,start=start,end=end,mode=mode,group_id=gid)
        if len(selected)==1:member_filter['artifact']=selected[0]
        if hostname:member_filter['hostname']=hostname
        return dict(evidence_id=obs['evidence_id'],artifact=obs['artifact'],group_id=gid,source_ids=[source],kind=obs['kind'],meaning=obs['meaning'],
            category=g['category'],count=g['count'],count_meaning='Retained observations, not distinct processes or incidents',
            first_time=g['first'],last_time=g['last'],timestamp_meaning=obs['timestamp_meaning'],artifact_host=bounded(obs['artifact_host']),
            context_host=bounded(obs['context_host']),host_basis=obs['host_basis'],original_fields=originals,original_fields_omitted=len({v['field'] for v in obs['original_fields'].values()})-len(originals),
            features=a['features'],decoding=decoding,analysis_truncated=a['analysis_truncated'],
            priority=dict(score=g['score'],basis='Feature count + 2 remote/local combination + 2 nested/chained combination; category round-robin; frequency then stable digest ties; not a compromise probability'),
            frequency=dict(executable=images[g['image_key']],exact_command=commands[g['command_key']] if g['command_key'] is not None else None,
                           recorded_parent_child=pairs[g['pair']],literal_argument_pattern=patterns[g['pattern']],scope='Current authorized analyzed population only'),
            members=member_filter,limitations=[*obs['limitations'],*a['limitations'],'Recorded parent fields are not corroborated ancestry; PID equality alone establishes no process instance.',
                'Features can describe legitimate administration, comments or quoted text. Original fields may be truncated; inspect before interpreting.'])
    member_count=groups.get(group_id,{}).get('count',0) if group_id else 0
    references=([(family,eid,group_id,groups[group_id]) for family,eid in groups[group_id]['members'][offset:offset+limit]] if group_id in groups else []) if group_id else [(g['obs']['artifact'],g['obs']['evidence_id'],gid,g) for gid,g in ordered[offset:offset+limit]]
    filtering_seconds=time.monotonic()-presentation_started
    hydration_started=time.monotonic()
    candidates=[]
    for family,eid,gid,g in references:
        original=Population(db,source,start,end,hostname=hostname,check=check)
        rows=list(original.rows(family,evidence_ids=[eid]))
        if len(rows)!=1:raise ValueError('Retained member no longer matches authorized population')
        obs=rows[0];analysis=features(obs['command'],obs['image'],obs['parent'])
        if key(obs,analysis,mode,scope)!=gid:raise ValueError('Retained member no longer matches group')
        candidates.append((obs,analysis,gid,g))
    output=[];host_contexts={}
    for o,a,gid,g in candidates:
        value=item(o,a,gid,g)
        if presentation=='compact':
            host={k:value[k] for k in ('artifact_host','context_host','host_basis')}
            host_id=next((k for k,v in host_contexts.items() if v==host),None)
            if host_id is None:host_id='H'+str(len(host_contexts)+1);host_contexts[host_id]=host
            wanted={'command','image','parent','registry_path','value_name'}
            previews=[f for f in value['original_fields'] if f['name'] in wanted][:3]
            value={k:value[k] for k in ('evidence_id','group_id','artifact','kind','category','count','first_time','last_time','features','analysis_truncated') } | dict(
                host_context=host_id,previews=previews,original_fields_omitted=len({v['field'] for v in o['original_fields'].values()})-len(previews),
                score=g['score'],frequency={k:v for k,v in item_frequency(g,commands,images,pairs,patterns).items()},
                limitations=list(dict.fromkeys([*o['limitations'],*a['limitations']])))
        output.append(value)
    hydration_seconds=time.monotonic()-hydration_started
    total=member_count if group_id else len(ordered);more=offset+len(output)<total
    if candidates and not output:raise ValueError('Candidate cannot fit response budget; no original disclosure granted')
    if diagnostics is None or not diagnostics['cache_hit']:
        progress(dict(processed=processed,groups=len(groups),phase='completed',elapsed_seconds=time.monotonic()-started))
    result=dict(contract='execution-discovery-v1',scope=scope,mode=mode,records=output,next_offset=offset+len(output) if more else None,
        truncated=more or offset>0,coverage=dict(analysis_complete=True,presentation_complete=not more and offset==0,counts_complete=True,
            records_processed=processed,records_with_commands=with_command,records_without_commands=processed-with_command,
            feature_analysis_truncated_records=truncated,families=deepcopy(data['coverage']),unsupported_artifact_families=sorted(set(families)-set(selected)),
            eligible_groups=len(groups),matching_groups=len(matched),member_population=member_count if group_id else None),
        statistics=dict(event_populations=[dict(provider=p,channel=c,event_id=i,count=n) for (p,c,i),n in sorted(event_types.items())],distinct_commands=len(commands),distinct_executables=len(images)-int('<unknown>' in images),distinct_recorded_parent_child=len(pairs),
                        distinct_literal_argument_patterns=len(patterns),feature_prevalence=dict(prevalence),observation_kinds=dict(kinds),candidate_categories=dict(categories)),
        feature_definitions={f:DEFINITIONS[f] for f in sorted({f for r in output for f in r['features']})},
        limitations=['Complete means the supported retained source/time population was processed, not complete endpoint telemetry or proof of absence.',
            'Untimed, ambiguous-source and host-conflicting records are excluded; exclusions concern the selected source, not the rest of the case.',
            'Large-field prefix analysis is explicitly limited; exact command identity still uses the entire recorded string.',
            'Grouping is derived; original literal arguments are preserved. No domain/vendor allowlist or incident-specific ranking.',
            'Population counts can include duplicated exports; membership does not imply causal relationships.'])
    if presentation=='compact':
        result['contract']='execution-discovery-compact-v1'
        result['shared']=dict(host_contexts=host_contexts,host_semantics='Artifact host and derived context host are distinct; analyst-supplied context is not independently verified. Inspect original context before host correlation.',previews='Preview-only retained fields with exact EID/pointer; show_evidence before independent verification. Truncated/redacted previews are incomplete.',
            meanings={r['kind']:MEANINGS[r['kind']] for r in output},
            timestamp_semantics='First/last eligible timestamp observations: EVTX SystemTime; Registry containing-key last-write (not value creation/execution); other families retain artifact-slot meanings, inspect original slots.',
            counts='Retained observations, not distinct processes/incidents; frequencies concern the full approved population only.',
            ranking='Feature count + 2 remote/local + 2 nested/chained; category round-robin; frequency/digest ties. Not a compromise probability.',
            navigation='Keep scope/mode/hostname; category_filter or feature selects groups. group_id selects members. presentation=detailed exposes original fields/decoding; show_evidence inspects an EID.',
            caution='Recorded parent fields are not corroborated ancestry; PID equality is insufficient. Features may describe legitimate administration, comments or quoted text.')
        inventory=[]
        for name in sorted(categories):
            values=[g for g in groups.values() if g['category']==name]
            inventory.append(dict(category_filter=name,observations=categories[name],groups=len(values),with_commands=sum(g['with_command'] for g in values),additional_candidates=len({r['group_id'] for r in output if r['category']==name})<len(values)))
        result['categories']=inventory
    serialization_started=time.monotonic()
    while len(wire(result))>byte_limit and output:
        output.pop()
        if presentation=='compact':
            host_contexts={k:v for k,v in host_contexts.items() if any(r['host_context']==k for r in output)}
            result['shared']['host_contexts']=host_contexts
        for category_entry in result.get('categories',[]):
            category_entry['additional_candidates']=len({r['group_id'] for r in output if r['category']==category_entry['category_filter']})<category_entry['groups']
        result['next_offset']=offset+len(output)
        result['truncated']=True
        result['coverage']['presentation_complete']=False
        result['feature_definitions']={f:DEFINITIONS[f] for f in sorted({f for r in output for f in r['features']})}
    if candidates and not output:
        if presentation=='detailed':raise ValueError('Candidate cannot fit response budget; no original disclosure granted')
        first=candidates[0]
        result['omitted_candidates']=[dict(evidence_id=first[0]['evidence_id'],group_id=first[2],reason='Individual candidate plus mandatory qualifications exceeds response capacity; inspect original EID directly')]
        result['next_offset']=offset+1 if offset+1<total else None
        result['coverage']['presentation_complete']=False
    if len(wire(result))>byte_limit:raise ValueError('Discovery envelope exceeds response capacity')
    check()
    if diagnostics is not None:
        cache.validate(db,authorization)
        diagnostics.update(presentation_seconds=serialization_started-presentation_started,serialization_seconds=time.monotonic()-serialization_started,
            population_records=processed,groups=len(groups),candidate_count=len(output),serialized_bytes=len(wire(result)),
            filtering_seconds=filtering_seconds,rehydration_seconds=hydration_seconds,rehydrated_candidates=len(candidates))
        diagnostics_sink(diagnostics)
    return result

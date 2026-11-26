"""Whole-population execution discovery; derived candidates, never verdicts."""
from collections import Counter,defaultdict
import hashlib
import ntpath
import time
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


def discover(db,source,start,end,*,families=FAMILIES,mode='behavioral',limit=5,offset=0,group_id=None,
             feature=None,category_filter=None,executable=None,parent=None,hostname=None,
             hydrate=None,byte_limit=12000,check=lambda:None,progress=lambda value:None):
    started=time.monotonic();start,end=required_time(start),required_time(end)
    if start>=end or mode not in ('exact','behavioral') or type(offset) is not int or offset<0 or not 1<=limit<=10:raise ValueError('Invalid discovery bounds')
    if byte_limit<4096:raise ValueError('Discovery response capacity too small')
    if feature is not None and feature not in DEFINITIONS:raise ValueError('Unknown behavioral feature')
    selected=tuple(f for f in FAMILIES if f in families)
    population=Population(db,source,start,end,hostname=hostname,check=check)
    scope=dict(source_id=source,start=start,end_exclusive=end,families=selected,hostname=hostname)
    groups={};commands=Counter();images=Counter();pairs=Counter();prevalence=Counter();patterns=Counter();kinds=Counter();categories=Counter();event_types=Counter()
    processed=with_command=truncated=0;members=[];member_count=0;last_progress=started
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
            if gid==group_id:
                if offset<=member_count<offset+limit:members.append((obs,analysis,gid))
                member_count+=1
            group=groups.get(gid)
            if group is None:
                group=groups[gid]=dict(count=0,first=obs['first_time'],last=obs['last_time'],obs=obs,analysis=analysis,category=cat,
                    image_key=image_key,command_key=command_key,pair=pair,pattern=pattern)
            group['count']+=1;group['first']=min(group['first'],obs['first_time']);group['last']=max(group['last'],obs['last_time'])
            if obs['evidence_id']<group['obs']['evidence_id']:group['obs']=obs
            if time.monotonic()-last_progress>=.5:
                progress(dict(processed=processed,groups=len(groups),phase='analyzing',elapsed_seconds=time.monotonic()-started));last_progress=time.monotonic()
    check()
    # Complete statistics precede selection. Frequency is only a tie-breaker.
    for gid,g in groups.items():
        f=set(g['analysis']['features'])
        g['score']=len(f)+2*int({'remote_reference','local_path'}<=f)+2*int('nested_interpreter' in f and 'chaining' in f)
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
    candidates=([(o,a,gid,groups[gid]) for o,a,gid in members] if group_id else
                [(g['obs'],g['analysis'],gid,g) for gid,g in ordered[offset:offset+limit]])
    output=[]
    for o,a,gid,g in candidates:
        value=item(o,a,gid,g)
        output.append(value)
    total=member_count if group_id else len(ordered);more=offset+len(output)<total
    if candidates and not output:raise ValueError('Candidate cannot fit response budget; no original disclosure granted')
    progress(dict(processed=processed,groups=len(groups),phase='completed',elapsed_seconds=time.monotonic()-started))
    result=dict(contract='execution-discovery-v1',scope=scope,mode=mode,records=output,next_offset=offset+len(output) if more else None,
        truncated=more or offset>0,coverage=dict(analysis_complete=True,presentation_complete=not more and offset==0,counts_complete=True,
            records_processed=processed,records_with_commands=with_command,records_without_commands=processed-with_command,
            feature_analysis_truncated_records=truncated,families=population.coverage,unsupported_artifact_families=sorted(set(families)-set(selected)),
            eligible_groups=len(groups),matching_groups=len(matched),member_population=member_count if group_id else None),
        statistics=dict(event_populations=[dict(provider=p,channel=c,event_id=i,count=n) for (p,c,i),n in sorted(event_types.items())],distinct_commands=len(commands),distinct_executables=len(images)-int('<unknown>' in images),distinct_recorded_parent_child=len(pairs),
                        distinct_literal_argument_patterns=len(patterns),feature_prevalence=dict(prevalence),observation_kinds=dict(kinds),candidate_categories=dict(categories)),
        feature_definitions={f:DEFINITIONS[f] for f in sorted({f for r in output for f in r['features']})},
        limitations=['Complete means the supported retained source/time population was processed, not complete endpoint telemetry or proof of absence.',
            'Untimed, ambiguous-source and host-conflicting records are excluded; exclusions concern the selected source, not the rest of the case.',
            'Large-field prefix analysis is explicitly limited; exact command identity still uses the entire recorded string.',
            'Grouping is derived; original literal arguments are preserved. No domain/vendor allowlist or incident-specific ranking.',
            'Population counts can include duplicated exports; membership does not imply causal relationships.'])
    while len(wire(result))>byte_limit and output:
        output.pop()
        result['next_offset']=offset+len(output)
        result['truncated']=True
        result['coverage']['presentation_complete']=False
        result['feature_definitions']={f:DEFINITIONS[f] for f in sorted({f for r in output for f in r['features']})}
    if candidates and not output:raise ValueError('Candidate cannot fit response budget; no original disclosure granted')
    if len(wire(result))>byte_limit:raise ValueError('Discovery envelope exceeds response capacity')
    return result

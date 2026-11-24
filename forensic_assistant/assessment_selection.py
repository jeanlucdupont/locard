"""Bounded historical seed planning, not evidence authority or maliciousness ranking."""
from collections import Counter,defaultdict
import re
from .correlation.models import time_ns
from .retrieval.queries import required_time

FAMILIES=('browser','evtx','prefetch','mft','registry')
WORDS={'browser':r'\b(browser|navigation|downloads?|visits?)\b','evtx':r'\b(evtx|events?|process|processes)\b',
       'prefetch':r'\bprefetch\b','mft':r'\b(mft|files?|filesystem)\b','registry':r'\b(registry|persistence)\b'}


def select(assessment,mapping,requested,question,scope,limit=12,*,temporal=False):
    records=assessment['records'];source=assessment['plan'].get('source_id')
    low,high=(time_ns(required_time(scope[k])) for k in ('start','end'))
    mentioned=[f for f in FAMILIES if re.search(WORDS[f],question,re.I)]
    only=mentioned if len(mentioned)==1 and re.search(r'\bonly\b',question,re.I) and not re.search(r'\bnot\s+only\b',question,re.I) else None
    groups=defaultdict(list);excluded=Counter();buckets={};times_by_id={}
    available=Counter(eid.split(':')[0].lower() for eid in records)
    for ref,eid in mapping.items():
        record=records[eid];family=eid.split(':')[0].lower()
        if family not in FAMILIES:excluded['unsupported_family']+=1;continue
        sources=record.get('source_context',{}).get('source_ids',[])
        if not sources or (source and not set(sources)<={source}):excluded['source_not_eligible']+=1;continue
        times=record.get('match',{}).get('timestamps',[])[:32]
        eligible=False;record_times=[]
        for stamp in times:
            try:
                if stamp.get('timestamp_utc') and low<=time_ns(required_time(stamp['timestamp_utc']))<high:
                    eligible=True;record_times.append(time_ns(required_time(stamp['timestamp_utc'])))
            except (ValueError,TypeError):continue
        if not eligible:excluded['no_retained_in_window_timestamp']+=1;continue
        if only and family not in only:excluded['question_family_only']+=1;continue
        subtype=record.get('presentation',{}).get('artifact_type','')
        bucket=family+('/'+subtype if family=='browser' and subtype in ('browser_download','browser_visit') else '')
        buckets[eid]=bucket;groups[bucket].append(ref);times_by_id[eid]=min(record_times)
    if any(mapping[ref] not in buckets for ref in requested):
        raise ValueError('Requested assessment reference is outside the eligible source/time/family selection; no scope expansion')
    order=sorted(groups,key=lambda b:(0 if b.split('/')[0] in mentioned else 1,FAMILIES.index(b.split('/')[0]),b))
    chosen=list(requested)
    while len(chosen)<limit:
        progress=False
        for bucket in order:
            remaining=[ref for ref in groups[bucket] if ref not in chosen]
            if remaining and len(chosen)<limit:
                if temporal:
                    prior=[times_by_id[mapping[r]] for r in chosen]
                    remaining.sort(key=lambda r:(-min(abs(times_by_id[mapping[r]]-t) for t in prior) if prior else abs(times_by_id[mapping[r]]-(low+high)//2),mapping[r]))
                chosen.append(remaining[0]);progress=True
        if not progress:break
    selected=[mapping[r] for r in chosen]
    return chosen,dict(contract='assessment-seed-selection-v1',available_records=len(records),available_by_family=dict(sorted(available.items())),
        eligible_records=len(buckets),eligible_families=sorted({b.split('/')[0] for b in buckets.values()}),
        selected_by_family=dict(sorted(Counter(e.split(':')[0].lower() for e in selected).items())),
        selected_ids=selected,requested_ids=[mapping[r] for r in requested],buckets={e:buckets[e] for e in selected},
        bucket_order=order,omitted_eligible_records=len(buckets)-len(selected),excluded=dict(excluded),
        source_ids=[source] if source else sorted({s for e in selected for s in records[e]['source_context']['source_ids']}),
        objectives_matched=mentioned,question_family_only=only or [],
        **({'temporal_order':selected,'selected_times_ns':{e:times_by_id[e] for e in selected},
            'temporal_coverage':'Farthest-time sampling within retained assessment observations only; no guarantee of full-window coverage.'} if temporal else {}),
        limitation=('Temporal coverage sample of retained assessment records, not relevance ranking. Follow-up searches require the separate displayed grant.' if temporal else 'Coverage sample, not relevance or maliciousness ranking. At most six selected IDs can be inspected; no search or refill is authorized.'))

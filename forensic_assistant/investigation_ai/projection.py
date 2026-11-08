"""Lossless field selection: unchanged leaves and stable array indices, never synthesized facts."""
from copy import deepcopy
import json


def size(value):
    return len(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode())


def merge(previous, disclosed):
    if isinstance(previous, dict) and isinstance(disclosed, dict):
        return {**deepcopy(previous), **{k:merge(previous.get(k),v) for k,v in disclosed.items()}}
    if isinstance(previous, list) and isinstance(disclosed, list):
        result=deepcopy(previous)
        for i,v in enumerate(disclosed):
            if i<len(result):
                # A page can reuse an array index for a different original ordinal.
                changed=isinstance(v,dict) and isinstance(result[i],dict) and any(k in v and k in result[i] and v[k]!=result[i][k] for k in ('ordinal','slot'))
                result[i]=deepcopy(v) if changed else merge(result[i],v)
            else:result.append(deepcopy(v))
        return result
    return deepcopy(disclosed)


def compact(record, budget):
    if size(record)<=budget:return deepcopy(record)
    # Source attribution and upstream truncation metadata remain inseparable.
    base={k:deepcopy(record[k]) for k in ('id','source_type','artifact_type','kind','source_file',
        'source_context','truncated_fields','coverage_notes','event_data_limitations','supporting_evidence_ids') if k in record}
    if size(base)>budget:return None
    family=record.get('source_type','evtx')
    priorities={
        'evtx':('event_id','timestamp_utc','provider','channel','original_event_data','process_name','command_line','parent_process_name','parent_command_line'),
        'browser':('browser_product','url','target_path','current_path','timestamps','timestamp_utc','state'),
        'mft':('timestamps','objects','paths','filename','record_number','allocated'),
        'prefetch':('executable','process_name','timestamps','referenced_files','run_count'),
        'registry':('hive','key','key_path','value_name','value_data','timestamps'),
    }.get(family,())
    # Keep the qualified blocking interpretation before less informative leaves.
    if 'defender_asr' in record and 'interpretation_ids' in record:
        from .conclusions import interpretations
        candidate = {**base, **{k: deepcopy(record[k]) for k in
            ('event_id', 'provider', 'channel', 'defender_asr', 'interpretation_ids') if k in record}}
        if size(candidate) <= budget and interpretations(candidate):
            base = candidate
    for key in dict.fromkeys((*priorities,*record)):
        if key in base or key in ('defender_asr','interpretation_ids'):continue
        if key not in record:continue
        value=record[key];base[key]=deepcopy(value)
        if size(base)<=budget:continue
        base.pop(key)
        if key=='original_event_data' and isinstance(value,list):
            # Preserve original JSON-pointer indices. Empty dicts disclose no leaf
            # values; selected entries retain original names, ordinals and flags.
            def priority(i):
                name=str(value[i].get('name','')).casefold()
                return (0 if 'target' in name and 'command' in name else 1 if 'command' in name else 2 if 'process' in name else 3, i)
            chosen=[]
            for i in sorted(range(len(value)),key=priority):
                candidate=deepcopy(chosen)
                candidate.extend({} for _ in range(i+1-len(candidate)))
                candidate[i]=deepcopy(value[i]);base[key]=candidate
                if size(base)<=budget:chosen=candidate
            base.pop(key,None)
            if chosen:base[key]=chosen
            continue
        if isinstance(value,list):
            prefix=[]
            for item in value:
                base[key]=prefix+[deepcopy(item)]
                if size(base)>budget:base.pop(key);break
                prefix=base[key]
            if prefix:base[key]=prefix
    # Derivation IDs and their exact input-derived object travel together.
    if 'defender_asr' in record and 'interpretation_ids' in record:
        candidate={**base,'defender_asr':deepcopy(record['defender_asr']),'interpretation_ids':deepcopy(record['interpretation_ids'])}
        from .conclusions import interpretations
        if size(candidate)<=budget and interpretations(candidate):base=candidate
    return base


def same(value, original):
    return type(value) is type(original) and json.dumps(value,sort_keys=True,ensure_ascii=True)==json.dumps(original,sort_keys=True,ensure_ascii=True)


def is_record_projection(value, original):
    metadata=('id','source_type','artifact_type','kind','source_file','source_context','truncated_fields',
              'coverage_notes','event_data_limitations','supporting_evidence_ids')
    if not isinstance(value,dict) or not isinstance(original,dict):return False
    if not all(k not in original or (k in value and same(value[k],original[k])) for k in metadata):return False
    for key,item in value.items():
        if key not in original:return False
        source=original[key]
        if same(item,source):continue
        if not isinstance(item,list) or not isinstance(source,list) or len(item)>len(source):return False
        if any(not same(v,source[i]) and not (v=={} and isinstance(source[i],dict)) for i,v in enumerate(item)):return False
    return True

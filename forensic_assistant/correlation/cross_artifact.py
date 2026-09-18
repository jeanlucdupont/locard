"""Object/time agreement is not execution identity, causation, or compromise."""
import hashlib
import json
from forensic_assistant.retrieval.evidence import get_evidence
from forensic_assistant.correlation.models import time_ns

ROLES={'process_image','file_path','filename','executable_name','executable_path_candidate','persistence_target'}


def paths(record):
    results=[]
    for o in record['objects']:
        if o['role'] not in ROLES or not o['normalized']:continue
        value=o['normalized'];kind=o['path_kind'];root=record['context']['volume_root']
        if kind=='volume_relative' and root:value=root.lower()+value;kind='absolute'
        if kind=='device' and root and record['source_type']=='prefetch':
            volumes=record.get('detail',{}).get('volumes',[])
            if len(volumes)==1 and volumes[0]['device_path']:
                prefix=volumes[0]['device_path'].lower().rstrip('\\')
                if value.startswith(prefix+'\\'):value=root.lower()+value[len(prefix):];kind='absolute'
        results.append(dict(path=value,kind=kind,basename=o['basename'],role=o['role']))
    return results


def relevant_times(record):
    times=record['timestamps']
    if record['source_type']=='mft':times=[t for t in times if t['source']=='MFT SI Created']
    return [t for t in times if t['timestamp_utc']]


def relation(anchor,candidate,status,reason,matched=None,comparison=None):
    ids=sorted({anchor['id'],candidate['id'],*anchor.get('supporting_evidence_ids',[]),*candidate.get('supporting_evidence_ids',[])})
    result=dict(relationship='cross_artifact_observation',status=status,evidence_ids=ids,source_id=anchor['id'],target_id=candidate['id'],
                reason=reason,matched_fields=matched or {},timestamp_comparison=comparison,
                limitations=['Path/name agreement does not prove identical content or process identity','Temporal proximity does not establish causation',
                             'Source host/volume assertions remain analyst-supplied where indicated'])
    result['relationship_id']='REL:'+hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest()[:16]
    return result


def correlate(db,anchor_id,limit=100):
    if not 1<=limit<=1000:raise ValueError('Cross-artifact candidate limit must be 1..1000')
    anchor=get_evidence(db,anchor_id);apaths=paths(anchor)
    basenames=sorted({p['basename'] for p in apaths if p['basename']})
    if not basenames:return {'relationships':[],'candidate_count':0,'truncated':False,'limitations':['Anchor has no explicit comparison object']}
    # Indexed basename lookup handles volume-relative paths without all-table Python scans.
    where='o.basename IN ('+','.join('?' for _ in basenames)+') AND e.source_type<>? AND o.role IN ('+','.join('?' for _ in ROLES)+')'
    params=[*basenames,anchor['source_type'],*sorted(ROLES)]
    sql=' FROM evidence_objects o JOIN evidence_records e USING(evidence_id) WHERE '+where
    total=db.execute('SELECT count(DISTINCT e.evidence_id)'+sql,params).fetchone()[0]
    rows=db.execute('SELECT DISTINCT e.evidence_id'+sql+' ORDER BY e.evidence_id LIMIT ?',[*params,limit]).fetchall()
    relations=[]
    for row in rows:
        candidate=get_evidence(db,row[0]);cp=paths(candidate)
        host=anchor['host_key'];other=candidate['host_key']
        if (host and other and host!=other) or anchor['context']['conflicts'] or candidate['context']['conflicts']:
            relations.append(relation(anchor,candidate,'UNRESOLVED','Known host or source-context conflict'));continue
        aa={p['path'] for p in apaths if p['kind']=='absolute'};ca={p['path'] for p in cp if p['kind']=='absolute'}
        overlap=aa&ca
        if aa and ca and not overlap:
            relations.append(relation(anchor,candidate,'UNRESOLVED','Same basename but different explicit paths'));continue
        at=relevant_times(anchor);ct=relevant_times(candidate)
        best=min(((abs(time_ns(a['timestamp_utc'])-time_ns(c['timestamp_utc'])),a,c) for a in at for c in ct),default=None,key=lambda x:x[0])
        seconds=2 if 'prefetch' in (anchor['source_type'],candidate['source_type']) and 'evtx' in (anchor['source_type'],candidate['source_type']) else 300 if 'registry' in (anchor['source_type'],candidate['source_type']) else 120
        comparison=None
        if best:
            delta,a,c=best;comparison={'anchor':a,'candidate':c,'distance_ns':delta,'window_seconds':seconds}
        compatible=bool(best and best[0]<=seconds*1_000_000_000)
        matched={'basenames':basenames,'exact_paths':sorted(overlap),'same_host':bool(host and host==other)}
        status='CORROBORATED' if overlap and host and host==other and compatible else 'POSSIBLE'
        reason='Independent artifact observations agree on explicit path, host scope, and compatible timestamp fields' if status=='CORROBORATED' else 'Partial object agreement; path identity, host scope, or compatible timing is missing'
        if total>limit:
            status='UNRESOLVED';reason='Candidate cap prevents complete ambiguity assessment'
        if anchor['objects_truncated'] or candidate['objects_truncated']:
            status='UNRESOLVED';reason='Object fields truncated; comparison cannot establish completeness'
        if (anchor['source_type']=='prefetch' and len(aa)>1) or (candidate['source_type']=='prefetch' and len(ca)>1):
            status='UNRESOLVED';reason='Prefetch contains competing executable-path candidates'
        relations.append(relation(anchor,candidate,status,reason,matched,comparison))
    groups={}
    for r in relations:
        if r['status']=='CORROBORATED':groups.setdefault((r['target_id'].split(':')[0],tuple(r['matched_fields']['exact_paths'])),[]).append(r)
    for group in groups.values():
        if len(group)>1:
            for r in group:r.update(status='UNRESOLVED',reason='Multiple compatible object observations; no unique association selected')
    for r in relations:
        r.pop('relationship_id',None)
        r['relationship_id']='REL:'+hashlib.sha256(json.dumps(r,sort_keys=True).encode()).hexdigest()[:16]
    return {'relationships':relations,'candidate_count':total,'truncated':total>limit,'limitations':[]}

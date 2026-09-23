"""Bounded report-time grounding, separate from historical model exposure."""
from dataclasses import asdict
from pathlib import Path
import time
from forensic_assistant.investigation_ai.runner import ForensicWorker
from forensic_assistant.investigation_ai.state import fields
from .model import Limits, claim, graph, DIRECT_SCOPE, CAUTION, FORMAT, canonical
from .transcripts import load

class ReportWorker(ForensicWorker):
    worker_script=Path(__file__).with_name('worker.py')

def matches(record, grounded):
    # Retrieval basis is provenance, never an observed evidence field.
    supplied={k:v for k,v in record.items() if k!='retrieval_basis'}
    return any(supplied==variant for variant in grounded['historical_variants'])

def build(case, *, evidence_ids=(), investigation_ids=(), transcript_root=None,
          limits=None, include_source_locations=False, metadata=None):
    limits=limits or Limits(); metadata=metadata or {}
    if set(metadata)-{'case_name','case_identifier','analyst_name','organization','title','scope_note'}:
        raise ValueError('Unknown analyst metadata')
    if any(type(v) is not str or len(v.encode())>1000 for v in metadata.values()): raise ValueError('Metadata bound exceeded')
    if bool(evidence_ids)==bool(investigation_ids): raise ValueError('Select evidence IDs OR investigations')
    if len(investigation_ids)>8 or len(set(investigation_ids))!=len(investigation_ids): raise ValueError('Investigation input bound or duplicate')
    if len(evidence_ids)>1000 or any(type(v) is not str or len(v)>256 for v in evidence_ids): raise ValueError('Evidence input bound')
    deadline=time.monotonic()+limits.seconds
    adapters=[load(transcript_root,i) for i in sorted(investigation_ids)]
    expected={a['manifest']['evidence_fingerprint'] for a in adapters}
    if len(expected)>1: raise ValueError('Investigations have different evidence states')
    expected=next(iter(expected),None)
    mode='investigations' if adapters else 'explicit_evidence_ids'
    selected=set(evidence_ids)
    for a in adapters:
        for result in a['results']: selected.update(r['id'] for r in result['records'])
    if not selected or len(selected)>2000: raise ValueError('Empty or excessive evidence selection')
    records={};inventory={};provenance=[];all_claims={};limitations=[]
    def add(category, assertion, ids=(), origins=()):
        item=claim(category,assertion,ids,origins)
        previous=all_claims.get(item['claim_id'])
        if previous: item['origins']=sorted(set(item['origins']+previous['origins']))
        all_claims[item['claim_id']]=item
    with ReportWorker({'case_path':str(case)}) as worker:
        def call(op,args=None):
            nonlocal expected
            remaining=deadline-time.monotonic()
            if remaining<=0: raise ValueError('Report runtime exhausted')
            response=worker.call(op,args,fingerprint=expected,seconds=min(45,remaining))
            if response['schema']!=3 or response['database_changes']!=0: raise ValueError('Read-only report gate failed')
            expected=response['fingerprint'];return response['result']
        pending=sorted(selected)
        while pending:
            batch=pending[:20];pending=pending[20:]
            result=call('collect',dict(ids=batch,locations=include_source_locations))
            inventory.update(result['inventory'])
            for record in result['records']: records[record['id']]=record
            support={eid for r in records.values() for eid in r['supporting_evidence_ids']}-records.keys()-set(pending)
            pending.extend(sorted(support))
            if len(records)+len(pending)>2000: raise ValueError('Supporting evidence bound exceeded')
        if adapters:
            for adapter in adapters:
                manifest=adapter['manifest'];iid=manifest['investigation_id']
                for result in adapter['results']:
                    for record in result['records']:
                        if not matches(record,records[record['id']]): raise ValueError('Historical evidence projection failed grounding')
                wanted={}
                for exposure in adapter['exposures']:
                    for section,key in [('relationships','relationship_id'),('detections','detection_id')]:
                        for obj in exposure[section]: wanted[obj[key]]=obj
                found={}
                if wanted:
                    ops=[{**op,'date_hint':manifest.get('date_hint'),'known_ids':sorted(records)} for op in adapter['operations'] if op['operation']!='semantic_search' and op['completion']=='COMPLETED']
                    # Pure conceptual questions have no deterministic planner
                    # equivalent. Ground their recorded candidates' engine
                    # expansions without rerunning semantic retrieval.
                    initial=adapter['results'][0]
                    if initial.get('semantic_used') and initial.get('plan',{}).get('operation')=='conceptual':
                        ops=[op for op in ops if op['operation']!='initial_retrieval']
                    semantic_ids={hit['evidence_id'] for result in adapter['results'] for hit in result.get('semantic_candidates',[])[:5]}
                    ops += [dict(operation='semantic_expansion',evidence_id=eid) for eid in sorted(semantic_ids)]
                    for op in ops:
                        result=call('objects',op)
                        for section,key in [('relationships','relationship_id'),('detections','detection_id')]:
                            for obj in result[section]: found[obj[key]]=obj
                    if any(found.get(key)!=value for key,value in wanted.items()): raise ValueError('Historical engine object failed grounding')
                findings=adapter['findings']
                for fact in findings['observed']:
                    add('OBSERVED FACT',dict(field=fact['field'],value=fact['reported_value'],
                        subject=fact['evidence_ids'][0],qualifier=fact['qualifier'],truncated_fields=fact['truncated_fields']),fact['evidence_ids'],[iid])
                for section,category in [('deterministically_correlated','DETERMINISTIC RELATIONSHIP'),('corroborated','CORROBORATED RELATIONSHIP'),('detections','DETECTION'),('unresolved_relationships','UNKNOWN')]:
                    for obj in findings[section]: add(category,dict(engine_object=obj),obj['evidence_ids'],[iid])
                for hypothesis in findings['hypotheses']:
                    add('MODEL/ANALYST HYPOTHESIS',dict(proposal=hypothesis,verification='UNVERIFIED',
                        contradictions={'status':'NOT_EVALUATED','evidence_ids':[]},
                        gaps=['No independent verification of hypothesis prose']),hypothesis['evidence_ids'],[iid])
                for unknown in findings['model_proposed_unknowns']:
                    add('UNKNOWN',dict(model_proposal=unknown,verification='UNVERIFIED'),(),[iid])
                provenance.append(dict(investigation_id=iid,question=manifest['question'],
                    termination=manifest['status'],application_version=manifest['application_version'],
                    code_sha256=manifest['code_sha256'],policy_version=manifest['policy_version'],
                    input_hashes=adapter['input_hashes'],operations=adapter['operations'],
                    budgets=manifest['budgets'],semantic_identity=manifest.get('semantic_identity'),
                    embedding_identity=manifest.get('embedding_identity'),model_metadata=adapter['terminal'].get('model_metadata',[]),
                    exposure_requests=len(adapter['exposures']),exposure_meaning='Request attempted; receipt not attested',
                    methodology_basis='Recorded transcript, not authenticated operation history'))
                if manifest['status']!='ANSWER_SUPPORTED': limitations.append('Input investigation ended with '+manifest['status'])
                limitations.extend(str(x)[:300] for x in adapter['terminal'].get('limitations',[])[:34])
        else:
            for eid in sorted(selected):
                record=records[eid]
                for pointer,value in fields(record['fields']):
                    if pointer in ('/kind','/source_type','/artifact_type'): continue
                    add('OBSERVED FACT',dict(field=pointer,value=value,subject=eid,
                        qualifier='Reported field in explicitly supplied evidence; no causal or attribution inference',
                        truncated_fields=record['fields'].get('truncated_fields',[])),
                        [eid]+record['supporting_evidence_ids'],['report-time explicit selection'])
        for eid,record in sorted(records.items()):
            if record['context']['conflicts']:
                add('CONFLICT',dict(kind='context_assertion_conflict',fields=record['context']['conflicts'],
                    assertions=record['context']['assertions'],resolution='Unresolved; no conflicting assertion selected'),[eid],['report-time context validation'])
            if record['fields'].get('truncated_fields') or record['warnings']:
                limitations.append('Record '+eid+' has parser warnings or compact-field omissions')
        call('check')
    # Never let the ordinary claim cap silently discard a conflict or limitation.
    claims=sorted(all_claims.values(),key=lambda c:(c['category'],c['claim_id']))
    mandatory=[c for c in claims if c['category'] in ('CONFLICT','UNKNOWN','LIMITATION')]
    optional=[c for c in claims if c not in mandatory]
    reserved=int(bool(limitations) or len(claims)>limits.claims)
    capacity=limits.claims-reserved
    if len(mandatory)>capacity: raise ValueError('Material caveats exceed claim limit; raise limit')
    omitted=max(0,len(claims)-capacity)
    claims=mandatory+optional[:capacity-len(mandatory)]
    if omitted: limitations.append(f'{omitted} claims omitted by requested report bound')
    observations={}
    for eid,record in sorted(records.items()):
        for stamp in record['timestamps']:
            key=(stamp['evidence_id'],stamp['slot'])
            if key not in observations:
                observations[key]={k:v for k,v in stamp.items() if k!='inherited_from_key'}
                observations[key]['referenced_by']=[]
            observations[key]['referenced_by'].append(eid)
    timeline=list(observations.values())
    timeline.sort(key=lambda t:(t['timestamp_utc'] is None,t['timestamp_utc'] or '',t['evidence_id'],t['slot']))
    omitted_timeline=max(0,len(timeline)-limits.timeline);timeline=timeline[:limits.timeline]
    if omitted_timeline: limitations.append(f'{omitted_timeline} timestamp observations omitted from timeline section by requested bound')
    if limitations and not reserved and len(claims)==limits.claims:
        candidates=[c for c in claims if c['category'] not in ('CONFLICT','UNKNOWN','LIMITATION')]
        if not candidates: raise ValueError('Material caveats exceed claim limit')
        claims.remove(candidates[-1]);omitted+=1
        limitations.append('One additional claim omitted to retain the limitations claim')
    limitations=sorted(set(limitations))
    # Structured limitation claims join the same graph; the reserved summary is
    # one claim regardless of the number of explicitly listed caveats.
    if limitations:
        claims.append(claim('LIMITATION',dict(items=limitations),origins=['report generation']))
    for record in records.values(): record.pop('historical_variants')
    scope=DIRECT_SCOPE if mode=='explicit_evidence_ids' else 'Bounded report of selected same-state investigations; not a complete forensic examination.'
    result=dict(format=FORMAT,schema=3,input_mode=mode,scope=scope,evidence_fingerprint=expected,
        analyst_metadata=metadata,analyst_metadata_basis='Analyst supplied; not evidence',
        selection={'evidence_ids':sorted(set(evidence_ids)),'investigation_ids':sorted(investigation_ids)},
        limits=asdict(limits),source_locations_included=include_source_locations,
        status='COMPLETE_WITH_LIMITATIONS' if limitations else 'COMPLETE',
        claims=claims,evidence=records,graph=graph(claims,records),timeline=timeline,
        inventory=inventory,investigations=provenance,limitations=limitations,
        omissions=dict(claims=omitted,timeline=omitted_timeline),
        methodology=dict(input_mode=mode,scope=scope,report_operations=['Read-only evidence hydration','Content fingerprint validation','Claim grounding and required-support validation','Timestamp and inventory projection'],
                         historical_operations_basis='Recorded, not independently authenticated',
                         semantic_retrieval_rerun=False,collection_used_model=False),caution=CAUTION)
    if len(canonical(result))>16*1024*1024: raise ValueError('Structured report size bound exceeded')
    return result

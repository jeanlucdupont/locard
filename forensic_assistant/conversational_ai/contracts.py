"""Closed tools and local immutable authorization; no provider or UI dependency."""
from copy import deepcopy
from pathlib import Path
import time
from forensic_assistant.investigation_ai import contracts as c
from forensic_assistant.retrieval.queries import required_time

FAMILIES=('browser','evtx','mft','prefetch','registry')
DEFAULTS=dict(active_seconds=900,provider_seconds=60,tool_seconds=15,requests=30,operations=60,
              request_bytes=65536,result_bytes=32768,disclosure_bytes=2097152,tokens=200000,output_tokens=2048,records=300)
STR=c.string
FILTERS={k:STR(512) for k in ('hostname','username','process','path','registry_key','registry_key_contains',
    'value_name','value_name_contains','ip','url','url_contains','download_path','object_basename')}
FILTERS.update(artifact=c.enumeration(*FAMILIES),event_id=c.integer(0,65535),browser_kind=c.enumeration('visit','download'),
    evtx_text=STR(256),evtx_match=c.enumeration('exact','contains'),evtx_after=STR(1024),object_after=STR(2048),
    source_id=STR(160),start=STR(80),end=STR(80),limit=c.integer(1,20),offset=c.integer(0,10000))
SCHEMAS={
 'search_evidence':c.obj(FILTERS,('artifact',)),
 'timeline':c.obj({k:v for k,v in FILTERS.items() if k not in ('object_basename','object_after','evtx_text','evtx_match','evtx_after')},('artifact',)),
 'show_evidence':c.obj(dict(evidence_id=STR(160),offset=c.integer(0,10000),limit=c.integer(1,40)),('evidence_id',)),
 'around':c.obj(dict(evidence_id=STR(160),timestamp_slot=STR(160),seconds=c.integer(1,3600),artifact=c.enumeration(*FAMILIES),limit=c.integer(1,20),offset=c.integer(0,10000)),('evidence_id','timestamp_slot','artifact')),
 'verify_observation':c.obj(dict(evidence_id=STR(160),field=STR(512),value_json=STR(4096),timestamp_meaning=STR(512)),('evidence_id','field','value_json')),
 'note':c.obj(dict(kind=c.enumeration('hypothesis','interpretation','open_question','next_lead'),text=STR(2000),status=c.enumeration('active','revised','rejected','unresolved')),('kind','text','status')),
}
DESCRIPTIONS={
 'search_evidence':'Search approved original evidence. Choose artifact; optional time narrows approval. process/path retain existing normalized semantics. object_basename is exact basename candidate discovery (not identity); only artifact, time, source, limit <=10 and object_after may accompany it. EVTX text is explicit literal original EventData search; use evtx_after, not offset. Both require <=24h windows. URL substring is case-sensitive. Results are bounded, not absence proof.',
 'timeline':'Chronological original timestamp observations; distinguish filesystem, browser and execution timestamp meanings. Paginate with offset.',
 'show_evidence':'Inspect a previously returned original evidence ID through pages of scalar JSON pointers. Preserve source/timestamp context; truncated values cannot be verified. Advance offset to next_offset.',
 'around':'Same-host timestamp observations around a previously returned record and explicit original timestamp_slot. Clamped to approved scope; temporal proximity is not causality.',
 'verify_observation':'Independently rehydrate an exact previously disclosed scalar field. value_json is its JSON encoding. For timestamp fields supply the exact disclosed timestamp_meaning. This verifies field equality, never arbitrary prose, causality or successful execution.',
 'note':'Keep a small unverified hypothesis, interpretation, question or next lead. Revisions do not erase earlier notes. Never use this as evidence or an authorization change.'}

def catalog():
    return [dict(type='function',function=dict(name=k,description=DESCRIPTIONS[k],parameters=deepcopy(v))) for k,v in SCHEMAS.items()]

def arguments(name,args):
    if name not in SCHEMAS:raise ValueError('TOOL_NOT_AUTHORIZED')
    c.validate(args,SCHEMAS[name])

def authorize(case,sources,start,end,families,provider,model,limits=None):
    from forensic_assistant.investigation_ai.storage import local_path
    path=local_path(case).resolve(strict=True);info=path.stat()
    if not path.is_file() or not isinstance(sources,(list,tuple)) or not sources or len(sources)>8 or any(type(s) is not str or not 1<=len(s.encode())<=160 for s in sources) or len(set(sources))!=len(sources):raise ValueError('INVALID_SCOPE')
    if provider!='openai':raise ValueError('Conversational provider unsupported; no cloud fallback')
    if not families or any(type(f) is not str for f in families) or not set(families)<=set(FAMILIES):raise ValueError('INVALID_FAMILIES')
    if type(model) is not str or not 1<=len(model.encode())<=256:raise ValueError('INVALID_MODEL')
    start,end=required_time(start),required_time(end)
    if start>=end:raise ValueError('INVALID_TIME_SCOPE')
    resources={**DEFAULTS,**(limits or {})}
    if set(resources)!=set(DEFAULTS) or any(type(resources[k]) is not int or not 1<=resources[k]<=v for k,v in DEFAULTS.items()):raise ValueError('INVALID_LIMITS')
    return dict(contract='conversational-authorization-v1',case=str(path),identity=[info.st_dev,info.st_ino],
        source_ids=list(sources),families=list(families),start=start,end=end,provider=provider,model=model,
        issued=time.time(),expires=time.time()+86400,limits=resources,
        temporal_policy='Record eligibility in [start,end); bounded full-record context including labeled out-of-window timestamps is authorized.',
        disclosure='Analyst context and bounded original evidence may be sent to the configured OpenAI model.')

def check(scope,case):
    path=Path(case).resolve(strict=True);info=path.stat()
    if scope.get('contract')!='conversational-authorization-v1' or str(path)!=scope['case'] or [info.st_dev,info.st_ino]!=scope['identity']:raise ValueError('CASE_IDENTITY_CHANGED')
    if time.time()>=scope['expires']:raise ValueError('AUTHORIZATION_EXPIRED')

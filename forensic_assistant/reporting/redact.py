"""Conservative output views. No regex-based promise of anonymization."""
from copy import deepcopy
import re
from .model import CATEGORIES, CAUTION, DIRECT_SCOPE, claim, graph

NOTICE = ('Identifiers redaction applied. Free text and payloads are suppressed. Evidence IDs, source '
          'hashes, timestamps and numeric metadata remain linkable. This is not anonymization. '
          'Original evidence and transcripts were not modified.')
SAFE = set(CATEGORIES) | {CAUTION,DIRECT_SCOPE,
    'search_evidence','semantic_search','show_evidence','timeline','around','process_tree','session','detections',
    'investigate_evidence','initial_retrieval',
    'evtx','mft','prefetch','registry','process','logon','registry_key','registry_value',
    'COMPLETE','COMPLETE_WITH_LIMITATIONS','explicit_evidence_ids','investigations',
    'COMPLETED','ATTEMPTED_NO_RESULT','ANSWER_SUPPORTED','INSUFFICIENT_EVIDENCE','BUDGET_EXHAUSTED',
    'MODEL_FAILURE','USER_SCOPE_REACHED','TOOL_LOOP','NO_NEW_EVIDENCE','TOO_MANY_REJECTIONS',
    'EVIDENCE_STATE_CHANGED','SEMANTIC_STATE_CHANGED','TOOL_FAILURE',
    'CONFIRMED','LIKELY','CORROBORATED','POSSIBLE','UNRESOLVED','DETERMINISTICALLY_CORRELATED',
    'UNVERIFIED','NOT_EVALUATED','hostname','username','volume_root','source_type','artifact_type',
    'artifact field','analyst-supplied','unknown','normalized','valid','invalid',
    'EVTX SystemTime','FILETIME','Unix','v4-1','report-time explicit selection',
    'report-time context validation','report generation',
    'Read-only evidence hydration','Content fingerprint validation',
    'Claim grounding and required-support validation','Timestamp and inventory projection',
    'Bounded report of selected same-state investigations; not a complete forensic examination.',
    'Analyst supplied; not evidence','Recorded, not independently authenticated',
    'Recorded transcript, not authenticated operation history',
    'Request attempted; receipt not attested','context_assertion_conflict',
    'Unresolved; no conflicting assertion selected',
    'Reported field; not proof of execution, attribution, intent or causation',
    'Reported field in explicitly supplied evidence; no causal or attribution inference'}
REF_KEYS={'id','evidence_id','subject','evidence_ids','supporting_evidence_ids','key_evidence_id',
          'source_id','target_id','referenced_by','selection'}
HASH_KEYS={'file_sha256','sha256','evidence_fingerprint','code_sha256','manifest','events','manifest_sha256'}
VERSION_KEYS={'parser_version','extractor_version','application_version','rule_version'}

def apply(data, mode):
    if mode not in ('none','identifiers'): raise ValueError('Unknown redaction mode')
    result=deepcopy(data)
    if mode=='none': return result
    aliases={}
    def alias(value):
        token=repr(value)
        if token not in aliases: aliases[token]='[REDACTED %04d]'%(len(aliases)+1)
        return aliases[token]
    def transform(value,key='',path=()):
        if key=='analyst_metadata': return {k:'[ANALYST METADATA REDACTED]' for k in sorted(value)}
        if key in ('model_metadata','embedding_identity','semantic_identity'):
            return {'redacted':True,'recorded':bool(value)}
        if key=='value': return alias(value)
        if key in ('username','hostname','volume_root','command_line','script_block','value_data','value_name',
                   'process_name','parent_process_name','executable','key','objects','source_ip','destination_ip',
                   'event_data_json','normalization_warnings_json','statement','model_proposal','reason','warnings',
                   'alternatives','source_locations','question','model','identity_basis','locator','query','process','path','ip'):
            return alias(value) if value not in (None,[],{}) else value
        if isinstance(value,dict): return {k:transform(v,k,path+(key,)) for k,v in sorted(value.items())}
        if isinstance(value,list): return [transform(v,key,path) for v in value]
        if not isinstance(value,str): return value
        # Payload fields are never rescued by a coincidental match to a safe word.
        if value in SAFE: return value
        # References and hashes deliberately remain linkable; never arbitrary URLs.
        if key in REF_KEYS and re.fullmatch(r'(?:EVTX|MFT|PREFETCH|REGISTRY):[a-f0-9]{64}:[A-Za-z0-9:._-]+',value): return value
        if key in ('claim_id','relationship_id','detection_id') and re.fullmatch(r'(?:CLM|REL|DET|DETECTION):[a-f0-9]{16,64}',value): return value
        if key in HASH_KEYS and re.fullmatch(r'[a-f0-9]{64}',value): return value
        if key in ('investigation_id','investigation_ids','origins','generation') and re.fullmatch(r'[a-f0-9]{32}',value): return value
        if key in VERSION_KEYS and re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,3}',value): return value
        if key=='field' and re.fullmatch(r'/[a-z_]+(?:/[0-9]+|/[a-z_]+)*',value): return value
        if key in ('timestamp_utc','utc','timestamp_original','original_value','started_utc','finished_utc','first_seen_utc','recorded_utc'):
            if re.fullmatch(r'[0-9TZ:+. -]{1,40}',value): return value
        # Keep Locard's generic semantics; evidence payloads, engine reasons,
        # model prose and unrestricted warning strings are otherwise suppressed.
        return alias(value)
    result=transform(result)
    # Keep controlled timestamp semantics exactly; these fields are renderer
    # metadata, validated against the case. Do not preserve arbitrary text.
    from forensic_assistant.reporting.semantics import timestamp_label
    def stamps(originals,redacted):
        for original,stamp in zip(originals,redacted):
            stamp['source'],stamp['meaning']=timestamp_label(original['source'])
    stamps(data['timeline'],result['timeline'])
    for eid,record in result['evidence'].items(): stamps(data['evidence'][eid]['timestamps'],record['timestamps'])
    result['scope']=data['scope']
    result['caution']=CAUTION
    result['redaction_notice']=NOTICE
    result['limitations']=[]
    if data['limitations']:
        result['limitations'].append('Sensitive limitation text suppressed; review the unredacted report.')
        result['limitations'].append(f"Claim omissions: {data['omissions']['claims']}; timeline section omissions: {data['omissions']['timeline']}.")
        warned=sum(bool(r['fields'].get('truncated_fields') or r['warnings']) for r in data['evidence'].values())
        result['limitations'].append(f'{warned} records have compact-field omissions or parser warnings.')
        for original in data['investigations']:
            status=original['termination'] if original['termination'] in SAFE else 'unknown termination'
            result['limitations'].append('Recorded investigation termination: '+status)
    for old,new in zip(data['claims'],result['claims']):
        if old['category']=='LIMITATION':
            new['assertion']={'items':result['limitations'],'original_item_count':len(old['assertion'].get('items',[]))}
        rebuilt=claim(new['category'],new['assertion'],new['evidence_ids'],new['origins'])
        new.clear();new.update(rebuilt)
    result['graph']=graph(result['claims'],result['evidence'])
    return result

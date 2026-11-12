"""Payload-free D2 diagnostics. Never grants authority or retains response text."""
import json
import re

CONTRACT = 'd2-validation-diagnostic-v1'
LIMIT = 2048
STAGES = frozenset(('initialization', 'provider_dispatch', 'provider_response_receipt',
    'sdk_response_extraction', 'provider_refusal', 'output_truncation', 'json_parsing',
    'compact_schema', 'outcome_validation', 'alias_membership', 'interpretation_premises',
    'relationship_premises', 'parent_canonical_revalidation', 'ipc', 'complete'))
CODES = frozenset(('none', 'malformed_json', 'duplicate_key', 'missing_field', 'unknown_field',
    'wrong_type', 'unsupported_enum', 'item_count', 'duplicate_item', 'blank_text', 'nul_text',
    'utf8_byte_limit', 'outcome_accounts', 'outcome_reason', 'competing_account_required',
    'unknown_support', 'incomplete_interpretation', 'incomplete_relationship', 'request_binding',
    'provider_refusal', 'output_truncated', 'provider_failure', 'timeout', 'cancelled',
    'invalid_response_envelope', 'ipc_failure', 'diagnostic_limit', 'unknown_internal_validation_error'))
ENUMS = dict(stage=STAGES, code=CODES, origin={'child','parent'}, failure_stage=STAGES,
    expected_type={'object','array','string','integer','boolean','null'},
    observed_type={'dict','list','str','int','bool','NoneType','float','other'},
    json_extraction={'passed','failed','not_attempted','unknown'},
    json_parsing={'passed','failed','not_attempted','unknown'},
    completion={'stop','end_turn','length','refusal','unknown'},
    usage_availability={'reported','absent','not_received','discarded_by_earlier_failure'},
    worker_outcome={'accepted','rejected','interrupted','unknown'}, cleanup={'confirmed','unknown','unconfirmed'})
NUMBERS = {'characters','utf8_bytes','maximum_bytes','response_bytes'}
REQUIRED = {'contract','stage','code','origin','provider_response_received','json_extraction',
    'json_parsing','completion','usage_availability','worker_outcome','cleanup'}
FIELDS = REQUIRED | set(ENUMS) | NUMBERS | {'pointer'}
# A schema-derived path whitelist: model keys never become diagnostic pointers.
KEYS = frozenset(('v','o','a','r','s','e','c','i','u','d','n','g','l','response','contract',
    'request_id','packet_digest','items','assessment','local_id','kind','statement','support_refs',
    'interpretation_refs','relationship_refs','contradictory_refs','alternatives','assumptions',
    'gaps','limitations','next_issue_refs','prior_refs','relationship','predicate','endpoints',
    'proposed_answerability','rationale'))


def pointer(path):
    if type(path) is not str or len(path)>256:return None
    match=re.fullmatch(r'(?:d2_quality_canonical|d2_quality|d2|request)((?:\.[a-z_]+|\[[0-9]{1,2}\])*)',path)
    if not match:return None
    parts=re.findall(r'\.([a-z_]+)|\[([0-9]{1,2})\]',match[1])
    if any(key and key not in KEYS for key,_ in parts):return None
    return ''.join('/'+(key or str(int(index))) for key,index in parts)


def validate(value):
    if type(value) is not dict or not REQUIRED<=value.keys() or not value.keys()<=FIELDS or value['contract']!=CONTRACT:
        raise ValueError('D2_DIAGNOSTIC_SHAPE')
    for key,choices in ENUMS.items():
        if key in value and (type(value[key]) is not str or value[key] not in choices):raise ValueError('D2_DIAGNOSTIC_ENUM')
    if value['provider_response_received'] is not None and type(value['provider_response_received']) is not bool:raise ValueError('D2_DIAGNOSTIC_RECEIPT')
    for key in NUMBERS & value.keys():
        if type(value[key]) is not int or not 0<=value[key]<=1048576:raise ValueError('D2_DIAGNOSTIC_COUNT')
    if 'pointer' in value:
        p=value['pointer']
        if type(p) is not str or len(p)>256 or any(x not in KEYS and not re.fullmatch(r'(?:0|[1-9][0-9]?)',x) for x in p.split('/')[1:]) or (p and not p.startswith('/')):
            raise ValueError('D2_DIAGNOSTIC_POINTER')
    if len(json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8'))>LIMIT:raise ValueError('D2_DIAGNOSTIC_LIMIT')
    return value


def usage(value):
    if type(value) is not dict:return {}
    return {k:v for k,v in value.items() if k in ('prompt_tokens','completion_tokens','total_tokens') and type(v) is int and 0<=v<=10000000}


def base(stage='complete',code='none',*,origin='child',received=None,reported=None,outcome='unknown'):
    return dict(contract=CONTRACT,stage=stage,code=code,origin=origin,
        provider_response_received=received,json_extraction='unknown',json_parsing='unknown',
        completion='unknown',usage_availability='reported' if usage(reported) else 'absent' if received is True else 'not_received',
        worker_outcome=outcome,cleanup='unknown')


def failure(exc,*,stage='compact_schema',origin='child',received=None,reported=None,completion=None):
    from forensic_assistant.ai.provider_diagnostics import ProviderFailure
    result=base(stage,'unknown_internal_validation_error',origin=origin,received=received,reported=reported,outcome='rejected')
    if completion in ('stop','end_turn'):result['completion']=completion
    if stage in ('initialization','provider_dispatch'):result.update(json_extraction='not_attempted',json_parsing='not_attempted')
    if stage=='compact_schema':result.update(json_extraction='passed',json_parsing='passed')
    # Only exact Locard-owned constants are mapped; arbitrary exception prose is never exported.
    token=exc.args[0] if isinstance(exc,ValueError) and len(exc.args)==1 and type(exc.args[0]) is str else None
    mapped={
        'Malformed structured response':('json_parsing','malformed_json'),
        'D2_INVALID_JSON':('json_parsing','malformed_json'),
        'Nonfinite JSON value':('json_parsing','malformed_json'),
        'D2_INVALID_JSON_CONSTANT':('json_parsing','malformed_json'),
        'Duplicate JSON key':('json_parsing','duplicate_key'),
        'D2_DUPLICATE_JSON_KEY':('json_parsing','duplicate_key'),
        'D2_RESPONSE_BYTES':('compact_schema','utf8_byte_limit'),
        'Model response exceeds content limit':('compact_schema','utf8_byte_limit'),
        'D2_QUALITY_OUTCOME_ACCOUNTS':('outcome_validation','outcome_accounts'),
        'D2_QUALITY_OUTCOME_REASON':('outcome_validation','outcome_reason'),
        'D2_COMPETING_ACCOUNT_REQUIRED':('outcome_validation','competing_account_required'),
        'D2_UNKNOWN_SUPPORT':('alias_membership','unknown_support'),
        'D2_INCOMPLETE_INTERPRETATION':('interpretation_premises','incomplete_interpretation'),
        'D2_INCOMPLETE_RELATIONSHIP':('relationship_premises','incomplete_relationship'),
        'D2_OMITTED_CONTRADICTORY_SUPPORT':('relationship_premises','incomplete_relationship'),
        'D2_INVALID_RELATIONSHIP':('relationship_premises','incomplete_relationship'),
        'D2_RESPONSE_REQUEST_BINDING':('alias_membership','request_binding')}
    if token in mapped:result['stage'],result['code']=mapped[token]
    detail=getattr(exc,'validation_detail',None)
    if type(detail) is dict:
        codes={'missing parameter':'missing_field','unknown parameter':'unknown_field','wrong type':'wrong_type',
            'unsupported value':'unsupported_enum','invalid item count':'item_count','duplicate items':'duplicate_item'}
        constraint=detail.get('constraint')
        result['code']=codes.get(constraint,'unknown_internal_validation_error') if type(constraint) is str else 'unknown_internal_validation_error'
        if detail.get('constraint')=='invalid string length/content':
            result['code']='nul_text' if detail.get('contains_nul') is True else 'blank_text' if detail.get('blank') is True else 'utf8_byte_limit'
        p=pointer(detail.get('validation_path'))
        if p is not None:result['pointer']=p
        for source,target in (('expected_type','expected_type'),('actual_type','observed_type')):
            if type(detail.get(source)) is str and detail[source] in ENUMS[target]:result[target]=detail[source]
        for source,target in (('characters','characters'),('utf8_bytes','utf8_bytes'),('maximum_utf8_bytes','maximum_bytes')):
            v=detail.get(source)
            if type(v) is int and 0<=v<=1048576:result[target]=v
    if isinstance(exc,ProviderFailure):
        envelope=exc.metadata.get('response_envelope',{})
        if type(envelope.get('envelope_received')) is bool:result['provider_response_received']=envelope['envelope_received']
        result.update(stage='provider_dispatch',code='provider_failure',json_extraction='not_attempted',json_parsing='not_attempted')
        if exc.category=='provider_refusal':result.update(stage='provider_refusal',code='provider_refusal',completion='refusal',json_extraction='failed')
        elif exc.category=='output_truncated':result.update(stage='output_truncation',code='output_truncated',completion='length',json_extraction='failed')
        elif exc.category=='response_envelope_failed':result.update(stage='sdk_response_extraction',code='invalid_response_envelope',json_extraction='failed')
        elif exc.category=='response_parse_failed':result.update(stage='provider_response_receipt',code='invalid_response_envelope')
        elif exc.category=='timeout':result['code']='timeout'
        if result['completion']=='unknown' and envelope.get('finish_reason') in ('stop','end_turn','length'):
            result['completion']=envelope['finish_reason']
        count=envelope.get('content_bytes')
        if type(count) is int and 0<=count<=1048576:result['response_bytes']=count
        if not usage(reported):
            result['usage_availability']='absent' if envelope.get('usage_reported') is False else 'discarded_by_earlier_failure' if result['provider_response_received'] is True else 'not_received'
    elif isinstance(exc,TimeoutError):result['code']='timeout'
    elif isinstance(exc,KeyboardInterrupt):result.update(code='cancelled',worker_outcome='interrupted')
    if result['stage']=='json_parsing':result['json_parsing']='failed'
    if token in ('D2_RESPONSE_BYTES','Model response exceeds content limit'):result['json_parsing']='not_attempted'
    if origin=='parent' and stage!='ipc':result['failure_stage']=result['stage'];result['stage']='parent_canonical_revalidation'
    return validate(result)


def line(value):
    validate(value)
    result=value['stage']+' / '+value['code']
    if 'failure_stage' in value:result+=' ('+value['failure_stage']+')'
    if value.get('pointer'):result+=' at '+value['pointer']
    if 'utf8_bytes' in value and 'maximum_bytes' in value:result+='; '+str(value['utf8_bytes'])+' / '+str(value['maximum_bytes'])+' UTF-8 bytes'
    return result

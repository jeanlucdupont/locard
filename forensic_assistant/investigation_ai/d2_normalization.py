"""Bounded set-preserving normalization of known d2q1 reference aliases only."""
import copy
from . import contracts, d2_quality as quality, d2_contracts

VERSION = 'd2-reference-normalization-v1'
PATHS = {'e':'support', 'c':'contrary', 'i':'interpretation'}
MAX_REFERENCES = 32  # Two accounts, each with at most 6 + 6 + 4 raw references.


def receipt():
    return dict(contract=VERSION,occurred=False,removed={v:0 for v in PATHS.values()},
                duplicates_removed=0,canonical_validation='not_attempted')


def validate_receipt(value):
    if (type(value) is not dict or set(value)!={'contract','occurred','removed','duplicates_removed','canonical_validation'}
            or value['contract']!=VERSION or type(value['occurred']) is not bool
            or type(value['removed']) is not dict or set(value['removed'])!=set(PATHS.values())
            or type(value['canonical_validation']) is not str
            or value['canonical_validation'] not in ('not_attempted','passed','failed')):
        raise ValueError('D2_NORMALIZATION_RECEIPT')
    counts=list(value['removed'].values())+[value['duplicates_removed']]
    if any(type(v) is not int or not 0<=v<=MAX_REFERENCES for v in counts):raise ValueError('D2_NORMALIZATION_RECEIPT')
    if sum(value['removed'].values())!=value['duplicates_removed'] or value['occurred']!=(value['duplicates_removed']>0):
        raise ValueError('D2_NORMALIZATION_RECEIPT')
    return value


def _structural(value, packet=None,version=quality.VERSION):
    # Exact provider-facing structure, including raw item counts, before any
    # mutation. The canonical validator remains responsible for UTF-8 byte limits.
    from forensic_assistant.ai.openai_schema import request_schema
    from forensic_assistant.ai.response_contract import validator
    from . import d2_schema
    schema=request_schema('openai',quality.schema(version) if packet is None else d2_schema.from_packet(packet,version))
    error=next(validator(schema).iter_errors(value),None)
    if error is None:return
    failure=ValueError('D2_RAW_SCHEMA')
    if packet is not None:
        failure.d2_schema_policy=d2_schema.POLICY
        failure.reference_detail=d2_schema.reference_detail(list(error.absolute_path),error.instance,packet)
    constraints={'required':'missing parameter','additionalProperties':'unknown parameter','type':'wrong type',
                 'enum':'unsupported value','minItems':'invalid item count','maxItems':'invalid item count',
                 'minLength':'invalid string length/content','maxLength':'invalid string length/content'}
    path='d2_quality'
    # Never include unknown JSON keys, exception messages, or instance values.
    allowed={'v','o','a','r','s','e','c','i','u','d','n'}
    for part in error.absolute_path:
        if type(part) is int and 0<=part<100:path+='['+str(part)+']'
        elif type(part) is str and part in allowed:path+='.'+part
        else:break
    failure.validation_detail=dict(validation_path=path,constraint=constraints.get(error.validator,''),
        expected_type=error.schema.get('type'),actual_type=type(error.instance).__name__)
    if type(error.instance) is str and error.validator in ('minLength','maxLength'):
        failure.validation_detail.update(characters=len(error.instance),utf8_bytes=len(error.instance.encode('utf-8')),
            maximum_utf8_bytes=error.schema.get('maxLength',1024),blank=not error.instance.strip(),contains_nul='\0' in error.instance)
    raise failure


def canonicalize(raw,packet,*,typed=False,version=quality.VERSION):
    """No original evidence mutation, alias repair, or post-dedup size admission."""
    info=receipt()
    value=None
    try:
        value=contracts.loads(raw,max_bytes=d2_contracts.RESPONSE_BYTES)
        _structural(value,packet if typed else None,version)
        refs={s['alias'] for s in packet['content']['supports']}
        interpretations={s['alias'] for s in packet['content']['interpretations']}
        count=0
        # Check membership before normalization: unknown/case/space/epoch aliases
        # are never transformed into valid support, even when repeated.
        for account in value['a']:
            for key in PATHS:
                count+=len(account[key])
                if count>MAX_REFERENCES:raise ValueError('D2_NORMALIZATION_LIMIT')
                if any(alias not in (interpretations if key=='i' else refs) for alias in account[key]):
                    raise ValueError('D2_UNKNOWN_SUPPORT')
        result=copy.deepcopy(value)
        for account in result['a']:
            for key,category in PATHS.items():
                unique=list(dict.fromkeys(account[key]))
                info['removed'][category]+=len(account[key])-len(unique)
                account[key]=unique
        info['duplicates_removed']=sum(info['removed'].values())
        info['occurred']=info['duplicates_removed']>0
        return result,info
    except Exception as exc:
        exc.d2_normalization=info
        exc.d2_outcome=quality.outcome_detail(value,'structural_invalid')
        raise

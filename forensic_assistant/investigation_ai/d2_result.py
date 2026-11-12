"""Bounded D2 terminal IPC. No evidence context is accepted from the child."""
import json
import hashlib
from . import d2_contracts
from . import d2_diagnostics as diagnostic

CONTRACT = 'd2-worker-result-v1'
DIAGNOSTIC_CONTRACT = 'd2-worker-result-v2'
LIMIT = 32768
RECEIVE_LIMIT = 131072
STAGES = {'initialization', 'provider_dispatch', 'response_validation', 'result_preparation', 'complete'}
CATEGORIES = {'none', 'worker_initialization_failure', 'provider_dispatch_failure', 'provider_timeout',
              'provider_refusal', 'provider_response_invalid', 'response_schema_validation',
              'result_serialization_failure', 'result_byte_limit', 'timeout'}
FIELDS = {'contract','binding','status','stage','category','attempted','provider_response_received',
          'validation','response','usage'}


def binding(prepared):
    p = prepared.packet
    return dict(request_id=p['request_id'], packet_digest=p['packet_digest'],
                request_sha256=hashlib.sha256(prepared.body).hexdigest(),
                source=p['content']['source'], issue=p['content']['issue']['id'],
                provider=prepared.config['provider'], model=prepared.config['model'])


def envelope(bound, *, response=None, usage=None, stage='complete', category='none', attempted=False,
             received=False, diagnostics=None):
    return dict(contract=DIAGNOSTIC_CONTRACT if diagnostics is not None else CONTRACT,binding=bound,status='accepted' if category=='none' else 'rejected',
                stage=stage,category=category,attempted=attempted,provider_response_received=received,
                validation='passed' if category=='none' else 'not_accepted',response=response,usage=usage or {},
                **({'diagnostic':diagnostics} if diagnostics is not None else {}))


def encode(value):
    return json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')


def parse(raw, bound):
    if len(raw)+8>LIMIT:raise ValueError('result_byte_limit')
    def pairs(items):
        result={}
        for k,v in items:
            if k in result:raise ValueError('ipc_invalid_message')
            result[k]=v
        return result
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('ipc_invalid_message')))
    if type(value) is not dict or value.get('binding')!=bound:
        raise ValueError('ipc_invalid_binding')
    if value.get('contract')==DIAGNOSTIC_CONTRACT:
        if set(value)!=FIELDS|{'diagnostic'}:raise ValueError('ipc_invalid_message')
        detail=diagnostic.validate(value['diagnostic'])
        if (detail['origin']!='child' or detail['cleanup']!='unknown'
                or detail['provider_response_received']!=value['provider_response_received']
                or detail['worker_outcome']!=value['status']
                or (detail['code']=='none')!=(value['status']=='accepted')):raise ValueError('ipc_invalid_message')
        if 'normalization' in detail:
            allowed=('passed',) if value['status']=='accepted' else ('failed','not_attempted')
            if detail['normalization']['canonical_validation'] not in allowed:raise ValueError('ipc_invalid_message')
    elif value.get('contract')!=CONTRACT or set(value)!=FIELDS:raise ValueError('ipc_invalid_binding')
    if (value['stage'] not in STAGES or value['category'] not in CATEGORIES
        or type(value['attempted']) is not bool or (value['provider_response_received'] is not None and type(value['provider_response_received']) is not bool)):
        raise ValueError('ipc_invalid_message')
    success=value['category']=='none'
    if value['status']!=('accepted' if success else 'rejected') or value['validation']!=('passed' if success else 'not_accepted'):
        raise ValueError('ipc_invalid_message')
    if success:
        if not value['attempted'] or not value['provider_response_received'] or type(value['response']) is not str:
            raise ValueError('ipc_invalid_message')
        if len(value['response'].encode('utf-8'))>d2_contracts.RESPONSE_BYTES:raise ValueError('result_byte_limit')
    elif value['response'] is not None:raise ValueError('ipc_invalid_message')
    usage=value['usage']
    if type(usage) is not dict or not set(usage)<={'prompt_tokens','completion_tokens','total_tokens'} or any(type(v) is not int or not 0<=v<=10000000 for v in usage.values()):
        raise ValueError('ipc_invalid_message')
    if 'diagnostic' in value and ((value['diagnostic']['usage_availability']=='reported')!=bool(usage)):
        raise ValueError('ipc_invalid_message')
    return value


def send(connection, value):
    """At most one channel write. Oversize/serialization failures become small envelopes."""
    diagnostic_failure=False
    try:
        if 'diagnostic' in value:
            try:diagnostic.validate(value['diagnostic'])
            except (TypeError,ValueError,UnicodeError,RecursionError):
                diagnostic_failure=True
                raise
        payload=encode(value)
        category='result_byte_limit' if len(payload)+8>LIMIT else None
    except (TypeError,ValueError,UnicodeError,RecursionError):
        category='result_serialization_failure'
    if category:
        detail=diagnostic.base('ipc','diagnostic_limit' if diagnostic_failure else 'ipc_failure',
                               received=value['provider_response_received'],reported=value.get('usage'),outcome='rejected')
        value=envelope(value['binding'],category=category,stage='result_preparation',
                       attempted=value['attempted'],received=value['provider_response_received'],
                       usage=diagnostic.usage(value.get('usage')),diagnostics=detail if 'diagnostic' in value else None)
        payload=encode(value)
    if len(payload)+8>LIMIT:return False
    try:
        connection.send_bytes(payload)
        return True
    except (OSError,ValueError):
        return False  # A failed channel cannot carry its own failure diagnostic.

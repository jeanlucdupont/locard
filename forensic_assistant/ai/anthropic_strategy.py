"""Anthropic-only bounded two-call transport; canonical contracts are unchanged."""
import copy
import json
import time
from contextvars import ContextVar
from .response_contract import validate
from .provider_diagnostics import ProviderFailure

VERSION = 1
RAW_STAGE = ContextVar('anthropic_raw_stage', default=None)

def stages(canonical):
    variants = {}
    for branch in canonical['oneOf']:
        props=branch['properties']
        selection=props['tool']['enum'][0] if props['action']['enum']==['tool'] else 'final'
        variants[selection]=copy.deepcopy(branch)
    selector={'type':'object','additionalProperties':False,'required':['selection'],
              'properties':{'selection':{'type':'string','enum':list(variants)}}}
    return selector, variants

def payload_schema(branch):
    result=copy.deepcopy(branch)
    for key in ('action','tool'):
        result['properties'].pop(key,None)
        if key in result['required']:result['required'].remove(key)
    return result

def wire_schemas(canonical):
    selector,variants=stages(canonical)
    return [selector]+[payload_schema(v) for v in variants.values()]

def generate(client,messages,canonical,timeout,handshake):
    started=time.monotonic()
    deadline=started+timeout
    detail={'strategy':'two_stage','stage1_status':'not_attempted','stage2_status':'not_attempted','canonical_validation':'not_checked'}
    usage={}
    selector,variants=stages(canonical)
    def call(number,contract,instruction):
        key='stage'+str(number)
        remaining=deadline-time.monotonic()
        detail[key+'_status']='started'
        from .schema_diagnostics import profile
        detail[key+'_schema_profile']=profile(contract)
        if remaining<=0:raise ProviderFailure('timeout','timeout')
        stage_started=time.monotonic()
        token=RAW_STAGE.set(key)
        try:
            # Reuse only the bounded context already supplied to this logical step.
            context=copy.deepcopy(messages)+[{'role':'user','content':instruction}]
            result=client._cloud_request(context,contract,timeout=remaining,handshake=handshake)
            if time.monotonic()>=deadline:raise ProviderFailure('timeout','timeout')
            value=validate(result['text'],contract)
            detail[key+'_status']='validated'
            for field in ('prompt_tokens','completion_tokens','total_tokens'):
                count=result.get('usage',{}).get(field)
                if type(count) is int and 0<=count<=10000000:
                    usage[field]=usage.get(field,0)+count
                    detail[key+'_'+field]=count
            return value
        except ProviderFailure as exc:
            detail[key+'_status']='timeout' if exc.category=='timeout' else 'schema_rejected' if exc.stage=='provider_request' else 'invalid'
            raise
        finally:
            RAW_STAGE.reset(token)
            detail[key+'_model_time']=round(time.monotonic()-stage_started,6)
    try:
        selection=call(1,selector,'Transport stage 1: return only selection, choosing a tool from the permitted enum or final. Do not provide arguments or findings yet.')['selection']
        detail['selected_tool']=selection
        branch=variants[selection]
        payload=call(2,payload_schema(branch),'Transport stage 2: selection is '+selection+'. Return only the fields required by this selected proposal schema. Preserve the requested rationale; do not change the selection. Use only the supplied context.')
        proposal={'action':'final',**payload} if selection=='final' else {'action':'tool','tool':selection,**payload}
        text=json.dumps(proposal,ensure_ascii=True)
        validate(text,canonical)
        detail['canonical_validation']='passed'
        detail['total_model_time']=round(time.monotonic()-started,6)
        return {'text':text,'usage':usage,'anthropic_strategy':detail,'provider_schema_profile':detail['stage2_schema_profile']}
    except ProviderFailure as exc:
        detail['total_model_time']=round(time.monotonic()-started,6)
        raise ProviderFailure(exc.category,exc.stage,metadata={**exc.metadata,'anthropic_strategy':detail,'provider_schema_profile':detail.get('stage2_schema_profile',detail.get('stage1_schema_profile',{}))}) from None

def safe(value):
    if type(value) is not dict:return {}
    from forensic_assistant.investigation_ai.contracts import TOOLS
    choices={'strategy':{'two_stage'},'stage1_status':{'not_attempted','started','validated','timeout','schema_rejected','invalid'},
             'stage2_status':{'not_attempted','started','validated','timeout','schema_rejected','invalid'},
             'canonical_validation':{'passed','not_checked'},'selected_tool':set(TOOLS)|{'final'}}
    result={k:v for k,v in value.items() if k in choices and type(v) is str and v in choices[k]}
    from .schema_diagnostics import safe_profile
    for key in ('stage1_schema_profile','stage2_schema_profile'):
        profile=safe_profile(value.get(key))
        if profile:result[key]=profile
    for key in ('stage1_model_time','stage2_model_time','total_model_time'):
        v=value.get(key)
        if type(v) in (int,float) and 0<=v<=3600:result[key]=v
    for stage in ('stage1','stage2'):
        for field in ('prompt_tokens','completion_tokens','total_tokens'):
            key=stage+'_'+field;v=value.get(key)
            if type(v) is int and 0<=v<=10000000:result[key]=v
    return result

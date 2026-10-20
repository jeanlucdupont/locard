"""Gemini-only extraction diagnostics; no payload retention or permissive parsing."""
import json
from .provider_diagnostics import ProviderFailure

def kind(value):
    return {str:'string',dict:'object',list:'array',type(None):'null',bool:'boolean',int:'number',float:'number'}.get(type(value),'provider_object')

def safe(value):
    if type(value) is not dict:return {}
    allowed={'container_type':{'provider_object','object','array','null'},
             'content_type':{'string','object','array','null','provider_object','boolean','number'},
             'parsed_type':{'string','object','array','null','boolean','number'},
             'phase':{'extraction','json_parse','wire_validation','canonical_validation','provider_rejection'},
             'json_parse':{'success','failed','not_attempted'},
             'wire_validation':{'passed','failed','not_attempted'},
             'finish_reason':{'stop','end_turn','length','content_filter','tool_calls','other'}}
    result={k:v for k,v in value.items() if k in allowed and type(v) is str and v in allowed[k]}
    if type(value.get('top_level_keys')) is list:
        result['top_level_keys']=sorted({k for k in value['top_level_keys'] if type(k) is str and k in ('status','message','goal','assessment','steps','cautions','action','tool','arguments','reason','answer')})
    return result

def extract(result):
    detail={'container_type':kind(result),'phase':'extraction','json_parse':'not_attempted','wire_validation':'not_attempted'}
    try:
        choice=result.choices[0];message=choice.message
        detail['content_type']=kind(message.content)
        finish=choice.finish_reason
        detail['finish_reason']=finish if finish in ('stop','end_turn','length','content_filter','tool_calls') else 'other'
        if finish not in ('stop','end_turn') or getattr(message,'tool_calls',None) or getattr(message,'function_call',None):raise ValueError()
        text=message.content
        if type(text) is not str or not text.strip() or len(text.encode())>1024*1024:raise ValueError()
        return text,detail
    except (AttributeError,IndexError,TypeError,ValueError,UnicodeError):
        raise ProviderFailure('structured_validation','structured_validation',metadata={'gemini_response':detail}) from None

def validate_response(text,schema,detail):
    from .response_contract import validate
    detail={**detail,'phase':'json_parse'}
    try:
        # Same strict parser, including duplicate-key/nonfinite rejection, first.
        value=validate(text,{})
        detail.update(json_parse='success',parsed_type=kind(value),phase='wire_validation')
        if type(value) is dict:detail['top_level_keys']=list(value)
        validate(text,schema)
        detail['wire_validation']='passed'
        return text
    except ProviderFailure as exc:
        detail['json_parse']='failed' if exc.category=='response_parse_failed' else detail.get('json_parse','not_attempted')
        if detail['phase']=='wire_validation':detail['wire_validation']='failed'
        raise ProviderFailure(exc.category,exc.stage,metadata={**exc.metadata,'gemini_response':detail}) from None

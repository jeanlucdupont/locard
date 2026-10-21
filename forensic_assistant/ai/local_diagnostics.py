"""Local request diagnostics: fixed categories and numeric metadata only."""
import json
from . import diagnostics, raw_diagnostics

def record(category,metadata):
    allowed={'n_prompt_tokens','n_ctx','http_status','requested_output_tokens','prompt_tokens','completion_tokens','total_tokens','prompt_plus_output_budget'}
    safe={k:v for k,v in metadata.items() if k in allowed and type(v) is int and 0<=v<=10000000}
    for k,choices in {'finish_reason':{'stop','length','tool_calls','other'},'content_type':{'string','object','array','null','other'}}.items():
        if metadata.get(k) in choices:safe[k]=metadata[k]
    from .validation_diagnostics import safe as validation_safe
    detail=validation_safe(metadata.get('validation_diagnostics'))
    if detail:safe['validation_diagnostics']=detail
    try:diagnostics.append('llama-server.log',json.dumps({'local_request':category,**safe})+'\n')
    except (OSError,ValueError):pass

def raw(kind,text):
    if raw_diagnostics.enabled:raw_diagnostics.capture({'kind':kind,'text':text})

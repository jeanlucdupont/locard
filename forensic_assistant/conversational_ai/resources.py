"""Offline model bounds and UI-independent resource presentation."""
import json
from functools import lru_cache
from importlib.metadata import distribution,PackageNotFoundError

@lru_cache(maxsize=32)
def model_capacity(model):
    # Only bundled metadata: no SDK import, network lookup, tokenizer download,
    # hidden readiness request or provider selection change.
    try:
        path=distribution('litellm').locate_file('litellm/model_prices_and_context_window_backup.json')
        data=json.loads(path.read_text(encoding='utf-8'))
        value=data.get('openai/'+model,data.get(model,{}))
        incoming=value.get('max_input_tokens');outgoing=value.get('max_output_tokens')
        if type(incoming) is int and incoming>0 and type(outgoing) is int and outgoing>0:
            return incoming,outgoing,'bundled model metadata'
    except (OSError,ValueError,PackageNotFoundError):pass
    return 131072,8192,'conservative unknown-model fallback'

def request_capacity(model,limits,local=None):
    if local:
        from .local import checked
        incoming=checked(local)['context_tokens'];outgoing=incoming
        basis='configured local tokens; UTF-8 byte proxy plus 2048 template reserve, not tokenizer proof'
    else:incoming,outgoing,basis=model_capacity(model)
    output=min(limits['output_tokens'],outgoing)
    # UTF-8 byte count as a conservative token upper estimate, not a tokenizer.
    # Reserve output and 2K framing tokens even for separate input/output limits.
    overhead=0
    if local:
        from .local import wire_overhead
        overhead=wire_overhead(local,output)
    size=min(limits['request_bytes'],max(0 if local else 1024,incoming-output-2048-overhead))
    return size,output,basis

"""Final serialized-body gate for the opt-in, single-attempt D2 worker only."""
import hashlib


def guarded_client(request, transport=None):
    import httpx
    from openai import OpenAI
    from forensic_assistant.investigation_ai import d2_wire as wire
    if request['provider'] != 'openai' or request['schema'] != wire.schema_for(request['messages']):
        raise ValueError('D2_PROVIDER_CONTRACT')
    limit = wire.request_limit(request["messages"])
    expected = wire.body(request['messages'], request['model'],request['schema'])
    if len(expected) > limit or hashlib.sha256(expected).hexdigest() != request['d2_body_sha256']:
        raise ValueError('D2_BODY_ADMISSION')
    class Gate(httpx.BaseTransport):
        def __init__(self):
            self.used = False
            self.inner = transport if transport is not None else httpx.HTTPTransport(retries=0)
        def handle_request(self, outgoing):
            if self.used:
                raise ValueError('D2_ATTEMPT_CONSUMED')
            self.used = True
            if (str(outgoing.url) != 'https://api.openai.com/v1/chat/completions'
                    or outgoing.method != 'POST' or outgoing.content != expected
                    or len(outgoing.content) > limit):
                raise ValueError('D2_SERIALIZED_BODY_CHANGED')
            # This is the sole point at which network activity becomes possible.
            return self.inner.handle_request(outgoing)
        def close(self):
            self.inner.close()
    client=OpenAI(api_key=request['_key'], base_url='https://api.openai.com/v1', max_retries=0,
                  http_client=httpx.Client(transport=Gate(), follow_redirects=False,
                                           timeout=min(55, request['timeout'])))
    # LiteLLM may omit OpenAI's explicit refusal field during conversion. Retain
    # only the sanitized envelope failure, never SDK response text, on this client.
    create=client.chat.completions.create
    client._locard_d2_failure=None
    def observed_create(*args,**kwargs):
        response=create(*args,**kwargs)
        from .response_envelope import content
        from .provider_diagnostics import ProviderFailure
        # LiteLLM requests OpenAI's LegacyAPIResponse wrapper. parse() decodes
        # that already-received response and caches it; it makes no HTTP request.
        parsed=response.parse() if callable(getattr(response,'parse',None)) else response
        try:content(parsed,{'max_completion_tokens':1024},explicit_refusal=True)
        except ProviderFailure as exc:
            client._locard_d2_failure={'category':exc.category,'stage':exc.stage,'metadata':exc.metadata}
        return response
    client.chat.completions.create=observed_create
    return client

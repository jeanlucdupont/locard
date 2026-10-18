"""One-shot isolated LiteLLM adapter. No evidence/request logging or tool execution."""
import json
import logging
import os
import sys

from .settings import PROVIDERS


def generate(request, sdk):
    provider = request['provider']
    if provider not in PROVIDERS or provider == 'local':
        raise ValueError('Invalid cloud provider')
    # Explicit provider + model, no router, fallback or provider-native tools.
    kwargs = dict(model=provider + '/' + request['model'],
                  custom_llm_provider=provider, api_key=os.environ[PROVIDERS[provider][1]],
                  messages=request['messages'], stream=False, max_tokens=1024,
                  timeout=request['timeout'], num_retries=0, drop_params=False)
    if request.get('schema'):
        kwargs['response_format'] = {'type': 'json_schema', 'json_schema': {
            'name': 'forensic_analysis', 'strict': True, 'schema': request['schema']}}
    else:
        kwargs['response_format'] = {'type': 'json_object'}
    result = sdk.completion(**kwargs)
    choice = result.choices[0]
    if choice.finish_reason not in ('stop', 'end_turn') or getattr(choice.message, 'tool_calls', None) or getattr(choice.message, 'function_call', None):
        raise ValueError('Unsupported completion')
    text = choice.message.content
    if not isinstance(text, str) or not text.strip() or len(text.encode()) > 1024 * 1024:
        raise ValueError('Invalid completion')
    usage = getattr(result, 'usage', None)
    return {'text': text, 'usage': {name: getattr(usage, name) for name in
            ('prompt_tokens', 'completion_tokens', 'total_tokens')
            if type(getattr(usage, name, None)) is int and 0 <= getattr(usage, name) <= 10000000}}


def main():
    # Parent owns bounded wall-clock termination. No provider exception is serialized.
    output = sys.stdout
    try:
        request = json.loads(sys.stdin.buffer.read(1024 * 1024 + 1))
        with open(os.devnull, 'w') as sink:
            sys.stdout = sys.stderr = sink
            logging.disable(logging.CRITICAL)
            os.environ['LITELLM_LOCAL_MODEL_COST_MAP'] = 'True'
            os.environ['LITELLM_TELEMETRY'] = 'False'
            os.environ['DO_NOT_TRACK'] = '1'
            os.environ['LITELLM_MODE'] = 'PRODUCTION'
            os.environ['PYTHON_DOTENV_DISABLED'] = '1'
            import litellm
            litellm.telemetry = False
            litellm.set_verbose = False
            litellm.callbacks = []
            litellm.success_callback = []
            litellm.failure_callback = []
            result = generate(request, litellm)
        output.write(json.dumps(result))
    except BaseException:
        output.write('{"error":"Cloud provider could not return a supported response"}')
    finally:
        output.flush()


if __name__ == '__main__':
    main()
    # This is a one-shot IPC worker. SDK background executors must not keep a
    # completed response alive until the parent's request deadline. main flushes
    # the sole response first; the parent still closes its owned process job.
    os._exit(0)

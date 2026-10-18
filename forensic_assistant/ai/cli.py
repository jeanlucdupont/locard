"""Provider settings and owned-runtime controls; no case is required."""
from pathlib import Path
import os
import sys
from . import settings, runtime
from forensic_assistant.terminal_activity import ActivityIndicator

WARNING = ('Cloud AI selected.\n\nEvidence supplied to the AI may leave this computer '
           'and be processed by the selected provider.')


def configure(commands):
    parser = commands.add_parser('ai', help='Configure AI provider and local runtime',
        description='Local uses llama.cpp / llama-server with a compatible user-selected GGUF model. Status distinguishes configuration readiness from runtime state. Cloud use sends bounded model context to the selected provider.')
    subs = parser.add_subparsers(dest='ai_command')
    for name in ('provider', 'status', 'configure', 'start', 'stop'):
        child = subs.add_parser(name, help={'provider':'View or select provider', 'status':'Show provider and runtime status',
            'configure':'Configure provider/model or local paths', 'start':'Start the owned local runtime',
            'stop':'Stop only the Locard-owned runtime'}[name])
        child.add_argument('--json', action='store_true')
        if name in ('provider', 'configure'):
            child.add_argument('provider', nargs='?', choices=list(settings.PROVIDERS))
            child.add_argument('--model', help='Explicit cloud model name, without provider prefix')
            child.add_argument('--acknowledge-cloud', action='store_true', help='Explicitly acknowledge transmission to the selected cloud provider')
        if name == 'configure':
            child.add_argument('--executable')
            child.add_argument('--model-path')
            child.add_argument('--context', type=int)
            child.add_argument('--gpu-layers', type=int)
            child.add_argument('--port', type=int, help='Preferred loopback port; 0 selects a free port')


def status(config):
    import os
    provider = config['provider']
    result = dict(provider=settings.PROVIDERS[provider][0], mode='Local' if provider == 'local' else 'Cloud')
    if provider == 'local':
        result.update(settings.local_configuration(config))
        current = runtime.status()
        # Runtime identity is diagnostic, not the configured model label.
        result.update({k: v for k, v in current.items() if k in
                       ('runtime', 'endpoint', 'owned', 'idle_timeout_seconds', 'runtime_reported_models')})
        if config['model_path']:
            result.update(model=Path(config['model_path']).name, model_path=config['model_path'])
        if config['executable']:
            result['executable'] = config['executable']
    else:
        available = bool(os.environ.get(settings.PROVIDERS[provider][1], '').strip())
        result.update(model=config['model'], api_key='available' if available else 'missing',
                      configuration='configured_ready' if available else 'credential_missing')
        if not available:
            result['configuration_detail'] = 'Set ' + settings.PROVIDERS[provider][1] + ' before starting Locard.'
    return result


class SetupCancelled(Exception):
    pass


def answer(read, prompt):
    value = read(prompt).strip()
    if value.casefold() in ('cancel', 'quit', 'exit'):
        raise SetupCancelled()
    return value


def local_setup(config, read):
    print('Local AI setup (llama.cpp / llama-server). Type cancel to return.')
    while True:
        candidate = dict(config)
        for field, prompt in [('executable', 'Path to llama-server.exe: '), ('model_path', 'Path to GGUF model: ')]:
            value = answer(read, prompt).strip('"')
            candidate[field] = os.path.abspath(value) if value else config[field]
        state = settings.local_configuration(candidate)
        if state['configuration'] == 'configured_ready':
            from forensic_assistant.retrieval.presentation import safe_text
            print('Model: ' + safe_text(Path(candidate['model_path']).name))
            return candidate
        print(state['configuration_detail'])
        if answer(read, 'Retry local setup? [Y/n]: ').casefold() in ('n', 'no'):
            raise SetupCancelled()


def dispatch(args):
    config = settings.load()
    operation = args.ai_command or 'status'
    if operation in ('provider', 'configure'):
        try:
            return configure_settings(args, config, operation)
        except (SetupCancelled, EOFError, KeyboardInterrupt):
            print('AI configuration cancelled; previous settings retained.')
            return {'status': 'unchanged', **status(config)}
    if operation == 'start':
        if config['provider'] != 'local':
            raise ValueError('Select Local before starting its runtime')
        settings.require_local(config)
        with ActivityIndicator('Starting local AI...', args=args) as indicator:
            runtime.ensure(config, indicator.update)
    elif operation == 'stop':
        runtime.stop()
    return status(config)


def configure_settings(args, config, operation):
    selected = getattr(args, 'provider', None)
    read = getattr(args, '_confirm', None)
    human = not args.json and callable(read)
    supplied = any(getattr(args, name, None) is not None for name in
                   ('model', 'executable', 'model_path', 'context', 'gpu_layers', 'port'))
    guided = operation == 'configure' and human and not supplied
    if guided and not selected:
        print('Choose AI provider')
        for number, (name, (label, _)) in enumerate(settings.PROVIDERS.items(), 1):
            print(f'  {number}. {label}  ' + ('Recommended - evidence stays local' if name == 'local' else 'Cloud'))
        choice = answer(read, 'Provider [1]: ') or '1'
        if not choice.isdigit() or not 1 <= int(choice) <= len(settings.PROVIDERS):
            raise ValueError('Invalid provider selection')
        selected = list(settings.PROVIDERS)[int(choice)-1]
    updated = dict(config)
    if selected and selected != config['provider']:
        updated.update(provider=selected, model='', cloud_acknowledged=False)
    model = getattr(args, 'model', None)
    if updated['provider'] == 'local':
        if model is not None:
            raise ValueError('--model is for cloud model identifiers; Local derives its name from --model-path.')
        updated['model'] = ''
        if guided:
            updated = local_setup(updated, read)
    else:
        # Disclosure precedes asking for a cloud model identifier.
        if not updated['cloud_acknowledged']:
            accepted = getattr(args, 'acknowledge_cloud', False)
            if not accepted and human:
                print(WARNING)
                accepted = answer(read, 'Continue? [y/N]: ').casefold() in ('y', 'yes')
                if not accepted:
                    return {'status': 'unchanged', **status(config)}
            if not accepted:
                raise ValueError(WARNING + '\nExplicitly pass --acknowledge-cloud to select this provider.')
            updated['cloud_acknowledged'] = True
        if model is not None:
            updated['model'] = model
        if not updated['model'] and human:
            updated['model'] = answer(read, 'Cloud model identifier: ')
    for field in ('executable', 'model_path', 'context', 'gpu_layers', 'port'):
        value = getattr(args, field, None)
        if value is not None:
            updated[field] = os.path.abspath(value) if field in ('executable', 'model_path') else value
    if updated['provider'] == 'local' and settings.local_configuration(updated)['configuration'] == 'configured_invalid':
        settings.require_local(updated)
    if updated != config:
        settings.save(updated)
    return status(updated)


def offer_setup(read):
    """Once at shell entry, after case selection; never load or start a model."""
    from types import SimpleNamespace
    try:
        config = settings.load()
        state = status(config)
        if state['configuration'] == 'configured_ready':
            return
        if state['configuration'] == 'credential_missing':
            print(state['configuration_detail'])
            return
        print('AI is not configured.' if state['configuration'] == 'not_configured' else 'AI configuration is invalid.')
        if answer(read, 'Configure AI now? [Y/n]: ').casefold() in ('n', 'no'):
            return
        print(render(dispatch(SimpleNamespace(ai_command='configure', provider=None, json=False, _confirm=read))))
    except (SetupCancelled, EOFError, KeyboardInterrupt):
        print('AI setup skipped. Use ai configure later.')
    except (ValueError, OSError) as exc:
        from forensic_assistant.retrieval.presentation import safe_text
        print('AI configuration unavailable: ' + safe_text(str(exc)) + ' Use ai configure later.')


def render(value):
    from forensic_assistant.retrieval.presentation import safe_text
    labels = {'provider':'Provider', 'configuration':'Configuration', 'model':'Model', 'model_path':'Model path', 'executable':'Executable', 'mode':'Evidence handling', 'runtime':'Runtime',
              'api_key':'API key', 'endpoint':'Endpoint', 'owned':'Locard-owned', 'runtime_reported_models':'Runtime-reported models', 'configuration_detail':'Details'}
    lines = ['AI provider']
    for key, label in labels.items():
        if key in value: lines.append('  ' + label + ': ' + safe_text(str(value[key]).replace('_', ' ') if key == 'configuration' else str(value[key])))
    if 'idle_timeout_seconds' in value: lines.append('  Idle timeout: 15 minutes')
    return '\n'.join(lines)

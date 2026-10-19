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
    for name in ('provider', 'status', 'configure', 'start', 'stop', 'logs'):
        child = subs.add_parser(name, help={'provider':'View or select provider', 'status':'Show provider and runtime status',
            'configure':'Configure provider/model or local paths', 'start':'Start the owned local runtime',
            'stop':'Stop only the Locard-owned runtime', 'logs':'Show private managed runtime diagnostics'}[name])
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
            child.add_argument('--extra-options', help='Validated performance options; -ngl/-c update dedicated settings, never duplicate defaults')


def status(config):
    import os
    provider = config['provider']
    result = dict(provider=settings.PROVIDERS[provider][0], mode='Local' if provider == 'local' else 'Cloud')
    if provider == 'local':
        result['configured_options'] = {k: config.get(k, []) for k in ('gpu_layers', 'context', 'extra_options')}
        result.update(settings.local_configuration(config))
        current = runtime.status(config)
        # Runtime identity is diagnostic, not the configured model label.
        result.update({k: v for k, v in current.items() if k in
                       ('runtime', 'endpoint', 'owned', 'ownership', 'restart_required', 'idle_timeout_seconds', 'runtime_reported_models')})
        if current.get('ownership') == 'external':
            result['configuration_detail'] = current['configuration_detail']
            result['configuration_differs'] = current.get('configuration_differs', False)
        elif current.get('owned') and type(current.get('active_configuration')) is dict:
            result['active_options'] = {k: current['active_configuration'][k]
                                       for k in ('gpu_layers', 'context', 'extra_options')
                                       if k in current['active_configuration']}
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


def local_setup(config, read, args=None):
    from forensic_assistant.terminal import Palette, enabled
    palette = Palette(enabled(args))
    print(palette('heading', 'Local AI setup (llama.cpp / llama-server). Type cancel to return.'))
    while True:
        candidate = dict(config)
        for field, prompt in [('executable', 'Full file path to llama-server.exe: '), ('model_path', 'Full file path to GGUF model: ')]:
            value = answer(read, prompt).strip('"')
            candidate[field] = os.path.abspath(value) if value else config[field]
        state = settings.local_configuration(candidate)
        if state['configuration'] == 'configured_ready':
            from forensic_assistant.retrieval.presentation import safe_text
            print('Model: ' + safe_text(Path(candidate['model_path']).name))
            return candidate
        print(palette('error', state['configuration_detail']))
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
        from .backend import restart_confirmation, RESTART
        with ActivityIndicator('Starting local AI...', args=args) as indicator:
            read = getattr(args, '_confirm', None) if not args.json else None
            with restart_confirmation(read, indicator):
                runtime.acquire(config, indicator.update, RESTART.get())
    elif operation == 'stop':
        current = runtime.status(config)
        if current.get('ownership') == 'external':
            return {**status(config), 'message': 'The active local AI runtime is externally managed.\nLocard will not stop it.'}
        runtime.stop()
    elif operation == 'logs':
        from .diagnostics import tail
        current = runtime.status(config)
        return {'logs': ('Locard does not own or capture external runtime logs.'
                         if current.get('ownership') == 'external' else tail())}
    return status(config)


def configure_settings(args, config, operation):
    selected = getattr(args, 'provider', None)
    read = getattr(args, '_confirm', None)
    human = not args.json and callable(read)
    supplied = any(getattr(args, name, None) is not None for name in
                   ('model', 'executable', 'model_path', 'context', 'gpu_layers', 'port', 'extra_options'))
    guided = operation == 'configure' and human and not supplied
    if guided and not selected:
        from forensic_assistant.terminal import Palette, enabled
        print(Palette(enabled(args))('heading', 'Choose AI provider'))
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
            updated = local_setup(updated, read, args)
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
    extra = getattr(args, 'extra_options', None)
    if extra is not None:
        if updated['provider'] != 'local':
            raise ValueError('--extra-options is only available for Local')
        from .options import parse
        fields, tokens = parse(extra)
        if any(getattr(args, field, None) is not None for field in fields):
            raise ValueError('Do not combine a dedicated setting with its extra-options alias')
        updated.update(fields, extra_options=tokens)
    if updated['provider'] == 'local' and settings.local_configuration(updated)['configuration'] == 'configured_invalid':
        settings.require_local(updated)
    if updated != config:
        settings.save(updated)
    result = status(updated)
    if updated != config:
        result['message'] = ('Configuration changed. Restart the external llama-server manually for the new settings to take effect.'
                             if result.get('ownership') == 'external' else 'AI configuration saved.')
    return result


def offer_setup(read, args=None):
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
        setup_args = SimpleNamespace(ai_command='configure', provider=None, json=False, _confirm=read,
                                     no_color=getattr(args, 'no_color', False))
        print(render(dispatch(setup_args), setup_args))
    except (SetupCancelled, EOFError, KeyboardInterrupt):
        print('AI setup skipped. Use ai configure later.')
    except (ValueError, OSError) as exc:
        from forensic_assistant.retrieval.presentation import safe_text
        print('AI configuration unavailable: ' + safe_text(str(exc)) + ' Use ai configure later.')


def render(value, args=None):
    from forensic_assistant.retrieval.presentation import safe_text
    from forensic_assistant.terminal import Palette, enabled
    palette = Palette(enabled(args))
    if 'logs' in value:
        return '\n'.join(safe_text(line) for line in value['logs'].splitlines())
    labels = {'provider':'Provider', 'configuration':'Configuration', 'model':'Model', 'model_path':'Model path', 'executable':'Executable', 'mode':'Evidence handling', 'runtime':'Runtime',
              'api_key':'API key', 'endpoint':'Endpoint', 'ownership':'Ownership', 'runtime_reported_models':'Runtime-reported models', 'configuration_detail':'Details'}
    lines = [palette('heading', 'AI provider')]
    for key, label in labels.items():
        if key in value:
            text = safe_text(str(value[key]).replace('_', ' ') if key == 'configuration' else str(value[key]))
            role = ('success' if value[key] in ('configured_ready', 'running') else
                    'secondary_text' if value[key] == 'stopped' else 'error')
            if key == 'provider': role = 'key'
            if key in ('provider', 'configuration', 'runtime'): text = palette(role, text)
            lines.append('  ' + label + ': ' + text)
    configured = value.get('configured_options')
    if configured is not None:
        external = value.get('ownership') == 'external'
        lines.append(palette('heading', '  Configured options' if external else '  Runtime options'))
        active = value.get('active_options', {})
        changed = value.get('restart_required', False)
        for field, label in (('gpu_layers', 'GPU layers'), ('context', 'Context size'), ('extra_options', 'Extra options')):
            def display(options):
                raw = options.get(field)
                return safe_text(' '.join(raw) if field == 'extra_options' and isinstance(raw, list) else str(raw))
            if field == 'extra_options' and not configured.get(field) and not active.get(field):
                continue
            lines.append('    ' + ('Configured ' + label.lower() if changed else label) + ': ' +
                         (display(configured) or '(none)'))
            if changed:
                lines.append('    Active ' + label.lower() + ': ' +
                             ((display(active) or '(none)') if field in active else 'unavailable; restart to record settings'))
    if value.get('restart_required'):
        lines.append(palette('warning', '  Configuration changed: restart required'))
    if value.get('configuration_differs'):
        lines.append(palette('warning', '  Configuration differs from running external runtime (reported model).'))
    if value.get('message'):
        lines.append(palette('success' if value['message'] == 'AI configuration saved.' else 'warning',
                            '\n'.join(safe_text(line) for line in value['message'].splitlines())))
    if 'idle_timeout_seconds' in value: lines.append('  Idle timeout: 15 minutes')
    return '\n'.join(lines)

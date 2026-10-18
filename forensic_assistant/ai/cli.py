"""Provider settings and owned-runtime controls; no case is required."""
from pathlib import Path
import sys
from . import settings, runtime
from forensic_assistant.terminal_activity import ActivityIndicator

WARNING = ('Cloud AI selected.\n\nEvidence supplied to the AI may leave this computer '
           'and be processed by the selected provider.')


def configure(commands):
    parser = commands.add_parser('ai', help='Configure AI provider and local runtime',
        description='Local is recommended. Cloud use sends bounded model context to the selected provider.')
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
    provider = config['provider']
    result = dict(provider=settings.PROVIDERS[provider][0], mode='Local' if provider == 'local' else 'Cloud',
                  model=Path(config['model_path']).name if provider == 'local' else config['model'])
    if provider == 'local':
        result.update(runtime.status())
    else:
        result['api_key'] = 'available' if bool(__import__('os').environ.get(settings.PROVIDERS[provider][1])) else 'missing'
    return result


def dispatch(args):
    config = settings.load()
    operation = args.ai_command or 'status'
    if operation in ('provider', 'configure'):
        selected = getattr(args, 'provider', None)
        confirm = getattr(args, '_confirm', None)
        human = not args.json and not getattr(args, 'output_file', None) and not getattr(args, 'append_file', None)
        if operation == 'configure' and not selected and human and callable(confirm):
            print('AI provider')
            for number, (name, (label, _)) in enumerate(settings.PROVIDERS.items(), 1):
                print(f'  {number}. {label}  ' + ('Recommended - evidence stays local' if name == 'local' else 'Cloud'))
            answer = confirm('Provider [1]: ').strip() or '1'
            if not answer.isdigit() or not 1 <= int(answer) <= len(settings.PROVIDERS):
                raise ValueError('Invalid provider selection')
            selected = list(settings.PROVIDERS)[int(answer)-1]
        updated = dict(config)
        if selected:
            updated['provider'] = selected
            if selected != config['provider']:
                updated['model'] = ''
                updated['cloud_acknowledged'] = False
        if getattr(args, 'model', None) is not None:
            updated['model'] = args.model
        if updated['provider'] != 'local' and not updated['model'] and callable(confirm) and human:
            updated['model'] = confirm('Cloud model name: ').strip()
        if updated['provider'] != 'local' and not updated['cloud_acknowledged']:
            accepted = getattr(args, 'acknowledge_cloud', False)
            if not accepted and callable(confirm) and human:
                print(WARNING)
                accepted = confirm('Continue? [y/N]: ').strip().casefold() in ('y', 'yes')
                if not accepted:
                    return {'status': 'unchanged', **status(config)}
            if not accepted:
                raise ValueError(WARNING + '\nExplicitly pass --acknowledge-cloud to select this provider.')
            updated['cloud_acknowledged'] = True
        for field in ('executable', 'model_path', 'context', 'gpu_layers', 'port'):
            value = getattr(args, field, None)
            if value is not None:
                updated[field] = str(Path(value).absolute()) if field in ('executable', 'model_path') else value
        if updated != config:
            settings.save(updated)
        return status(updated)
    if operation == 'start':
        if config['provider'] != 'local':
            raise ValueError('Select Local before starting its runtime')
        with ActivityIndicator('Starting local AI...', args=args) as indicator:
            runtime.ensure(config, indicator.update)
    elif operation == 'stop':
        runtime.stop()
    return status(config)


def render(value):
    from forensic_assistant.retrieval.presentation import safe_text
    labels = {'provider':'Provider', 'model':'Model', 'mode':'Evidence handling', 'runtime':'Runtime',
              'api_key':'API key', 'endpoint':'Endpoint', 'owned':'Locard-owned'}
    lines = ['AI provider']
    for key, label in labels.items():
        if key in value: lines.append('  ' + label + ': ' + safe_text(str(value[key])))
    if 'idle_timeout_seconds' in value: lines.append('  Idle timeout: 15 minutes')
    return '\n'.join(lines)

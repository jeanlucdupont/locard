"""Non-evidence provider preferences. Credentials are never persisted here."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import tempfile

from forensic_assistant.investigation_ai.storage import local_path, DirectoryGuard
from forensic_assistant.investigation_ai.snapshot import _private_mkdir

PROVIDERS = {
    'local': ('Local', None),
    'openai': ('OpenAI', 'OPENAI_API_KEY'),
    'anthropic': ('Anthropic Claude', 'ANTHROPIC_API_KEY'),
    'gemini': ('Google Gemini', 'GEMINI_API_KEY'),
    'deepseek': ('DeepSeek', 'DEEPSEEK_API_KEY'),
    'xai': ('xAI Grok', 'XAI_API_KEY'),
}


def root():
    value = os.environ.get('LOCALAPPDATA')
    if not value or not Path(value).is_absolute():
        raise ValueError('LOCALAPPDATA is required for AI configuration')
    return local_path(Path(value) / 'Locard' / 'ai')


@contextmanager
def private_root():
    path = root()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with DirectoryGuard(path.parent):
        if not path.exists():
            try:
                _private_mkdir(path)
            except FileExistsError:
                pass
        with DirectoryGuard(path):
            yield path


def read(path):
    path = local_path(path)
    with path.open('rb') as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError('AI state exceeds its size limit')
    try:
        return json.loads(data)
    except (ValueError, RecursionError):
        raise ValueError('Invalid AI state; preserved without modification') from None


def write(path, value):
    path = local_path(path)
    fd, temp = tempfile.mkstemp(prefix='.ai-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=True, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, local_path(path))
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def defaults():
    return dict(format=1, provider='local', model='', cloud_acknowledged=False,
                executable='', model_path='',
                context=4096, gpu_layers=99, port=8080, startup_seconds=120)


def validate(value):
    if type(value) is not dict or set(value) != set(defaults()):
        raise ValueError('Invalid AI configuration fields')
    if value['format'] != 1 or value['provider'] not in PROVIDERS or type(value['cloud_acknowledged']) is not bool:
        raise ValueError('Invalid AI provider configuration')
    if type(value['model']) is not str or (value['model'] and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}', value['model'])):
        raise ValueError('Use a model name without a provider prefix, path, or URL')
    if value['provider'] != 'local' and (not value['model'] or not value['cloud_acknowledged']):
        raise ValueError('Cloud provider requires an explicit model and acknowledged disclosure')
    for name, low, high in [('context', 512, 131072), ('gpu_layers', 0, 999), ('port', 0, 65535), ('startup_seconds', 1, 600)]:
        if type(value[name]) is not int or not low <= value[name] <= high:
            raise ValueError('Invalid AI runtime setting: ' + name)
    for name in ('executable', 'model_path'):
        if type(value[name]) is not str or (value[name] and not Path(value[name]).is_absolute()):
            raise ValueError('AI runtime paths must be absolute')
    return value


def load():
    path = root() / 'config.json'
    return validate(read(path)) if path.exists() else defaults()


def save(value):
    validate(value)
    # Never overwrite malformed existing state silently.
    load()
    with private_root() as path:
        write(path / 'config.json', value)


def key(provider):
    variable = PROVIDERS[provider][1]
    value = os.environ.get(variable, '') if variable else ''
    if variable and not value.strip():
        raise ValueError(f'API key for {PROVIDERS[provider][0]} is not configured. Set {variable} and retry.')
    return value


def local_configuration(config):
    if not config['executable'] or not config['model_path']:
        return {'configuration': 'not_configured', 'configuration_detail': 'Run ai configure to select llama-server and a compatible GGUF model.'}
    for field, label, extension in [('executable', 'llama-server executable', '.exe'),
                                     ('model_path', 'Model file', '.gguf')]:
        try:
            path = local_path(config[field])
            if not path.is_file():
                raise ValueError(label + ' not found or not a regular file.')
            if (field == 'model_path' or os.name == 'nt') and path.suffix.lower() != extension:
                raise ValueError(label + ' must have the ' + extension + ' extension.')
            with path.open('rb'):
                pass
        except (OSError, ValueError):
            return {'configuration': 'configured_invalid',
                    'configuration_detail': label + ' is missing, inaccessible, redirected, or invalid' +
                    (' (requires .gguf).' if field == 'model_path' else '.')}
    return {'configuration': 'configured_ready'}


def require_local(config):
    state = local_configuration(config)
    if state['configuration'] != 'configured_ready':
        raise ValueError('Local AI is not configured or is invalid. ' + state['configuration_detail'] + ' Use ai configure.')

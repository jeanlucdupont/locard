"""User-local model preferences and optional, offline runtime diagnostics."""
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import sys
import tempfile

from forensic_assistant.interactive.state import state_path
from forensic_assistant.reporting.transcripts import safe_path


def settings_path():
    return safe_path(state_path().parent / 'semantic-state.json')


def model_path(override=None, model='bge'):
    if override is not None:
        return safe_path(override)
    path = settings_path()
    if path.exists():
        if path.stat().st_size > 65536:
            raise ValueError('Semantic settings are oversized; preserved without modification')
        value = json.loads(path.read_text(encoding='utf-8'))
        if (not isinstance(value, dict) or set(value) != {'format', 'model_path'}
                or value['format'] != 1 or not isinstance(value['model_path'], str)
                or not Path(value['model_path']).is_absolute()):
            raise ValueError('Malformed semantic settings; preserved without modification')
        return safe_path(value['model_path'])
    name = 'bge-small-en-v1.5' if model == 'bge' else 'all-MiniLM-L6-v2'
    return safe_path(path.parent / 'models' / name)


def remember(path):
    """Only successful explicit model setup changes the shared preference."""
    destination = settings_path()
    # Validate any existing configuration before replacing it.
    model_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.semantic-', dir=destination.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump({'format': 1, 'model_path': str(safe_path(path))}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, safe_path(destination))
    finally:
        Path(temporary).unlink(missing_ok=True)


def requirements():
    """Use installed project metadata, not a second dependency/version list."""
    selected = []
    for requirement in importlib.metadata.requires('locard-forensics') or []:
        package, _, marker = requirement.partition(';')
        if re.search(r'extra\s*==\s*[\"\']semantic[\"\']', marker):
            package = package.strip()
            if not re.fullmatch(r'[A-Za-z0-9_-]+==[A-Za-z0-9.+_-]+', package):
                raise ValueError('Semantic dependency metadata must contain exact pins')
            selected.append(package)
    if not selected:
        raise ValueError('Installed Locard metadata is missing the pinned semantic extra')
    return selected


def dependencies():
    for name in ('HF_HUB_OFFLINE', 'TRANSFORMERS_OFFLINE', 'HF_HUB_DISABLE_TELEMETRY', 'DO_NOT_TRACK'):
        os.environ[name] = '1'
    pins = requirements()
    failures = []
    versions = {}
    for pin in pins:
        name, expected = pin.split('==')
        module = {'faiss-cpu': 'faiss'}.get(name, name.replace('-', '_'))
        try:
            importlib.import_module(module)
            versions[name] = importlib.metadata.version(name)
            if versions[name] != expected:
                failures.append(name + ': installed version differs from the project pin')
        except Exception as exc:
            failures.append(name + ': ' + type(exc).__name__)
    if os.name == 'nt':
        quote = lambda value: "'" + value.replace("'", "''") + "'"
        command = '& ' + quote(sys.executable) + ' -m pip install ' + ' '.join(map(quote, pins))
    else:
        import shlex
        command = shlex.join([sys.executable, '-m', 'pip', 'install', *pins])
    return {'state': 'missing' if failures else 'ready', 'python': sys.executable,
            'failures': failures, 'packages': versions, 'install_command': command}

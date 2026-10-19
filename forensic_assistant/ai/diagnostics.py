"""Bounded runtime diagnostics containing only Locard-controlled messages.

Raw server output may contain prompts, paths, or credentials. Drain it without
retaining it; publish only fixed diagnostic categories, once per process.
"""
import time
from . import settings
from forensic_assistant.investigation_ai.storage import local_path

MESSAGES = {'starting': 'Starting managed llama-server.',
            'ready': 'Managed llama-server is ready.',
            'stopped': 'Managed llama-server stopped.',
            'error': 'llama-server reported an error; check model, executable and performance settings.',
            'warning': 'llama-server reported a warning; raw output omitted for privacy.',
            'failed': 'Managed runtime startup or operation failed.'}


def record(category):
    with settings.private_root() as root:
        path = local_path(root / 'llama-server.log')
        # Atomic replacement avoids following a redirected destination on append.
        previous = b''
        if path.exists():
            with path.open('rb') as stream:
                stream.seek(max(0, path.stat().st_size - 32768))
                previous = stream.read(32768)
        line = (time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()) + ' ' + MESSAGES[category] + '\n').encode()
        import os
        import tempfile
        fd, temporary = tempfile.mkstemp(prefix='.log-', dir=root)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write((previous + line)[-32768:])
            os.replace(temporary, local_path(path))
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def drain(stream):
    seen = set()
    try:
        while True:
            chunk = stream.readline(4096)
            if not chunk:
                break
            lower = chunk.lower()
            for category in ('error', 'warning'):
                if category not in seen and category.encode() in lower:
                    seen.add(category)
                    record(category)
    except (OSError, ValueError):
        pass
    finally:
        stream.close()


def tail():
    path = local_path(settings.root() / 'llama-server.log')
    if not path.exists():
        return 'No managed runtime diagnostics are available.'
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - 32768))
        text = stream.read(32768).decode('utf-8', errors='replace')
    return '\n'.join(text.splitlines()[-40:])

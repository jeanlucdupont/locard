"""Bounded analyst-side path preferences; no command or evidence history."""
from pathlib import Path
import json
import os
import tempfile
from forensic_assistant.reporting.transcripts import safe_path
from forensic_assistant.reporting.model import loads

MAX_BYTES = 1024*1024


def state_path():
    root = os.environ.get('LOCALAPPDATA')
    if not root or not Path(root).is_absolute():
        raise ValueError('LOCALAPPDATA is unavailable; recent cases will not be saved')
    return safe_path(Path(root)/'Locard'/'ui-state.json')


class State:
    def __init__(self, path):
        self.path = Path(path) if path is not None else None
        self.recent = []
        self.blocked = False
        self.warning = None

    def load(self):
        if self.path is None:
            return self
        try:
            path = safe_path(self.path)
            try:
                with path.open('rb') as stream:
                    raw = stream.read(MAX_BYTES+1)
            except FileNotFoundError:
                return self
            if len(raw) > MAX_BYTES:
                raise ValueError('UI state exceeds size limit')
            value = loads(raw)
            if type(value) is not dict or set(value) != {'format','last_database','recent_databases'} or type(value['format']) is not int or value['format'] != 1:
                raise ValueError('Unsupported UI state')
            recent = value['recent_databases']
            if type(recent) is not list or not 1 <= len(recent) <= 10:
                raise ValueError('Invalid recent case list')
            if any(type(p) is not str or len(p) > 32767 or '\x00' in p or not Path(p).is_absolute() for p in recent):
                raise ValueError('Invalid recent case path')
            if value['last_database'] != recent[0] or len({os.path.normcase(p) for p in recent}) != len(recent):
                raise ValueError('Inconsistent UI state')
            self.recent = recent
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            self.blocked = True
            self.warning = 'UI state ignored and preserved: ' + str(exc)
        return self

    def remember(self, validated_path):
        value = str(validated_path)
        self.recent = ([value]+[p for p in self.recent if os.path.normcase(p) != os.path.normcase(value)])[:10]
        if self.path is None or self.blocked:
            return
        payload = json.dumps(dict(format=1,last_database=value,recent_databases=self.recent),ensure_ascii=True,indent=2).encode()
        if len(payload)>MAX_BYTES:
            raise ValueError('UI state exceeds size limit')
        path = safe_path(self.path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.ui-state-', suffix='.tmp', delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            safe_path(path)
            os.replace(temporary, path)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

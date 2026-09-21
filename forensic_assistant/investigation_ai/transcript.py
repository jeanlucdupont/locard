"""Derived, bounded JSON transcripts. Integrity hashes detect changes, not forgery."""
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid
from forensic_assistant import __version__
from .state import encoded

MAX_BYTES = 4 * 1024 * 1024
ID = re.compile(r'[a-f0-9]{32}\Z')

def digest(value): return hashlib.sha256(encoded(value).encode()).hexdigest()

def implementation():
    root = Path(__file__).resolve().parents[1]
    h = hashlib.sha256()
    for path in sorted(root.rglob('*.py')):
        h.update(path.relative_to(root).as_posix().encode()); h.update(path.read_bytes())
    return {'application_version': __version__, 'code_sha256': h.hexdigest(), 'policy_version': 'v4-1', 'schema': 3}

class Transcript:
    def __init__(self, root, metadata):
        root = Path(root).resolve(); root.mkdir(parents=True, exist_ok=True)
        self.id = uuid.uuid4().hex; self.path = root / self.id
        self.path.mkdir()
        self.size = 0; self.chain = '0' * 64; self.count = 0
        self.manifest = {'format': 1, 'investigation_id': self.id, 'derived_data': True,
                         'status': 'RUNNING', **implementation(), **metadata}
        self._manifest()

    def _manifest(self):
        self.manifest.update(event_count=self.count, chain=self.chain)
        pending = self.path / 'manifest.tmp'
        with pending.open('xb') as stream:
            stream.write(encoded(self.manifest).encode()); stream.flush(); os.fsync(stream.fileno())
        # Windows scanners/readers can briefly hold a non-delete-sharing handle.
        # Retry the same atomic replacement; never fall back to an in-place write.
        for attempt in range(6):
            try:
                os.replace(pending, self.path / 'manifest.json'); break
            except PermissionError:
                if attempt == 5: raise
                time.sleep(.02 * (attempt + 1))

    def append(self, kind, data, terminal=False):
        event = {'sequence': self.count, 'kind': kind, 'data': data, 'previous': self.chain}
        event['hash'] = digest(event)
        raw = (encoded(event) + '\n').encode()
        cap = MAX_BYTES if terminal else MAX_BYTES - 512 * 1024
        if len(raw) > 600 * 1024 or self.size + len(raw) > cap:
            raise ValueError('TRANSCRIPT_BUDGET_EXHAUSTED')
        with (self.path / 'events.jsonl').open('ab') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        self.size += len(raw); self.chain = event['hash']; self.count += 1
        self._manifest()

    def finish(self, result):
        self.append('terminal', result, terminal=True)
        self.manifest['status'] = result['termination']; self._manifest()

def load(root, investigation_id):
    if not ID.fullmatch(investigation_id): raise ValueError('Invalid investigation ID')
    root = Path(root).resolve(); path = root / investigation_id
    if path.resolve().parent != root: raise ValueError('Transcript directory escapes configured root')
    def read(name, limit):
        file = path / name
        if file.is_symlink() or file.resolve().parent != path.resolve(): raise ValueError('Transcript file redirection rejected')
        with file.open('rb') as stream: raw = stream.read(limit + 1)
        if len(raw) > limit: raise ValueError('Transcript exceeds size limit')
        return raw
    try:
        manifest = json.loads(read('manifest.json', 64 * 1024))
        lines = read('events.jsonl', MAX_BYTES).splitlines()
        if len(lines) > 256: raise ValueError('Too many transcript events')
        events = []; chain = '0' * 64
        for i, line in enumerate(lines):
            if len(line) > 600 * 1024: raise ValueError('Transcript event exceeds limit')
            event = json.loads(line)
            if type(event) is not dict or set(event) != {'sequence','kind','data','previous','hash'}:
                raise ValueError('Invalid transcript event')
            stored = event.pop('hash')
            if event['sequence'] != i or event['previous'] != chain or digest(event) != stored:
                raise ValueError('Transcript integrity check failed')
            chain = stored; event['hash'] = stored; events.append(event)
        if manifest.get('format') != 1 or manifest.get('investigation_id') != investigation_id:
            raise ValueError('Invalid transcript manifest')
        if manifest.get('event_count') != len(events) or manifest.get('chain') != chain:
            raise ValueError('Transcript incomplete or modified')
        return manifest, events
    except (TypeError, KeyError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError('Malformed untrusted transcript') from exc

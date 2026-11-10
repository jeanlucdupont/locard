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
from .storage import DirectoryGuard, local_path

MAX_BYTES = 4 * 1024 * 1024
ID = re.compile(r'[a-f0-9]{32}\Z')

class JournalPublicationError(BaseException):
    """Fatal execution boundary: ordinary optional-update handlers must not swallow it.

    Supervision catches BaseException and contains the worker. No exception text
    contains evidence. The filesystem may be ahead of the confirmed application state.
    """


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()

READ_VIEW_CONTRACT = 'sqlite-read-view-v1'


def _write_complete(stream, raw):
    """Binary publication writes must accept every byte in one bounded attempt."""
    written = stream.write(raw)
    if type(written) is not int or written != len(raw):
        raise OSError('Incomplete journal write')


def validate_evidence_state(value):
    """Run-local identity, explicitly NOT a digest or cross-run compatibility proof."""
    if (type(value) is not dict or set(value) != {'contract', 'view_id', 'file_identity'}
            or value['contract'] != READ_VIEW_CONTRACT
            or type(value['view_id']) is not str or not ID.fullmatch(value['view_id'])
            or type(value['file_identity']) is not dict
            or set(value['file_identity']) != {'device', 'inode'}
            or any(type(v) is not int or v < 0 for v in value['file_identity'].values())):
        raise ValueError('Invalid investigation evidence-state contract')
    return value


def implementation():
    root = Path(__file__).resolve().parents[1]
    h = hashlib.sha256()
    for path in sorted(root.rglob('*.py')):
        h.update(path.relative_to(root).as_posix().encode())
        h.update(path.read_bytes())
    return {'application_version': __version__, 'code_sha256': h.hexdigest(), 'policy_version': 'v4-3', 'schema': 3}

class Transcript:
    def __init__(self, root, metadata, *, investigation_id=None):
        self.guard = None
        self.stream = None
        root = local_path(root)
        self.guard = DirectoryGuard(root, create=True)
        self.id = investigation_id or uuid.uuid4().hex
        if not ID.fullmatch(self.id):
            self.close()
            raise ValueError('Invalid investigation ID')
        self.path = root / self.id
        try:
            self.path.mkdir(mode=0o700)
            self.child_guard = DirectoryGuard(self.path)
            self.stream = (self.path / 'events.jsonl').open('xb')
        except BaseException:
            self.close()
            raise
        self.size = 0
        self.chain = '0' * 64
        self.count = 0
        self.publication = {'contract':'journal-publication-v1','status':'ready','stage':None}
        self.last_confirmed = None
        self.manifest = {
            'format': 1,
            'investigation_id': self.id,
            'derived_data': True,
            'status': 'RUNNING',
            **implementation(),
            **metadata
        }
        self._manifest()
        self._confirm()

    def _confirm(self):
        from copy import deepcopy
        self.last_confirmed = dict(count=self.count,chain=self.chain,size=self.size,
                                   manifest=deepcopy(self.manifest))

    def _uncertain(self, stage):
        self.publication.update(status='uncertain',stage=stage)
        if self.last_confirmed is not None:
            self.count=self.last_confirmed['count'];self.chain=self.last_confirmed['chain']
            self.size=self.last_confirmed['size'];self.manifest=self.last_confirmed['manifest'].copy()
        # Never append or rewrite the manifest after a possibly partial publication.
        # close() is best effort; supervisor containment remains the ultimate bound.
        try:self.close()
        except BaseException:pass
        error=JournalPublicationError('JOURNAL_PUBLICATION_UNCERTAIN')
        error.diagnostic=dict(contract='journal-publication-v1',status='uncertain',stage=stage,
            confirmed_event_count=self.count,attempted_sequence=self.publication.get('attempted_sequence'),
            event_persistence='not_attempted' if stage=='before_event_write' else 'possible',
            persistence='unknown_requires_strict_validation')
        raise error from None

    def _manifest(self):
        self.manifest.update(event_count=self.count, chain=self.chain)
        pending = self.path / 'manifest.tmp'
        local_path(self.path)
        local_path(self.path / 'manifest.json')
        with pending.open('xb') as stream:
            _write_complete(stream, encoded(self.manifest).encode('utf-8'))
            stream.flush()
            os.fsync(stream.fileno())
        # Windows scanners/readers can briefly hold a non-delete-sharing handle.
        # Retry the same atomic replacement; never fall back to an in-place write.
        for attempt in range(6):
            try:
                os.replace(pending, self.path / 'manifest.json')
                break
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(.02 * (attempt + 1))

    def append(self, kind, data, terminal=False):
        if self.publication['status']=='uncertain':
            raise JournalPublicationError('JOURNAL_PUBLICATION_UNCERTAIN')
        event = {'sequence': self.count, 'kind': kind, 'data': data, 'previous': self.chain}
        event['hash'] = digest(event)
        raw = (encoded(event) + '\n').encode()
        cap = MAX_BYTES if terminal else MAX_BYTES - 512 * 1024
        if len(raw) > 600 * 1024 or self.size + len(raw) > cap:
            self.publication.update(status='admission_rejected',stage='before_io')
            raise ValueError('TRANSCRIPT_BUDGET_EXHAUSTED')
        self.publication.update(status='attempting',stage='before_event_write',
                                attempted_sequence=self.count,attempted_kind=kind)
        stage='before_event_write'
        try:
            local_path(self.path / 'events.jsonl')
            stage='event_write'
            _write_complete(self.stream, raw)
            stage='event_flush';self.stream.flush()
            stage='event_fsync';os.fsync(self.stream.fileno())
            self.size += len(raw);self.chain = event['hash'];self.count += 1
            stage='manifest_publication';self._manifest()
            self._confirm()
        except BaseException:
            self._uncertain(stage)
        self.publication.update(status='confirmed',stage=None,confirmed_sequence=self.count-1)

    def finish(self, result):
        try:
            self.append('terminal', result, terminal=True)
            self.manifest['status'] = result['termination']
            try:
                self._manifest()
                self._confirm()
            except BaseException:
                self._uncertain('terminal_manifest_publication')
        finally:
            self.close()

    def close(self):
        if self.stream is not None:
            self.stream.close()
            self.stream = None
        if getattr(self, 'child_guard', None):
            self.child_guard.close()
        if self.guard:
            self.guard.close()

    def __del__(self):
        self.close()

def load(root, investigation_id):
    if not ID.fullmatch(investigation_id):
        raise ValueError('Invalid investigation ID')
    root = local_path(root)
    path = root / investigation_id
    local_path(path)
    if path.resolve().parent != root:
        raise ValueError('Transcript directory escapes configured root')
    def read(name, limit):
        file = local_path(path / name)
        if file.is_symlink() or file.resolve().parent != path.resolve():
            raise ValueError('Transcript file redirection rejected')
        with file.open('rb') as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('Transcript exceeds size limit')
        return raw
    try:
        manifest = json.loads(read('manifest.json', 64 * 1024))
        lines = read('events.jsonl', MAX_BYTES).splitlines()
        if len(lines) > 256:
            raise ValueError('Too many transcript events')
        events = []
        chain = '0' * 64
        for i, line in enumerate(lines):
            if len(line) > 600 * 1024:
                raise ValueError('Transcript event exceeds limit')
            event = json.loads(line)
            if type(event) is not dict or set(event) != {'sequence', 'kind', 'data', 'previous', 'hash'}:
                raise ValueError('Invalid transcript event')
            stored = event.pop('hash')
            if event['sequence'] != i or event['previous'] != chain or digest(event) != stored:
                raise ValueError('Transcript integrity check failed')
            if event['kind'] == 'exposure' and 'contract' in event['data'].get('content', {}):
                from .disclosure import CONTRACT
                if (event['data']['content']['contract'] != CONTRACT
                        or event['data']['content'].get('encoding') != 'tuples-v1'):
                    raise ValueError('Unsupported disclosure contract')
            chain = stored
            event['hash'] = stored
            events.append(event)
        if manifest.get('format') != 1 or manifest.get('investigation_id') != investigation_id:
            raise ValueError('Invalid transcript manifest')
        if manifest.get('event_count') != len(events) or manifest.get('chain') != chain:
            raise ValueError('Transcript incomplete or modified')
        if manifest.get('evidence_state') is not None:
            state = validate_evidence_state(manifest['evidence_state'])
            if manifest.get('evidence_fingerprint') is not None:
                raise ValueError('Read-view transcript must not claim a case fingerprint')
            for event in events:
                data = event['data']
                response = data if event['kind'] in ('initial', 'terminal') else data.get('response') if event['kind'] == 'result' else None
                if response is not None and (response.get('evidence_state') != state or
                        response.get('evidence_fingerprint' if event['kind']=='terminal' else 'fingerprint') is not None):
                    raise ValueError('Transcript read-view identity mismatch')
        if (path / 'termination.json').exists():
            marker = json.loads(read('termination.json', 4096))
            if (not isinstance(marker, dict) or marker.get('investigation_id') != investigation_id
                    or marker.get('derived_data') is not True):
                raise ValueError('Invalid interruption marker')
            manifest['interruption'] = marker
        return manifest, events
    except (TypeError, KeyError, AttributeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError('Malformed untrusted transcript') from exc

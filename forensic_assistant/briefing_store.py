"""Private analyst briefing revisions, separate from immutable case evidence."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from forensic_assistant.investigation_ai.storage import local_path, DirectoryGuard
from forensic_assistant.investigation_ai.snapshot import _private_mkdir

FIELDS = {'when': 'When', 'incident': 'Reported incident', 'people': 'People',
          'systems': 'Systems or locations', 'indicators': 'Known indicators',
          'activities': 'Reported processes or activities', 'alerts': 'Security alerts',
          'objectives': 'Investigation objectives', 'uncertainty': 'Additional information or uncertainty'}
MAX_STORE = 8 * 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True).encode()).hexdigest()


def content(answers, narrative, interviews=None, canonical=None):
    if type(answers) is not dict or set(answers) != set(FIELDS):
        raise ValueError('Invalid briefing answer fields.')
    values = [*answers.values(), narrative]
    if interviews is not None:
        from forensic_assistant.briefing_interview import validate_sessions
        values.extend(validate_sessions(interviews))
    if any(type(v) is not str or '\0' in v for v in values):
        raise ValueError('Invalid briefing text.')
    if any(len(v.encode('utf-8')) > 32768 for v in values) or sum(len(v.encode('utf-8')) for v in values) > 40960:
        raise ValueError('Briefing content exceeds 32 KiB per field / 40 KiB total.')
    if canonical is not None:
        from .briefing_canonical import check_envelope
        check_envelope(canonical)
    return {'answers': dict(answers), 'narrative': narrative, **({'interviews': interviews} if interviews is not None else {}), **({'canonical':canonical} if canonical is not None else {})}


class Store:
    def __init__(self, case):
        from forensic_assistant.interactive.case import validate
        self.case = local_path(validate(case))
        info = self.case.stat()
        self.identity = {'path': os.path.normcase(str(self.case)), 'device': info.st_dev, 'inode': info.st_ino}
        self.root = local_path(str(self.case) + '.briefing')
        self.path = self.root / 'state.json'

    def check_case(self):
        info = local_path(self.case).stat()
        if (info.st_dev, info.st_ino) != (self.identity['device'], self.identity['inode']):
            raise ValueError('Case file identity changed; briefing not saved.')

    def load(self):
        try:
            return self._load()
        except (KeyError, TypeError, RecursionError, UnicodeError):
            raise ValueError('Malformed briefing workspace; preserved without modification.') from None

    def _load(self):
        self.check_case()
        if not self.root.exists():
            return None
        with DirectoryGuard(self.root):
            path = local_path(self.path)
            if not path.exists():
                raise ValueError('Briefing workspace is incomplete; preserved for recovery.')
            if not path.is_file() or path.stat().st_nlink != 1:
                raise ValueError('Briefing state must be a private regular file.')
            with path.open('rb') as stream:
                raw = stream.read(MAX_STORE + 1)
            if len(raw) > MAX_STORE:
                raise ValueError('Briefing storage bound exceeded.')
            from forensic_assistant.investigation_ai.contracts import loads
            state = loads(raw.decode('utf-8'), max_bytes=MAX_STORE)
            if type(state) is not dict or set(state) != {'format','case','revisions','analyses'} or state['format'] != 1 or state['case'] != self.identity:
                raise ValueError('Unsupported briefing format or case identity mismatch.')
            revisions = state['revisions']
            if type(revisions) is not list or not 1 <= len(revisions) <= 100:
                raise ValueError('Invalid briefing revision history.')
            for number, revision in enumerate(revisions, 1):
                if type(revision) is not dict or set(revision) != {'revision','modified','digest','content'} or revision['revision'] != number:
                    raise ValueError('Invalid briefing revision.')
                if type(revision['modified']) is not str:
                    raise ValueError('Invalid briefing timestamp.')
                datetime.fromisoformat(revision['modified'])
                c = revision['content']
                if type(c) is not dict or set(c) not in ({'answers','narrative'}, {'answers','narrative','interviews'}, {'answers','narrative','canonical'}, {'answers','narrative','interviews','canonical'}) or content(c['answers'], c['narrative'], c.get('interviews'), c.get('canonical')) != c or digest(c) != revision['digest']:
                    raise ValueError('Briefing content digest mismatch.')
            if type(state['analyses']) is not list or len(state['analyses']) > 100:
                raise ValueError('Invalid briefing analysis metadata.')
            for a in state['analyses']:
                if type(a) is not dict or set(a) != {'revision','digest','created','ai_status'} or type(a['revision']) is not int or not 1 <= a['revision'] <= len(revisions):
                    raise ValueError('Invalid briefing analysis reference.')
                if a['digest'] != revisions[a['revision']-1]['digest'] or a['ai_status'] not in ('not_requested','success','partial','failed','skipped'):
                    raise ValueError('Invalid briefing analysis identity.')
                datetime.fromisoformat(a['created'])
            return state

    @contextmanager
    def locked(self):
        with DirectoryGuard(self.case.parent):
            if not self.root.exists():
                _private_mkdir(self.root)
            with DirectoryGuard(self.root):
                lock = local_path(self.root / 'write.lock')
                try:
                    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                except FileExistsError:
                    raise ValueError('Briefing is busy or an interrupted write needs review; write.lock preserved.') from None
                try:
                    os.close(fd)
                    yield
                finally:
                    lock.unlink()

    def write(self, state):
        self.check_case()
        raw = json.dumps(state, ensure_ascii=True, indent=2).encode()
        if len(raw) > MAX_STORE:
            raise ValueError('Briefing storage bound exceeded; previous content preserved.')
        fd, name = tempfile.mkstemp(prefix='.save-', dir=self.root)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, local_path(self.path))
        finally:
            if os.path.exists(name):os.unlink(name)

    def save(self, value, expected):
        if content(value['answers'], value['narrative'], value.get('interviews'),value.get('canonical'))!=value:raise ValueError('Invalid briefing content fields.')
        # Optimistic revision check prevents overwriting changes made while editing.
        with self.locked():
            state = self.load() if self.path.exists() else None
            current = state['revisions'][-1] if state else None
            if (current['digest'] if current else None) != expected:
                raise ValueError('Briefing changed while editing; previous content preserved. Reload before saving.')
            if current and current['content'] == value:return state
            if state is None:state = {'format':1,'case':self.identity,'revisions':[],'analyses':[]}
            if len(state['revisions']) >= 100:raise ValueError('Briefing revision limit reached; history preserved.')
            state['revisions'].append({'revision':len(state['revisions'])+1,'modified':now(),'digest':digest(value),'content':value})
            self.write(state)
            return state

    def record_analysis(self, revision, packet):
        with self.locked():
            state = self.load()
            if len(state['analyses']) >= 100:raise ValueError('Analysis metadata limit reached; existing history preserved.')
            state['analyses'].append({'revision':revision['revision'],'digest':revision['digest'],
                                      'created':now(),'ai_status':packet['ai_status']})
            self.write(state)


def sources(revision):
    c = revision['content']
    if c.get('canonical'):
        return {k:v for k,v in c['canonical']['provenance']['inputs'].items() if k!='canonical:summary' and v.strip()}
    return {**{f"interview:{session['id']}:{i+1}":turn['answer']
               for session in c.get('interviews',[]) for i,turn in enumerate(session['turns'])
               if turn['answer_status']=='answered' and turn['answer'].lstrip('\ufeff').strip()},
            **{'field:'+key:value for key,value in c['answers'].items() if value.lstrip('\ufeff').strip()},
            **({'narrative':c['narrative']} if c['narrative'].lstrip('\ufeff').strip() else {})}

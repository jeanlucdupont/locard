"""Private bounded assessment history; never stored in the evidence database."""
import json
import re
from pathlib import Path
from .briefing_store import Store as BriefingStore, digest
from .investigation_ai.storage import DirectoryGuard, local_path

MAX_BYTES = 4 * 1024 * 1024
MAX_HISTORY = 50


class AssessmentStore(BriefingStore):
    def __init__(self, case):
        super().__init__(case)
        self.root = local_path(str(self.case) + '.assessments')
        self.path = self.root / 'unused.json'

    def identities(self):
        self.check_case()
        if not self.root.exists():return []
        with DirectoryGuard(self.root):
            ids = [p.stem for p in self.root.iterdir() if re.fullmatch(r'[a-f0-9]{32}\.json',p.name)]
            if len(ids)>MAX_HISTORY:raise ValueError('Assessment history bound exceeded')
            return ids

    def load(self, identity):
        if not re.fullmatch(r'[a-f0-9]{32}',identity):raise ValueError('Invalid assessment ID')
        self.check_case()
        with DirectoryGuard(self.root):
            path=local_path(self.root/(identity+'.json'))
            if not path.is_file() or path.stat().st_nlink!=1:raise ValueError('Assessment must be a private regular file')
            with path.open('rb') as stream:raw=stream.read(MAX_BYTES+1)
            if len(raw)>MAX_BYTES:raise ValueError('Assessment exceeds storage limit')
            from .investigation_ai.contracts import loads
            packet=loads(raw.decode('utf-8'),max_bytes=MAX_BYTES)
            if not isinstance(packet,dict) or set(packet)!={'format','digest','assessment'} or packet['format']!=1 or digest(packet['assessment'])!=packet['digest']:
                raise ValueError('Invalid assessment integrity envelope')
            result=packet['assessment']
            if result.get('id')!=identity or result.get('case')!=self.identity:raise ValueError('Assessment case identity mismatch')
            if result.get('kind')!='case_assessment':raise ValueError('Invalid assessment format')
            if result.get('authorization',{}).get('plan_digest')!=digest(result.get('plan')):
                raise ValueError('Assessment authorization/plan mismatch')
            return result

    def history(self):
        rows=[]
        for identity in self.identities():
            r=self.load(identity)
            rows.append(dict(id=r['id'],created=r['created'],status=r['status'],plan={'revision':r['plan']['revision']}))
        return sorted(rows,key=lambda r:(r['created'],r['id']))

    def save_assessment(self, result):
        if result['case']!=self.identity or not re.fullmatch(r'[a-f0-9]{32}',result['id']):raise ValueError('Invalid assessment identity')
        envelope={'format':1,'digest':digest(result),'assessment':result}
        if len(json.dumps(envelope,ensure_ascii=True,indent=2).encode())>MAX_BYTES:
            raise ValueError('Assessment storage limit reached; previous checkpoint preserved')
        with self.locked():
            ids=self.identities()
            if result['id'] not in ids and len(ids)>=MAX_HISTORY:raise ValueError('Assessment history full; no history deleted')
            self.path=self.root/(result['id']+'.json')
            if self.path.exists():self.load(result['id'])
            self.write(envelope)

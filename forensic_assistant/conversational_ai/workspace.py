"""Journal-derived, session-private SQLite memory. Never an evidence authority.

Only a newly created projection is opened. Historical reconstruction streams a
validated journal into a new private directory; it never restores execution grants.
"""
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from forensic_assistant.investigation_ai.storage import DirectoryGuard,local_path
from forensic_assistant.investigation_ai.transcript import digest,CONVERSATION_BYTES,CONVERSATION_EVENTS,validate_evidence_state

VERSION=1
ZERO='0'*64
def encoded(v):return json.dumps(v,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False)
def signature(v):return hashlib.sha256(encoded(v).encode()).hexdigest()


def events(path):
    """Bounded streaming verification, including manifest frontier. No case access."""
    path=local_path(path)
    with DirectoryGuard(path):
        def manifest_bytes():
            with local_path(path/'manifest.json').open('rb') as stream:return stream.read(65537)
        raw=manifest_bytes()
        if len(raw)>65536:raise ValueError('WORKSPACE_MANIFEST_LIMIT')
        manifest=json.loads(raw)
        if manifest.get('engine')!='conversational-v1' or manifest.get('format')!=1 or manifest.get('investigation_id')!=path.name:
            raise ValueError('WORKSPACE_JOURNAL_BINDING')
        chain=ZERO;count=size=0
        with local_path(path/'events.jsonl').open('rb') as stream:
            while True:
                line=stream.readline(600*1024+1)
                if not line:break
                size+=len(line)
                if len(line)>600*1024 or size>CONVERSATION_BYTES or count>=CONVERSATION_EVENTS or not line.endswith(b'\n'):
                    raise ValueError('WORKSPACE_JOURNAL_LIMIT')
                e=json.loads(line)
                if set(e)!={'sequence','kind','data','previous','hash'} or e['sequence']!=count or e['previous']!=chain:
                    raise ValueError('WORKSPACE_JOURNAL_CHAIN')
                if digest({k:v for k,v in e.items() if k!='hash'})!=e['hash']:raise ValueError('WORKSPACE_JOURNAL_HASH')
                if e['kind']=='authorization' and e['data']!=manifest.get('authorization'):raise ValueError('WORKSPACE_MANIFEST_AUTHORIZATION')
                chain=e['hash'];count+=1
                yield e
        if manifest.get('event_count')!=count or manifest.get('chain')!=chain or manifest_bytes()!=raw:
            raise ValueError('WORKSPACE_JOURNAL_FRONTIER')


def identities(value):
    rows=[*value.get('records',[]),*value.get('omitted_candidates',[])]
    if value.get('evidence_id'):rows.append(value)
    return {r['evidence_id'] for r in rows if isinstance(r,dict) and isinstance(r.get('evidence_id'),str)}


SCHEMA='''
CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE events(sequence INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, kind TEXT NOT NULL);
CREATE TABLE actions(id TEXT PRIMARY KEY, sequence INTEGER NOT NULL REFERENCES events(sequence), tool TEXT NOT NULL,
 signature TEXT NOT NULL, arguments TEXT NOT NULL, status TEXT NOT NULL, result_event INTEGER REFERENCES events(sequence),
 coverage TEXT, duration REAL, result_digest TEXT, call_id TEXT, computation TEXT);
CREATE INDEX action_signature ON actions(signature,sequence);
CREATE INDEX action_status ON actions(status,sequence);
CREATE INDEX action_result ON actions(result_digest,sequence);
CREATE INDEX action_tool ON actions(tool,sequence);
CREATE TABLE evidence(eid TEXT PRIMARY KEY,artifact TEXT,first_event INTEGER NOT NULL REFERENCES events(sequence),
 last_event INTEGER NOT NULL REFERENCES events(sequence),disclosure TEXT NOT NULL DEFAULT 'retrieved',scope TEXT NOT NULL,group_id TEXT);
CREATE INDEX evidence_disclosure ON evidence(disclosure,last_event);
CREATE INDEX evidence_recent ON evidence(last_event);
CREATE TABLE fields(eid TEXT NOT NULL REFERENCES evidence(eid),pointer TEXT NOT NULL,event INTEGER NOT NULL REFERENCES events(sequence),
 preview INTEGER NOT NULL,truncated INTEGER NOT NULL,redacted INTEGER NOT NULL,meaning TEXT,PRIMARY KEY(eid,pointer,event));
CREATE INDEX field_event ON fields(event);
CREATE TABLE action_evidence(action TEXT NOT NULL REFERENCES actions(id),eid TEXT NOT NULL REFERENCES evidence(eid),PRIMARY KEY(action,eid));
CREATE TABLE disclosures(event INTEGER NOT NULL REFERENCES events(sequence),eid TEXT NOT NULL REFERENCES evidence(eid),PRIMARY KEY(event,eid));
CREATE TABLE field_exposures(event INTEGER NOT NULL REFERENCES events(sequence),eid TEXT NOT NULL,pointer TEXT NOT NULL,origin INTEGER NOT NULL,
 FOREIGN KEY(eid,pointer,origin) REFERENCES fields(eid,pointer,event),PRIMARY KEY(event,eid,pointer,origin));
CREATE INDEX field_exposure_origin ON field_exposures(eid,pointer,origin);
CREATE TABLE verifications(id TEXT PRIMARY KEY,event INTEGER NOT NULL REFERENCES events(sequence),eid TEXT NOT NULL REFERENCES evidence(eid),pointer TEXT NOT NULL,meaning TEXT);
CREATE INDEX verified_eid ON verifications(eid,event);
CREATE TABLE notes(id TEXT PRIMARY KEY,event INTEGER NOT NULL REFERENCES events(sequence),kind TEXT NOT NULL,author TEXT NOT NULL,
 status TEXT NOT NULL,text TEXT NOT NULL,details TEXT NOT NULL,supersedes TEXT REFERENCES notes(id));
CREATE INDEX note_kind_status ON notes(kind,status,event);
CREATE INDEX note_supersedes ON notes(supersedes);
CREATE INDEX note_status ON notes(status,event);
CREATE TABLE populations(id TEXT PRIMARY KEY,event INTEGER NOT NULL REFERENCES events(sequence),metadata TEXT NOT NULL);
'''


class Workspace:
    def __init__(self,path,session_id):
        self.path=local_path(path);self.guard=DirectoryGuard(self.path.parent);self.db=None
        try:
            for suffix in ('','-journal','-wal','-shm'):
                p=local_path(str(self.path)+suffix)
                if p.exists():raise ValueError('WORKSPACE_ALREADY_EXISTS_RECONSTRUCT_REQUIRED')
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
            self.identity=(self.path.stat().st_dev,self.path.stat().st_ino)
            self.db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,timeout=.2)
            self.db.row_factory=sqlite3.Row
            self.db.execute('PRAGMA foreign_keys=ON');self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('PRAGMA journal_mode=DELETE');self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA temp_store=MEMORY');self.db.execute('PRAGMA cache_size=-4096')
            self.db.enable_load_extension(False)
            self.db.executescript(SCHEMA);self.db.execute('PRAGMA user_version=1')
            self.db.executemany('INSERT INTO meta VALUES (?,?)',[('session',session_id),('chain',ZERO),('next','0')]);self.db.commit()
            self.fts5_available=any('ENABLE_FTS5' in row[0] for row in self.db.execute('PRAGMA compile_options'))
        except BaseException:self.close();raise

    def guard_files(self):
        for suffix in ('','-journal','-wal','-shm'):
            p=local_path(str(self.path)+suffix)
            if p.exists() and (not p.is_file() or p.stat().st_nlink!=1):raise ValueError('WORKSPACE_FILE_REDIRECTION')
        if (self.path.stat().st_dev,self.path.stat().st_ino)!=self.identity:raise ValueError('WORKSPACE_IDENTITY_CHANGED')

    def meta(self,key):
        row=self.db.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone()
        return row[0] if row else None

    def bound(self,scope,view):
        self.guard_files()
        if self.meta('authorization')!=encoded(scope) or self.meta('read_view')!=encoded(view):raise ValueError('WORKSPACE_AUTHORITY_CHANGED')

    def apply(self,event):
        self.guard_files();seq=event['sequence']
        if digest({k:v for k,v in event.items() if k!='hash'})!=event['hash']:raise ValueError('WORKSPACE_EVENT_HASH')
        old=self.db.execute('SELECT hash FROM events WHERE sequence=?',(seq,)).fetchone()
        if old:
            if old[0]!=event['hash']:raise ValueError('WORKSPACE_EVENT_CONFLICT')
            return
        if seq!=int(self.meta('next')) or event['previous']!=self.meta('chain'):raise ValueError('WORKSPACE_EVENT_GAP')
        with self.db:
            self.db.execute('INSERT INTO events VALUES (?,?,?)',(seq,event['hash'],event['kind']))
            self._project(event)
            self.db.execute("UPDATE meta SET value=? WHERE key='chain'",(event['hash'],))
            self.db.execute("UPDATE meta SET value=? WHERE key='next'",(str(seq+1),))

    def _project(self,e):
        d=e['data'];seq=e['sequence'];kind=e['kind'];db=self.db
        if kind in ('authorization','read_view'):
            if kind=='read_view':validate_evidence_state(d)
            previous=self.meta(kind)
            if previous is not None and previous!=encoded(d):raise ValueError('WORKSPACE_BINDING_CONFLICT')
            db.execute('INSERT OR IGNORE INTO meta VALUES (?,?)',(kind,encoded(d)))
        elif kind=='artifact_availability':
            db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('artifact_availability',encoded(d)))
        elif kind=='operation_progress':
            if d.get('reason')=='known_unavailable_family':
                db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('unavailable_operations',str(int(self.meta('unavailable_operations') or '0')+1)))
            db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('progress:'+d['key'],encoded(d)))
            if d['tool'] in ('search_evidence','timeline','around','discover_security_signals','discover_execution_behaviors','activity_overview'):
                db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('progress-frontier:'+d['frontier_key'],encoded(d)))
                if d.get('artifact'):db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('progress-family:'+d['artifact'],encoded(d)))
            if d.get('aggregate_summary'):
                db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('latest_aggregate',encoded(d['aggregate_summary'])))
            compact={k:d[k] for k in ('operation','tool','state','reason','previous_operation','search_complete','continuation_available','artifact_signal_state')}
            db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('latest_progress',encoded(compact)))
            if d['tool'] in ('search_evidence','timeline','around','discover_security_signals','discover_execution_behaviors','activity_overview'):
                recent=json.loads(self.meta('recent_coverage') or '[]')
                recent=[r for r in recent if r['frontier_key']!=d['frontier_key']]
                recent.append(dict(compact,frontier_key=d['frontier_key']))
                db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('recent_coverage',encoded(recent[-2:])))
        elif kind=='completion_assessment':
            db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('completion_assessment',encoded(d)))
        elif kind=='tool_attempt':
            aid=d.get('operation_id','A'+str(seq))
            db.execute('INSERT INTO actions VALUES (?,?,?,?,?,?,NULL,NULL,NULL,NULL,?,NULL)',
                (aid,seq,d['name'],signature(dict(name=d['name'],arguments=d['arguments'])),encoded(d['arguments']),'pending',d.get('id')))
        elif kind in ('tool_result','tool_failure'):
            aid=d.get('operation_id')
            action=db.execute('SELECT * FROM actions WHERE id=?',(aid,)).fetchone() if aid else db.execute("SELECT * FROM actions WHERE status='pending' ORDER BY sequence DESC LIMIT 1").fetchone()
            if not action and kind=='tool_failure':
                args=d.get('attempted_arguments',{})
                db.execute('INSERT INTO actions VALUES (?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL)',('A'+str(seq),seq,d.get('tool','unknown'),signature(dict(name=d.get('tool','unknown'),arguments=args)),encoded(args),'pending'))
                action=db.execute('SELECT * FROM actions WHERE id=?',('A'+str(seq),)).fetchone()
            if not action:return
            if kind=='tool_failure':
                db.execute('UPDATE actions SET status=?,result_event=?,coverage=?,duration=? WHERE id=?',('cancelled' if d.get('code')=='ANALYST_CANCELLED' else 'failed',seq,encoded(d),d.get('duration_seconds'),action['id']));return
            value=d['result'];coverage={k:v for k,v in value.items() if k not in ('records','fields','shared','statistics','feature_definitions','items','value')}
            partial=value.get('truncated') or value.get('has_more') or value.get('next_offset') is not None or any(value.get('coverage',{}).get(k) is False for k in ('complete','analysis_complete','presentation_complete','counts_complete'))
            db.execute('UPDATE actions SET status=?,result_event=?,coverage=?,duration=?,result_digest=? WHERE id=?',
                ('partial' if partial else 'completed',seq,encoded(coverage),d.get('duration_seconds'),signature(value),action['id']))
            rows=[*value.get('records',[]),*value.get('omitted_candidates',[])]
            if value.get('evidence_id'):rows.append(value)
            for row in rows:
                eid=row.get('evidence_id')
                if not eid:continue
                db.execute('INSERT INTO evidence(eid,artifact,first_event,last_event,scope,group_id) VALUES (?,?,?,?,?,?) ON CONFLICT(eid) DO UPDATE SET last_event=excluded.last_event,artifact=coalesce(excluded.artifact,evidence.artifact)',
                    (eid,row.get('artifact'),seq,seq,encoded(value.get('scope',json.loads(self.meta('authorization') or '{}'))),row.get('group_id')))
                db.execute('INSERT OR IGNORE INTO action_evidence VALUES (?,?)',(action['id'],eid))
                for f in [*row.get('fields',[]),*row.get('original_fields',[]),*row.get('previews',[])]:
                    db.execute('INSERT OR IGNORE INTO fields VALUES (?,?,?,?,?,?,?)',(eid,f['field'],seq,int(f in row.get('previews',[])),int(f.get('truncated',False)),int(f.get('redacted',False)),f.get('timestamp_meaning')))
            if value.get('contract')=='execution-discovery-compact-v1':
                pid=d.get('population_id') or 'P'+str(seq)
                metadata={k:v for k,v in value.items() if k not in ('records','omitted_candidates')}
                db.execute('INSERT OR REPLACE INTO populations VALUES (?,?,?)',(pid,seq,encoded(metadata)))
        elif kind=='behavioral_computation':
            db.execute("UPDATE actions SET computation=? WHERE id=(SELECT id FROM actions WHERE status='pending' ORDER BY sequence DESC LIMIT 1)",(encoded(d),))
        elif kind=='operation_repeat':
            db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('latest_repeat',encoded(d)))
        elif kind=='provider_attempt':
            # Journaled dispatch means possible exposure, not provider acknowledgement.
            for m in d.get('messages',[]):
                if m.get('role')!='tool':continue
                try:value=json.loads(m.get('content',''))
                except (ValueError,TypeError):continue
                ids=identities(value)|set(value.get('workspace_evidence_ids',[]))
                for eid in ids:
                    if db.execute('SELECT 1 FROM evidence WHERE eid=?',(eid,)).fetchone():
                        db.execute('INSERT OR IGNORE INTO disclosures VALUES (?,?)',(seq,eid))
                        db.execute("UPDATE evidence SET disclosure='possibly_exposed' WHERE eid=?",(eid,))
                result_hash=signature(value)
                for row in db.execute('SELECT eid,pointer,event FROM fields WHERE event=(SELECT result_event FROM actions WHERE result_digest=? ORDER BY sequence DESC LIMIT 1)',(result_hash,)).fetchall():
                    db.execute('INSERT OR IGNORE INTO field_exposures VALUES (?,?,?,?)',(seq,row['eid'],row['pointer'],row['event']))
        elif kind=='verified_observation':
            if db.execute('SELECT 1 FROM evidence WHERE eid=?',(d['evidence_id'],)).fetchone():
                db.execute('INSERT INTO verifications VALUES (?,?,?,?,?)',('V'+str(seq),seq,d['evidence_id'],d['field'],d.get('timestamp_meaning')))
        elif kind in ('note','analyst_message','provider_response'):
            if kind=='provider_response' and not d.get('text'):return
            if kind=='note' and 'note_id' in d:self.validate_note(d)
            author='analyst' if kind=='analyst_message' else 'model'
            text=d.get('text',d.get('content',''))
            nid=d.get('note_id','N'+str(seq))
            db.execute('INSERT INTO notes VALUES (?,?,?,?,?,?,?,?)',(nid,seq,d.get('kind','instruction' if author=='analyst' else 'interpretation'),author,d.get('status','active'),text,encoded(d) if kind=='note' else '{}',d.get('supersedes')))
            if kind=='note' and 'note_id' not in d:
                db.execute("UPDATE actions SET status='completed',result_event=? WHERE id=(SELECT id FROM actions WHERE tool='note' AND status='pending' ORDER BY sequence DESC LIMIT 1)",(seq,))

    def previous_action(self,name,args):
        row=self.db.execute('SELECT id,status FROM actions WHERE signature=? ORDER BY sequence DESC LIMIT 1',(signature(dict(name=name,arguments=args)),)).fetchone()
        return dict(row) if row else None

    def validate_note(self,d):
        for key in ('evidence_ids','supporting','contradictory'):
            for eid in d.get(key,[]):
                if not self.db.execute("SELECT 1 FROM evidence WHERE eid=? AND disclosure='possibly_exposed'",(eid,)).fetchone():raise ValueError('UNEXPOSED_WORKSPACE_REFERENCE')
        for aid in d.get('operation_ids',[]):
            if not self.db.execute('SELECT 1 FROM actions WHERE id=?',(aid,)).fetchone():raise ValueError('UNKNOWN_OPERATION_REFERENCE')
        if d.get('supersedes') and not self.db.execute("SELECT 1 FROM notes WHERE id=? AND author='model'",(d['supersedes'],)).fetchone():raise ValueError('UNKNOWN_NOTE_REVISION')

    def query(self,kind='state',*,evidence_id=None,query=None,status=None,offset=0,limit=10,byte_limit=12000):
        self.guard_files()
        if kind=='state':return dict(contract='investigative-memory-v1',counts={t:self.db.execute('SELECT count(*) FROM '+t).fetchone()[0] for t in ('evidence','fields','actions','verifications','notes','populations')},
            next_event=int(self.meta('next')),fts5_available=self.fts5_available,limitation='Journal-derived history, not evidence authority or permission to resume. Query pages; show_evidence rehydrates originals.')
        tables={'evidence':('evidence','last_event'),'fields':('fields','event'),'actions':('actions','sequence'),'notes':('notes','event'),'verified':('verifications','event'),'populations':('populations','event')}
        if kind not in tables:raise ValueError('UNKNOWN_MEMORY_KIND')
        table,order=tables[kind];where=[];args=[]
        if evidence_id:
            if not self.db.execute('SELECT 1 FROM evidence WHERE eid=?',(evidence_id,)).fetchone():raise ValueError('UNKNOWN_WORKSPACE_EVIDENCE')
            if kind not in ('evidence','fields','verified'):raise ValueError('MEMORY_FILTER_MISMATCH')
            where.append('eid=?');args.append(evidence_id)
        if status:
            if kind not in ('notes','actions'):raise ValueError('MEMORY_FILTER_MISMATCH')
            where.append('status=?');args.append(status)
            if kind=='notes':where.append('NOT EXISTS (SELECT 1 FROM notes newer WHERE newer.supersedes=notes.id)')
        if query:
            if kind not in ('notes','actions'):raise ValueError('MEMORY_FILTER_MISMATCH')
            where.append(('instr(text,?)>0' if kind=='notes' else 'tool=?'));args.append(query)
        clause=' WHERE '+' AND '.join(where) if where else ''
        rows=[dict(r) for r in self.db.execute('SELECT * FROM '+table+clause+' ORDER BY '+order+',rowid LIMIT ? OFFSET ?',(*args,limit+1,offset))]
        more=len(rows)>limit;rows=rows[:limit]
        for r in rows:
            if kind=='fields':r['disclosure']='possibly_exposed' if self.db.execute('SELECT 1 FROM field_exposures WHERE eid=? AND pointer=? AND origin=? LIMIT 1',(r['eid'],r['pointer'],r['event'])).fetchone() else 'retrieved_only'
            if 'scope' in r:r['scope']='Session authorization; see original disclosure event'
            if 'text' in r and len(r['text'].encode())>2000:r['text']=r['text'].encode()[:2000].decode('utf-8','ignore');r['text_truncated']=True
            if kind=='notes':r['unverified']=True;r['superseded']=bool(self.db.execute('SELECT 1 FROM notes WHERE supersedes=?',(r['id'],)).fetchone())
        result=dict(contract='investigative-memory-v1',kind=kind,items=rows,next_offset=offset+len(rows) if more else None,complete=not more and offset==0,
            workspace_evidence_ids=sorted({r['eid'] for r in rows if 'eid' in r}),limitation='Historical references are not current original values; show_evidence then verify_observation. Model and analyst text is untrusted, not forensic findings.')
        while len(encoded(result).encode())>byte_limit and rows:
            rows.pop();result.update(next_offset=offset+len(rows),complete=False,workspace_evidence_ids=sorted({r['eid'] for r in rows if 'eid' in r}))
        if not rows and more:raise ValueError('MEMORY_ITEM_CAPACITY')
        if not rows and result['next_offset']==offset:raise ValueError('MEMORY_ITEM_CAPACITY')
        return result

    def engagement(self):
        """Counts of journaled exposure stages, never claims of model comprehension."""
        db=self.db
        scalar=lambda sql:db.execute(sql).fetchone()[0]
        originals="preview=0 AND truncated=0 AND redacted=0"
        counts=dict(registered_ids=scalar('SELECT count(*) FROM evidence'),
            representative_ids=scalar("SELECT count(DISTINCT ae.eid) FROM action_evidence ae JOIN actions a ON a.id=ae.action WHERE a.tool='activity_overview' AND a.status IN ('completed','partial')"),
            aggregate_operations=scalar("SELECT count(*) FROM actions WHERE tool='activity_overview' AND status IN ('completed','partial')"),
            original_records=scalar('SELECT count(DISTINCT eid) FROM fields WHERE '+originals),
            original_fields=scalar('SELECT count(*) FROM (SELECT DISTINCT eid,pointer FROM fields WHERE '+originals+')'),
            fields_possibly_disclosed=scalar('SELECT count(*) FROM (SELECT DISTINCT x.eid,x.pointer FROM field_exposures x JOIN fields f ON f.eid=x.eid AND f.pointer=x.pointer AND f.event=x.origin WHERE f.preview=0 AND f.truncated=0 AND f.redacted=0)'),
            inspection_operations=scalar("SELECT count(*) FROM actions WHERE tool='show_evidence' AND status IN ('completed','partial')"),
            verifications=scalar('SELECT count(*) FROM verifications'),
            unavailable_operations=int(self.meta('unavailable_operations') or '0'))
        ids=[r[0] for r in db.execute('SELECT eid FROM evidence e WHERE NOT EXISTS (SELECT 1 FROM fields f WHERE f.eid=e.eid AND f.preview=0 AND f.truncated=0 AND f.redacted=0) ORDER BY eid LIMIT 3')]
        return dict(counts=counts,latest_aggregate=json.loads(self.meta('latest_aggregate') or 'null'),unexamined_ids=ids,unexamined_ids_limit=3,
            next_tools=['show_evidence'] if ids else [],
            limitation='IDs and aggregates are not examination. Original fields are retrieved/disclosed, not proof of comprehension or causality.')

    def context(self):
        # Indexed bounded selections, not a full workspace load. All pages remain queryable.
        result=dict(state=self.query(),previous_repeated_action=json.loads(self.meta('latest_repeat') or 'null'),operational_progress=json.loads(self.meta('latest_progress') or 'null'),artifact_availability=json.loads(self.meta('artifact_availability') or '{}'),engagement=self.engagement(),recent_query_coverage=[{k:v for k,v in r.items() if k not in ('frontier_key','previous_operation','artifact_signal_state')} for r in json.loads(self.meta('recent_coverage') or '[]')])
        for key in ('evidence','fields','verifications'):result['state']['counts'].pop(key,None)
        for label,kind,kwargs in [('active_notes','notes',{'status':'active','limit':2}),('unresolved_questions','notes',{'status':'unresolved','limit':2}),('verified','verified',{'limit':3}),('pending_searches','actions',{'status':'partial','limit':2})]:
            try:result[label]=self.query(kind,**kwargs)
            except ValueError as exc:
                if str(exc)!='MEMORY_ITEM_CAPACITY':raise
                result[label]={'omitted':'Item exceeds automatic projection capacity; query memory explicitly.'}
        return result

    def reconcile(self,journal_path):
        # Validate the complete authoritative frontier before mutating a projection.
        if Path(journal_path).name!=self.meta('session'):raise ValueError('WORKSPACE_SESSION_MISMATCH')
        for _ in events(journal_path):pass
        count=0;chain=ZERO
        for e in events(journal_path):self.apply(e);count+=1;chain=e['hash']
        if int(self.meta('next'))!=count or self.meta('chain')!=chain:raise ValueError('WORKSPACE_AHEAD_OF_JOURNAL')

    def fingerprint(self):
        # Explicit historical validation only, not a per-request context operation.
        h=hashlib.sha256()
        for table in ('meta','events','actions','evidence','fields','action_evidence','disclosures','field_exposures','verifications','notes','populations'):
            columns=[r[1] for r in self.db.execute('PRAGMA table_info('+table+')')]
            h.update(table.encode())
            for row in self.db.execute('SELECT * FROM '+table+' ORDER BY '+','.join(columns)):
                h.update((encoded(list(row))+'\n').encode())
        return h.hexdigest()

    def close(self):
        if self.db:self.db.close();self.db=None
        if self.guard:self.guard.close()


def reconstruct(journal_path,output_directory):
    """Historical projection only. No case open, provider, or resumed execution."""
    from forensic_assistant.investigation_ai.snapshot import _private_mkdir
    path=local_path(journal_path)
    for _ in events(path):pass
    out=local_path(output_directory);_private_mkdir(out)
    workspace=Workspace(out/'workspace.db',path.name)
    try:
        workspace.reconcile(path)
        return dict(workspace.query(),projection_sha256=workspace.fingerprint())
    finally:workspace.close()

"""Indexed, bounded object candidates for explicit briefing discovery.

Basename equality is candidate retrieval, never file identity or execution proof.
"""
import base64
import hashlib
import json
import os
import sqlite3
import threading
import time
from .queries import required_time
from dataclasses import dataclass


@dataclass
class ObjectResult:
    records: list
    total: int
    limit: int
    truncated: bool
    limits: list
    object_search: dict

    def as_dict(self):
        return dict(records=self.records,total=self.total,limit=self.limit,offset=0,truncated=self.truncated,
                    limits=self.limits,object_search=self.object_search,
                    total_is_lower_bound=self.truncated or self.object_search['continued'])

CANDIDATES = 1000
SECONDS = 5


def scope(db, values):
    filename = next(row[2] for row in db.execute('PRAGMA database_list') if row[1]=='main')
    stat = os.stat(filename) if filename else None
    identity = [stat.st_dev, stat.st_ino] if stat else ['memory', id(db)]
    return hashlib.sha256(json.dumps([identity,values],sort_keys=True).encode()).hexdigest()


def search(query, *, object_basename, artifact, start, end, limit=10, object_after=None):
    from .evidence import get_evidence
    from forensic_assistant.correlation.models import time_ns
    if artifact not in ('mft','prefetch','registry','browser') or not 1<=limit<=10:
        raise ValueError('Invalid object discovery scope')
    if not isinstance(object_basename,str) or not 1<=len(object_basename.encode())<=256 or any(c in object_basename for c in '/\\\x00'):
        raise ValueError('Invalid object basename')
    start,end=required_time(start),required_time(end)
    if not 0<=time_ns(end)-time_ns(start)<=86400*10**9:
        raise ValueError('Object discovery requires at most 24 hours')
    db=query.db
    identity=scope(db,[object_basename,artifact,start,end])
    after=''
    if object_after is not None:
        try:
            if not isinstance(object_after,str) or len(object_after)>2048:raise ValueError()
            decoded=json.loads(base64.b64decode(object_after,altchars=b'-_',validate=True))
            if not isinstance(decoded,list) or len(decoded)!=2 or decoded[0]!=identity or not isinstance(decoded[1],str) or len(decoded[1])>512:raise ValueError()
            after=decoded[1]
        except (ValueError,TypeError,UnicodeError):raise ValueError('Invalid object continuation for this scope') from None
    # No total-count query and no time-window-wide candidate materialization.
    # The existing (basename,evidence_id) index supplies ordered unique IDs.
    sql=('SELECT DISTINCT evidence_id FROM evidence_objects WHERE basename=? AND evidence_id>? '
         'ORDER BY evidence_id LIMIT ?')
    records=[];examined=0;last=after;complete=False;notes=[]
    deadline=time.monotonic()+SECONDS
    timer=threading.Timer(SECONDS,db.interrupt);timer.daemon=True;timer.start()
    try:
        candidates=db.execute(sql,(object_basename.lower(),after,CANDIDATES+1)).fetchall()
        for row in candidates[:CANDIDATES]:
            if time.monotonic()>=deadline:break
            eid=row[0]
            family=db.execute('SELECT source_type FROM evidence_records WHERE evidence_id=?',(eid,)).fetchone()
            if family and family[0]==artifact:
                # Resolve only this candidate through the established hydration layer,
                # including inherited Registry and UserAssist timestamp semantics.
                record=get_evidence(db,eid)
                if any(t.get('timestamp_utc') and start<=required_time(t['timestamp_utc'])<=end for t in record['timestamps']):
                    objects=db.execute('SELECT slot,role,original FROM evidence_objects WHERE evidence_id=? AND basename=? ORDER BY slot LIMIT 9',
                                       (eid,object_basename.lower())).fetchall()
                    record['discovery_objects']=[dict(o) for o in objects[:8]]
                    record['discovery_objects_truncated']=len(objects)>8
                    records.append(record)
            examined+=1;last=eid
            if len(records)>=limit:break
        complete=examined==len(candidates) and len(candidates)<=CANDIDATES
    except sqlite3.OperationalError as exc:
        if 'interrupt' not in str(exc).lower():raise
        notes.append('Object discovery execution-time bound reached; coverage incomplete')
    finally:
        timer.cancel();timer.join()
    if not complete:notes.append('Bounded object candidates only; no overall absence conclusion is supported')
    cursor=base64.urlsafe_b64encode(json.dumps([identity,last]).encode()).decode() if not complete and last!=after else None
    return ObjectResult(records=records,total=len(records),limit=limit,truncated=not complete,limits=notes,
                object_search=dict(complete=complete,examined=examined,candidate_limit=CANDIDATES,
                    continued=bool(after),next_cursor=cursor,ordering='evidence ID',basis='basename candidate; not file identity'))

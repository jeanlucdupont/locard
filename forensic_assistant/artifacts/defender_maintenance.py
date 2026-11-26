"""Explicit, atomic Defender-derived maintenance from hash-verified retained bytes."""
import base64
from collections import Counter
import hashlib
import json
import uuid
from pathlib import Path
from forensic_assistant.investigation_ai.snapshot import SnapshotDirectory
from forensic_assistant.database import sources
from forensic_assistant.database.artifacts import add_timestamp,dump
from forensic_assistant.database.db import now
from .defender import parse,validate_policy,VERSION,MAX_CHUNK,STAMP


def selected_files(db,source):
    sources.current(db,source)
    files=[r[0] for r in db.execute("SELECT DISTINCT e.file_sha256 FROM evidence_records e JOIN ("+sources.MEMBERSHIP+") m USING(file_sha256) WHERE e.source_type='defender' AND m.source_id=? ORDER BY 1",(source,))]
    for sha in files:
        members={r[0] for r in db.execute('SELECT source_id FROM ('+sources.MEMBERSHIP+') WHERE file_sha256=?',(sha,))}
        if members!={source}:raise ValueError('Shared Defender file: source-specific normalization would affect another source; repair refused')
    return files


def population(db,source,limit=5):
    """Bounded representatives; counts cover all selected retained records."""
    if not 0<=limit<=20:raise ValueError('Example limit must be 0..20')
    files=selected_files(db,source);categories=Counter();statuses=Counter();category_status=Counter();times=Counter();basis=Counter();unknown=Counter();examples={};bm=[];total=usable=0
    for sha in files:
        for row in db.execute("SELECT evidence_id,original_json FROM evidence_records WHERE source_type='defender' AND file_sha256=? ORDER BY evidence_id",(sha,)):
            d=json.loads(row['original_json']);total+=1;categories[d['category']]+=1;statuses[d['parsing_status']]+=1;category_status[(d['category'],d['parsing_status'])]+=1
            stamps=list(db.execute('SELECT * FROM evidence_timestamps WHERE evidence_id=?',(row['evidence_id'],)))
            usable+=any(t['timestamp_utc'] is not None for t in stamps)
            for t in stamps:times[(t['meaning'],t['normalization_status'])]+=1
            for t in d.get('timestamp_interpretations',[]):basis[t['interpretation_basis']]+=1
            if d['category']=='behavior_telemetry' and len(bm)<limit:
                bm.append(dict(evidence_id=row['evidence_id'],text=d['text'][:4096],truncated=len(d['text'])>4096,timestamps=d.get('timestamp_interpretations',[])))
            if d['category']=='unknown':
                text=d['text'].lstrip('\ufeff');m=STAMP.match(text);body=text[m.end():] if m else text
                prefix=body.strip()[:64];unknown[prefix]+=1
                # Keep only counts until the representative prefixes are selected.
    for prefix,count in unknown.most_common(limit):
        examples[prefix]=dict(count=count,representative_prefix=prefix,truncated=True)
    if examples:
        for sha in files:
            for row in db.execute("SELECT evidence_id,original_json FROM evidence_records WHERE source_type='defender' AND artifact_type='unknown' AND file_sha256=? ORDER BY evidence_id",(sha,)):
                d=json.loads(row['original_json']);text=d['text'].lstrip('\ufeff');m=STAMP.match(text);prefix=(text[m.end():] if m else text).strip()[:64]
                if prefix in examples and 'evidence_id' not in examples[prefix]:
                    examples[prefix].update(evidence_id=row['evidence_id'],text=d['text'][:4096],truncated=len(d['text'])>4096)
    return dict(records=total,with_normalized_time=usable,without_normalized_time=total-usable,categories=dict(categories),parsing_status=dict(statuses),
                category_status=[dict(category=k[0],status=k[1],count=v) for k,v in sorted(category_status.items())],
                timestamps=[dict(meaning=k[0],status=k[1],count=v) for k,v in sorted(times.items())],interpretation_basis=dict(basis),
                unknown_prefix_groups=examples,unknown_group_count=len(unknown),unknown_grouping='Exact first 64 characters after leading timestamp; not semantic equivalence',bm_examples=bm)


def repair(db,source,*,policy='format-utc',apply=False,progress=lambda count:None,operation_id=None):
    validate_policy(policy)
    operation_id=operation_id or uuid.uuid4().hex
    if db.in_transaction:raise ValueError('Maintenance requires its own transaction')
    if apply:
        from forensic_assistant import activity
        session=activity.CURRENT.get()
        case_path=Path(db.execute('PRAGMA database_list').fetchone()[2]).absolute()
        if session is None or session.case!=case_path:raise ValueError('Repair requires a matching mandatory audit session')
    count=changed=0;before=Counter();after=Counter();digest=hashlib.sha256()
    db.execute('BEGIN IMMEDIATE' if apply else 'BEGIN')
    try:
        files=selected_files(db,source)
        for sha in files:
            info=db.execute('SELECT size_bytes FROM evidence_files WHERE sha256=?',(sha,)).fetchone()
            if info is None:raise ValueError('Missing file provenance')
            with SnapshotDirectory() as directory:
                temp=directory.path/'snapshot.db'  # Private retained-byte stream, not a SQLite database
                offset=0;filehash=hashlib.sha256();oldcount=0;original_path=None
                with temp.open('xb') as out:
                    for row in db.execute("SELECT * FROM evidence_records WHERE source_type='defender' AND file_sha256=? ORDER BY CAST(json_extract(locator_json,'$.offset') AS INTEGER)",(sha,)):
                        loc=json.loads(row['locator_json']);d=json.loads(row['original_json'])
                        if len(d['raw_base64'])>MAX_CHUNK*2:raise ValueError('Oversized retained record')
                        raw=base64.b64decode(d['raw_base64'],validate=True)
                        if row['evidence_id']!=f'DEFENDER:{sha}:Offset:{offset}' or loc['offset']!=offset or loc['end_offset']!=offset+len(raw) or loc['ordinal']!=oldcount:
                            raise ValueError('Retained record identity/boundary mismatch')
                        if raw.decode(d['encoding'],errors='backslashreplace')!=d['text']:raise ValueError('Original bytes/text mismatch')
                        if row['parser_name']!='locard.defender' or row['parser_version'] not in ('1',VERSION):raise ValueError('Unexpected or unsupported parser provenance')
                        if not db.execute('SELECT 1 FROM source_locations WHERE file_sha256=? AND source_file=?',(sha,row['source_file'])).fetchone():raise ValueError('Missing original source location')
                        original_path=original_path or row['source_file']
                        if original_path!=row['source_file']:raise ValueError('Inconsistent retained source locations')
                        out.write(raw);filehash.update(raw);offset+=len(raw);oldcount+=1
                        if oldcount%500==0:progress(count)
                if offset!=info[0] or filehash.hexdigest()!=sha:raise ValueError('Retained bytes do not reconstruct the original file hash; no changes committed')
                seen=0
                for pack in parse(temp,sha,defender_time_policy=policy,_source_path=original_path):
                    eid=pack['record']['evidence_id'];row=db.execute('SELECT * FROM evidence_records WHERE evidence_id=?',(eid,)).fetchone()
                    if row is None or json.loads(row['locator_json'])!=json.loads(pack['record']['locator_json']):raise ValueError('Reparse changed record boundaries; repair refused')
                    old=json.loads(row['original_json']);new=pack['detail'];stamps=pack['timestamps']
                    for key in ('text','raw_base64','encoding','category','fields','group_key','group_id'):
                        if new[key]!=old[key]:raise ValueError('Repair would alter original content or non-timestamp interpretation: '+key)
                    oldstamps=[dict(t) for t in db.execute('SELECT * FROM evidence_timestamps WHERE evidence_id=? ORDER BY slot',(eid,))]
                    for t in oldstamps:t.pop('evidence_id')
                    before[old['parsing_status']]+=1;before['with_time']+=any(t['timestamp_utc'] for t in oldstamps)
                    after[new['parsing_status']]+=1;after['with_time']+=any(t['timestamp_utc'] for t in stamps)
                    clean={k:v for k,v in old.items() if k!='normalization_history'}
                    keys=('slot','timestamp_utc','original_value','encoding','source','meaning','precision_ns','normalization_status')
                    projected=sorted(({k:t.get(k) for k in keys} for t in stamps),key=lambda t:t['slot'])
                    different=clean!=new or projected!=oldstamps
                    if different:
                        changed+=1
                        if apply:
                            history=list(old.get('normalization_history',[]))
                            history.append(dict(operation_id=operation_id,new_policy=policy,recorded_utc=now(),parser_version=row['parser_version'],time_policy=old.get('time_policy','6.179'),timestamps=oldstamps,
                                                timestamp_interpretations=old.get('timestamp_interpretations',[]),parsing_status=old['parsing_status'],limitations=old['limitations'],warnings_json=row['warnings_json']))
                            new['normalization_history']=history
                            db.execute('DELETE FROM evidence_timestamps WHERE evidence_id=?',(eid,))
                            for stamp in stamps:add_timestamp(db,eid,stamp)
                            db.execute('UPDATE evidence_records SET original_json=?,warnings_json=?,parser_version=? WHERE evidence_id=?',
                                       (dump(new),pack['record']['warnings_json'],VERSION,eid))
                    digest.update(dump([eid,oldstamps,stamps]).encode());count+=1;seen+=1
                    if count%100==0:progress(count)
                if seen!=oldcount:raise ValueError('Reparse record count mismatch')
        result=dict(contract='defender-normalization-repair-v1',operation_id=operation_id,source_id=source,policy=policy,parser_version=VERSION,files=len(files),records=count,changed=changed,
                    before=dict(before),after=dict(after),comparison_sha256=digest.hexdigest(),applied=apply)
        progress(count)
        if apply:db.commit()
        else:db.rollback()
        return result
    except BaseException:
        db.rollback();raise


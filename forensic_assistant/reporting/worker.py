"""Private report collector. Not a model tool and never accepts SQL or code."""
from pathlib import Path
import sys
import time
import os
if __package__ in (None,''):
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]))

from forensic_assistant.investigation_ai.case import open_readonly, read_transaction
from forensic_assistant.investigation_ai.tools import compact, initial, execute, envelope
from forensic_assistant.retrieval.evidence import get_evidence
from forensic_assistant.semantic.documents import fingerprint
from forensic_assistant.reporting.model import canonical, loads

def collect(db, ids, locations=False):
    if not isinstance(ids,list) or not 1<=len(ids)<=20 or any(type(eid) is not str or len(eid)>256 for eid in ids):
        raise ValueError('Invalid evidence collection batch')
    records=[];inventory={}
    for eid in ids:
        raw=get_evidence(db,eid)
        timestamps=raw['timestamps']
        if len(timestamps)>128: raise ValueError('Timestamp count exceeds per-record bound')
        source=raw['source'];sha=source['sha256']
        contexts=raw['context']
        if len(contexts['assertions'])>100: raise ValueError('Context count exceeds bound')
        contexts={**contexts,'assertions':[{k:v for k,v in row.items() if k not in ('source_file','context_id')} for row in contexts['assertions']]}
        variants=[compact(raw)]
        if raw['source_type']=='evtx':
            from forensic_assistant.correlation.models import get_event
            variants.append(compact(get_event(db,eid)))
        records.append(dict(id=eid,fields=variants[0],historical_variants=variants,timestamps=timestamps,
                            source={k:v for k,v in source.items() if k!='source_file'},
                            context=contexts,warnings=raw['warnings'],
                            supporting_evidence_ids=raw.get('supporting_evidence_ids',[])))
        if sha not in inventory:
            item=dict(db.execute('SELECT * FROM evidence_files WHERE sha256=?',(sha,)).fetchone())
            item['source_types']=[r[0] for r in db.execute('SELECT DISTINCT source_type FROM evidence_records WHERE file_sha256=? ORDER BY source_type',(sha,))]
            item['evidence_count']=db.execute('SELECT count(*) FROM evidence_records WHERE file_sha256=?',(sha,)).fetchone()[0]
            item['parsers']=[dict(r) for r in db.execute('SELECT DISTINCT parser_name,parser_version,extractor_version FROM evidence_records WHERE file_sha256=? ORDER BY parser_name,parser_version,extractor_version LIMIT 101',(sha,))]
            item['ingestion_runs']=[dict(r) for r in db.execute('SELECT id,status,started_utc,finished_utc,inserted_count,duplicate_count,error_count FROM ingestion_runs WHERE file_sha256=? ORDER BY id LIMIT 101',(sha,))]
            if len(item['parsers'])>100 or len(item['ingestion_runs'])>100: raise ValueError('Inventory metadata bound exceeded')
            item['source_locations_included']=locations
            if locations:
                item['source_locations']=[r[0] for r in db.execute('SELECT source_file FROM source_locations WHERE file_sha256=? ORDER BY source_file LIMIT 101',(sha,))]
                if len(item['source_locations'])>100: raise ValueError('Source location bound exceeded')
            inventory[sha]=item
    return dict(records=records,inventory=inventory)

def verify_objects(db, request):
    # Recompute engine objects, including deterministic expansion of historical
    # semantic candidates. No embedding model or index is imported or opened.
    from forensic_assistant.detections.engine import available_rules
    from forensic_assistant.correlation.investigation import investigate
    config={'semantic_enabled':False,'rule_ids':[r.rule_id for r in available_rules()],
            'known_ids':request.get('known_ids',[]),'date_hint':request.get('date_hint')}
    op=request['operation']
    if op=='initial_retrieval': result=initial(db,request['question'],config)
    elif op=='semantic_expansion':
        result=envelope(db,'investigate_evidence',investigate(db,request['evidence_id'],max_candidates=50))
    else: result=execute(db,op,request['arguments'],config)
    return {key:result[key] for key in ('relationships','detections')}

def serve():
    from forensic_assistant.artifacts.worker import limit_memory
    memory_guard=limit_memory()
    config=None
    while line:=sys.stdin.buffer.readline(512*1024+1):
        if len(line)>512*1024: raise ValueError('Request bound exceeded')
        try:
            request=loads(line)
            if config is None:
                config=request['config'];response={'ready':True,'worker_pid':os.getpid()}
            else:
                with_db=open_readonly(config['case_path'],time.monotonic()+request['seconds'])
                try:
                    with read_transaction(with_db):
                        observed=fingerprint(with_db)
                        if request.get('expected_fingerprint') not in (None,observed): raise ValueError('EVIDENCE_STATE_CHANGED')
                        op=request['operation'];args=request['arguments']
                        if op=='check': result={'checked':True}
                        elif op=='collect': result=collect(with_db,args['ids'],args.get('locations',False))
                        elif op=='objects': result=verify_objects(with_db,args)
                        else: raise ValueError('Unknown report operation')
                        response=dict(result=result,fingerprint=observed,schema=3,database_changes=with_db.total_changes)
                finally: with_db.close()
        except Exception as exc:
            response={'error':str(exc)[:500],'error_type':type(exc).__name__}
        raw=canonical(response)
        if len(raw)>512*1024: raw=canonical({'error':'Report worker output bound exceeded'})
        sys.stdout.buffer.write(raw+b'\n');sys.stdout.buffer.flush()

if __name__=='__main__': serve()

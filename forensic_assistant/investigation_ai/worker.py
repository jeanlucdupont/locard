"""Private trusted process entry point. Never accepts raw model output."""
import contextlib
import json
from pathlib import Path
import sys
import time
import os

if __package__ in (None,''):
    # Launched with -I: only this installed source root is added, never case CWD.
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]))

from forensic_assistant.investigation_ai.case import open_readonly,read_transaction
from forensic_assistant.semantic.documents import fingerprint
from forensic_assistant.investigation_ai import tools

MAX_MESSAGE=512*1024

def serve():
    from forensic_assistant.artifacts.worker import limit_memory
    memory_guard=limit_memory()
    config=None;model=None;index_identity=None
    while line := sys.stdin.buffer.readline(MAX_MESSAGE + 1):
        if len(line)>MAX_MESSAGE:raise ValueError('Worker request limit exceeded')
        started=time.monotonic();response={}
        try:
            request=json.loads(line)
            if config is None:
                config=request['config']
                response={'ready':True,'worker_pid':os.getpid()}
            else:
                op=request['operation']
                # A pinned generation cannot change underneath the investigation.
                if config.get('semantic_enabled'):
                    from forensic_assistant.semantic.index import _generation
                    from forensic_assistant.semantic.model import sha
                    try:
                        generation=_generation(config['index_root'])
                        current={'generation':generation.name,'manifest_sha256':sha(generation/'manifest.json')}
                        if index_identity is not None and current!=index_identity:raise ValueError('SEMANTIC_STATE_CHANGED')
                        index_identity=current
                    except (OSError,ValueError):
                        if index_identity is not None:raise
                        config['semantic_enabled']=False
                needs_model=op=='semantic_search'
                if op=='initial' and config.get('semantic_enabled'):
                    from forensic_assistant.semantic.hybrid import precise
                    needs_model=not precise(request['question'])
                if needs_model and model is None:
                    try:
                        with contextlib.redirect_stdout(sys.stderr):
                            from forensic_assistant.semantic.model import LocalModel
                            model=LocalModel(config['model_path'])
                    except (ImportError, OSError, ValueError):
                        if op != 'initial': raise
                        config['semantic_enabled'] = False
                db=open_readonly(config['case_path'],started+request['seconds'])
                try:
                    with read_transaction(db):
                        observed=fingerprint(db)
                        if request.get('expected_fingerprint') not in (None,observed):raise ValueError('EVIDENCE_STATE_CHANGED')
                        with contextlib.redirect_stdout(sys.stderr):
                            if op=='initial':result=tools.initial(db,request['question'],config,model)
                            elif op=='check':result={'checked':True}
                            else:result=tools.execute(db,op,request['arguments'],{**config,'known_ids':request['known_ids']},model)
                        response={'result':result,'fingerprint':observed,'schema':3,
                          'semantic_identity':index_identity,'model_identity':model.identity if model else None,
                          'semantic_available':bool(model and config.get('semantic_enabled') and (op!='initial' or result.get('semantic_used'))),
                          'elapsed_seconds':time.monotonic()-started,'database_changes':db.total_changes}
                finally:db.close()
        except Exception as exc:
            response={'error':str(exc)[:1000],'error_type':type(exc).__name__,'elapsed_seconds':time.monotonic()-started}
        raw=json.dumps(response,ensure_ascii=True,separators=(',',':')).encode()
        if len(raw)>MAX_MESSAGE:raw=b'{"error":"Worker result exceeded byte budget","error_type":"ResourceLimit"}'
        sys.stdout.buffer.write(raw+b'\n');sys.stdout.buffer.flush()

if __name__=='__main__':serve()

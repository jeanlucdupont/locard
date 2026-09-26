"""Explicit format-1 / v4-1 adapter. Hashes never substitute for grounding."""
from pathlib import Path
import re
import stat
from forensic_assistant.investigation_ai.state import State, Budget
from forensic_assistant.investigation_ai.contracts import arguments, validate_output
from forensic_assistant.investigation_ai.transcript import digest as event_digest
from .model import loads

def safe_path(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if part.is_symlink() or getattr(info,'st_file_attributes',0) & getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',1024):
                raise ValueError('File redirection rejected')
    return path

def read(path, limit):
    path = safe_path(path)
    if not stat.S_ISREG(path.stat().st_mode): raise ValueError('Input must be a regular file')
    with path.open('rb') as stream: raw = stream.read(limit+1)
    if len(raw)>limit: raise ValueError('Input size limit exceeded')
    return raw

def load(root, investigation_id):
    if not re.fullmatch('[a-f0-9]{32}',investigation_id): raise ValueError('Invalid investigation ID')
    directory = safe_path(Path(root)/investigation_id)
    manifest_raw = read(directory/'manifest.json',65536)
    events_raw = read(directory/'events.jsonl',4*1024*1024)
    try:
        manifest = loads(manifest_raw)
        if (type(manifest['format']) is not int or manifest['format'] != 1 or manifest['policy_version'] != 'v4-1' or manifest['schema'] != 3
            or manifest['application_version'] not in ('0.5.0','0.6.0','0.7.0')
            or manifest['investigation_id'] != investigation_id or manifest.get('dry_run')
            or manifest['status'] == 'RUNNING' or 'replay_of' in manifest):
            raise ValueError('Unsupported or incomplete investigation')
        if not re.fullmatch('[a-f0-9]{64}',manifest['evidence_fingerprint']):
            raise ValueError('Invalid evidence fingerprint')
        lines = events_raw.splitlines()
        if not 1 <= len(lines) <= 256: raise ValueError('Invalid transcript event count')
        events=[]; chain='0'*64
        for sequence,line in enumerate(lines):
            if len(line)>600*1024: raise ValueError('Transcript event size limit')
            event=loads(line)
            if set(event) != {'sequence','kind','data','previous','hash'}: raise ValueError('Invalid event keys')
            unsigned={k:v for k,v in event.items() if k!='hash'}
            if type(event['sequence']) is not int or event['sequence']!=sequence or event['previous']!=chain or event_digest(unsigned)!=event['hash']:
                raise ValueError('Transcript integrity failed')
            chain=event['hash'];events.append(event)
        if manifest['chain']!=chain or manifest['event_count']!=len(events): raise ValueError('Incomplete transcript')
        if events[-1]['kind']!='terminal' or sum(e['kind']=='terminal' for e in events)!=1:
            raise ValueError('Invalid terminal sequence')
        state=State(Budget(**manifest['budgets'])); operations=[]; exposures=[]; results=[]
        initialized=False; pending=None; final=None
        for event in events[:-1]:
            kind,data=event['kind'],event['data']
            if final is not None: raise ValueError('Event after final proposal')
            if kind=='initial':
                if initialized: raise ValueError('Duplicate initialization')
                response=data; initialized=True
                operations.append(dict(operation='initial_retrieval',question=manifest['question'],completion='COMPLETED'))
            elif kind=='accepted':
                if not initialized or pending is not None: raise ValueError('Invalid operation sequence')
                proposal=data['proposal'];name=proposal['tool'];args=arguments(name,proposal['arguments'])
                if 'evidence_id' in args and args['evidence_id'] not in state.exposed: raise ValueError('Undisclosed anchor')
                pending=dict(operation=name,arguments=args,completion='ATTEMPTED_NO_RESULT')
                operations.append(pending);continue
            elif kind=='result':
                if pending is None or data['operation']!=pending['operation']: raise ValueError('Unpaired result')
                response=data['response']
                if event_digest(response['result'])!=data['result_sha256']: raise ValueError('Result digest mismatch')
                pending['completion']='COMPLETED'
                pending=None
            elif kind=='exposure':
                if not initialized or pending: raise ValueError('Invalid exposure sequence')
                disclosed=data['content']
                if set(disclosed)!= {'records','relationships','detections'}: raise ValueError('Invalid exposure')
                for section,key in [('records','id'),('relationships','relationship_id'),('detections','detection_id')]:
                    for item in disclosed[section]:
                        if item!=getattr(state,section).get(item[key]): raise ValueError('Exposure differs from retrieved data')
                state.disclose(disclosed);exposures.append(disclosed);continue
            elif kind=='validated_final':
                if not initialized or pending: raise ValueError('Invalid final sequence')
                final=state.render(data['answer']);continue
            elif kind in ('rejected','loop_rejected'): continue
            else: raise ValueError('Unsupported transcript event')
            if response['fingerprint']!=manifest['evidence_fingerprint'] or response['schema']!=3 or response['database_changes']!=0:
                raise ValueError('Transcript evidence state mismatch')
            validate_output(response['result']);results.append(response['result']);state.ingest(response['result'])
        terminal=events[-1]['data']
        if terminal['evidence_fingerprint']!=manifest['evidence_fingerprint'] or terminal['termination']!=manifest['status']:
            raise ValueError('Terminal state mismatch')
        expected=final if final is not None else state.partial()
        if terminal['findings']!=expected: raise ValueError('Terminal findings differ from controller rendering')
        if not initialized: raise ValueError('No completed retrieval')
        import hashlib
        return dict(manifest=manifest, findings=expected, results=results, exposures=exposures,
                    operations=operations, terminal=terminal,
                    input_hashes={'manifest':hashlib.sha256(manifest_raw).hexdigest(),'events':hashlib.sha256(events_raw).hexdigest()})
    except (KeyError,TypeError,AttributeError,IndexError) as exc:
        raise ValueError('Malformed investigation transcript') from exc

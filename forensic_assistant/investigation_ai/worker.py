"""Private trusted process entry point. Never accepts raw model output."""
import contextlib
import json
from pathlib import Path
import sys
import time
import os

if __package__ in (None, ''):
    # Launched with -I: only this installed source root is added, never case CWD.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from forensic_assistant.investigation_ai.case import open_readonly, read_transaction
from forensic_assistant.semantic.documents import fingerprint
from forensic_assistant.investigation_ai import tools
from forensic_assistant.investigation_ai.diagnostics import Profile

MAX_MESSAGE = 512 * 1024

def serve():
    from forensic_assistant.artifacts.worker import limit_memory
    memory_guard = limit_memory()
    config = None
    protocol = sys.stdout.buffer
    model = None
    index_identity = None
    snapshot_path = None
    snapshot_guard = None
    baseline = None
    integrity = dict(strategy='private_sqlite_snapshot', fingerprint_count=0,
                     fingerprint_seconds=0.0, snapshot_seconds=0.0, snapshot_bytes=0,
                     live_case_matches=None)
    while line := sys.stdin.buffer.readline(MAX_MESSAGE + 1):
        if len(line) > MAX_MESSAGE:
            raise ValueError('Worker request limit exceeded')
        started = time.monotonic()
        response = {}
        profile = None
        try:
            request = json.loads(line)
            if config is None:
                config = request['config']
                response = {'ready': True, 'worker_pid': os.getpid()}
            else:
                op = request['operation']
                def emit(value):
                    protocol.write(json.dumps({'startup_diagnostic': value}).encode() + b'\n')
                    protocol.flush()
                profile = Profile(started + request['seconds'], emit, config.get('_deadline'))
                with profile.phase('semantic_setup'):
                    # A pinned generation cannot change underneath the investigation.
                    if config.get('semantic_enabled'):
                        from forensic_assistant.semantic.index import _generation
                        from forensic_assistant.semantic.model import sha
                        try:
                            generation = _generation(config['index_root'])
                            current = {'generation': generation.name, 'manifest_sha256': sha(generation / 'manifest.json')}
                            if index_identity is not None and current != index_identity:
                                raise ValueError('SEMANTIC_STATE_CHANGED')
                            index_identity = current
                        except (OSError, ValueError):
                            if index_identity is not None:
                                raise
                            config['semantic_enabled'] = False
                    needs_model = op == 'semantic_search'
                    if op == 'initial' and config.get('semantic_enabled'):
                        from forensic_assistant.semantic.hybrid import precise
                        needs_model = not precise(request['question'])
                    if needs_model and model is None:
                        try:
                            with contextlib.redirect_stdout(sys.stderr):
                                from forensic_assistant.semantic.model import LocalModel
                                model = LocalModel(config['model_path'])
                        except (ImportError, OSError, ValueError):
                            if op != 'initial':
                                raise
                            config['semantic_enabled'] = False
                if config.get('_snapshot_dir') and op == 'initial':
                    if snapshot_path is not None:
                        raise ValueError('Investigation snapshot already initialized')
                    from forensic_assistant.investigation_ai.snapshot import create, SnapshotFile
                    with profile.phase('snapshot_creation'):
                        copied_at = time.perf_counter()
                        live = open_readonly(config['case_path'], started + request['seconds'], profile)
                        try:
                            with read_transaction(live):
                                # Establish the source read view before backup; WAL is included.
                                live.execute('SELECT name FROM sqlite_master LIMIT 1').fetchone()
                                snapshot_path, integrity['snapshot_bytes'] = create(live, config['_snapshot_dir'], profile.deadline)
                        finally:
                            live.close()
                        snapshot_guard = SnapshotFile(snapshot_path)
                        integrity['snapshot_seconds'] = time.perf_counter() - copied_at
                if config.get('_snapshot_dir') and snapshot_path is None:
                    raise ValueError('Investigation snapshot not initialized')
                selected_path = config['case_path'] if op == 'check' or snapshot_path is None else snapshot_path
                db = open_readonly(selected_path, started + request['seconds'], profile)
                try:
                    with read_transaction(db):
                        if snapshot_path is None or op in ('initial', 'check'):
                            with profile.phase('fingerprint'):
                                hashed_at = time.perf_counter()
                                observed = fingerprint(db)
                                integrity['fingerprint_count'] += 1
                                integrity['fingerprint_seconds'] += time.perf_counter() - hashed_at
                            if op == 'initial':
                                baseline = observed
                            if snapshot_path is not None and op == 'check':
                                integrity['live_case_matches'] = observed == baseline
                        else:
                            observed = baseline
                        if request.get('expected_fingerprint') not in (None, observed):
                            raise ValueError('EVIDENCE_STATE_CHANGED')
                        tool_config = config
                        if snapshot_path is not None and op != 'check':
                            from forensic_assistant.investigation_ai.snapshot import SnapshotFingerprint
                            tool_config = {**config, '_snapshot_proof': SnapshotFingerprint(db, snapshot_guard, baseline)}
                        with contextlib.redirect_stdout(sys.stderr):
                            if op == 'initial':
                                result = tools.initial(db, request['question'], {**tool_config, '_profile': profile}, model)
                            elif op == 'check':
                                result = {'checked': True}
                            else:
                                result = tools.execute(
                                    db,
                                    op,
                                    request['arguments'],
                                    {**tool_config, 'known_ids': request['known_ids']},
                                    model
                                )
                        response = {
                            'result': result,
                            'fingerprint': observed,
                            'schema': db.execute('PRAGMA user_version').fetchone()[0],
                            'semantic_identity': index_identity,
                            'model_identity': model.identity if model else None,
                            'semantic_available': bool(model and config.get('semantic_enabled') and (op != 'initial' or result.get('semantic_used'))),
                            'elapsed_seconds': time.monotonic() - started,
                            'database_changes': db.total_changes,
                            **({'integrity': dict(integrity)} if snapshot_path is not None else {})
                        }
                finally:
                    db.close()
        except Exception as exc:
            response = {
                'error': str(exc)[:1000],
                'error_type': type(exc).__name__,
                'stage': profile.current if profile else 'worker_start',
                'timed_out': bool(profile and time.monotonic() >= profile.deadline),
                **({'integrity': dict(integrity)} if snapshot_path is not None else {}),
                'elapsed_seconds': time.monotonic() - started
            }
        raw = json.dumps(response, ensure_ascii=True, separators=(',', ':')).encode()
        if len(raw) > MAX_MESSAGE:
            raw = b'{"error":"Worker result exceeded byte budget","error_type":"ResourceLimit"}'
        sys.stdout.buffer.write(raw + b'\n')
        sys.stdout.buffer.flush()

if __name__ == '__main__':
    serve()

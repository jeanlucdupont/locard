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
    view = None
    baseline = None
    integrity = dict(strategy='read_only_transaction', fingerprint_count=0,
                     fingerprint_seconds=0.0, transaction_seconds=0.0,
                     live_case_matches=None)
    try:
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
                    profile = Profile(started + request['seconds'], emit, request.get('_deadline') or config.get('_deadline'))
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
                    if config.get('_transaction_view') and op == 'initial':
                        if view is not None:
                            raise ValueError('Investigation read view already initialized')
                        from forensic_assistant.investigation_ai.case import ReadView
                        opened_at = time.perf_counter()
                        view = ReadView(config['case_path'], profile.deadline, profile)
                        integrity['transaction_seconds'] = time.perf_counter() - opened_at
                    if config.get('_transaction_view') and view is None:
                        raise ValueError('Investigation read view not initialized')
                    if view is not None:
                        view.check_identity()
                    pinned = view is not None and op != 'check'
                    db = view.db if pinned else open_readonly(config['case_path'], profile.deadline, profile)
                    if pinned:
                        view.deadline(profile.deadline)
                    try:
                        with (contextlib.nullcontext(db) if pinned else read_transaction(db)):
                            if view is None or op in ('initial', 'check'):
                                with profile.phase('fingerprint'):
                                    hashed_at = time.perf_counter()
                                    observed = fingerprint(db)
                                    integrity['fingerprint_count'] += 1
                                    integrity['fingerprint_seconds'] += time.perf_counter() - hashed_at
                                if op == 'initial':
                                    baseline = observed
                                    if view is not None:
                                        view.fingerprint = observed
                                if view is not None and op == 'check':
                                    integrity['live_case_matches'] = observed == baseline
                            else:
                                observed = baseline
                            if request.get('expected_fingerprint') not in (None, observed):
                                raise ValueError('EVIDENCE_STATE_CHANGED')
                            tool_config = config
                            if pinned:
                                from forensic_assistant.investigation_ai.case import ReadViewFingerprint
                                tool_config = {**config, '_read_view_proof': ReadViewFingerprint(view)}
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
                            if view is not None:
                                view.check_identity()
                            response = {
                                'result': result,
                                'fingerprint': observed,
                                'schema': db.execute('PRAGMA user_version').fetchone()[0],
                                'semantic_identity': index_identity,
                                'model_identity': model.identity if model else None,
                                'semantic_available': bool(model and config.get('semantic_enabled') and (op != 'initial' or result.get('semantic_used'))),
                                'elapsed_seconds': time.monotonic() - started,
                                'database_changes': db.total_changes,
                                **({'integrity': dict(integrity)} if view is not None else {})
                            }
                    finally:
                        if not pinned:
                            db.close()
            except Exception as exc:
                response = {
                    'error': str(exc)[:1000],
                    'error_type': type(exc).__name__,
                    'stage': profile.current if profile else 'worker_start',
                    'timed_out': bool(profile and time.monotonic() >= profile.deadline),
                    **({'integrity': dict(integrity)} if view is not None else {}),
                    'elapsed_seconds': time.monotonic() - started
                }
            raw = json.dumps(response, ensure_ascii=True, separators=(',', ':')).encode()
            if len(raw) > MAX_MESSAGE:
                raw = b'{"error":"Worker result exceeded byte budget","error_type":"ResourceLimit"}'
            sys.stdout.buffer.write(raw + b'\n')
            sys.stdout.buffer.flush()
    finally:
        if view is not None:
            view.close()

if __name__ == '__main__':
    serve()

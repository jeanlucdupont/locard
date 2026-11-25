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
    autonomous_calls = 0
    follow_records = {}
    follow_searches = set()
    batch_searches = 0
    integrity = dict(strategy='sqlite_read_view_v1', fingerprint_count=0,
                     fingerprint_seconds=0.0, transaction_seconds=0.0,
                     live_case_matches=None)
    try:
        while line := sys.stdin.buffer.readline(MAX_MESSAGE + 1):
            if len(line) > MAX_MESSAGE:
                raise ValueError('Worker request limit exceeded')
            started = time.monotonic()
            response = {}
            profile = None
            phase = 'worker_start'
            try:
                request = json.loads(line)
                if config is None:
                    config = request['config']
                    response = {'ready': True, 'worker_pid': os.getpid()}
                else:
                    op = request['operation']
                    grant=config.get('_stage_a')
                    if grant is not None and op!='check':
                        phase = 'authorization_validation'
                        from forensic_assistant.investigation_ai import autonomous_policy
                        autonomous_policy.validate(grant,config['case_path'])
                        if op!='initial':
                            autonomous_policy.operation(grant,config['case_path'],op,request['arguments'])
                            autonomous_calls+=1
                            if (autonomous_calls-1)%6==0:batch_searches=0
                            if autonomous_calls>grant['limits']['tool_calls']:raise ValueError('RESOURCE_BUDGET_EXHAUSTED')
                    if config.get('_briefing_initial') and op not in ('initial','briefing_search','check'):
                        raise ValueError('Operation outside approved briefing discovery surface')
                    def emit(value):
                        protocol.write(json.dumps({'startup_diagnostic': value}).encode() + b'\n')
                        protocol.flush()
                    profile = Profile(min(started + request['seconds'],request.get('_operation_deadline',float('inf'))), emit, request.get('_deadline') or config.get('_deadline'))
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
                            from forensic_assistant.retrieval.temporal_scope import resolve
                            needs_model = (resolve(request['question'], config.get('date_hint'))['kind'] == 'none'
                                           and not precise(request['question']))
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
                    pinned = view is not None
                    db = view.db if pinned else open_readonly(config['case_path'], profile.deadline, profile)
                    if pinned:
                        view.deadline(profile.deadline)
                        view.profile = profile
                    try:
                        with (contextlib.nullcontext(db) if pinned else read_transaction(db)):
                            if view is None:
                                # Legacy replay still verifies exact content on every operation.
                                with profile.phase('fingerprint'):
                                    observed = fingerprint(db)
                            else:
                                observed = None  # Never put a session token in a digest field.
                            if request.get('expected_fingerprint') not in (None, observed):
                                raise ValueError('EVIDENCE_STATE_CHANGED')
                            tool_config = config
                            if pinned:
                                from forensic_assistant.investigation_ai.case import ReadViewFingerprint
                                tool_config = {**config, '_read_view_proof': ReadViewFingerprint(view)}
                            with contextlib.redirect_stdout(sys.stderr):
                                if op == 'initial':
                                    result = (tools.envelope(db, 'briefing_initial', {'records': []})
                                              if config.get('_briefing_initial') or grant is not None else
                                              tools.initial(db, request['question'], {**tool_config, '_profile': profile}, model))
                                    if config.get('_briefing_all'):
                                        from forensic_assistant.briefing_discovery import available
                                        result['available_artifacts'] = available(db)
                                elif op == 'check':
                                    result = {'checked': True}
                                elif op == 'briefing_search' and config.get('_briefing_initial'):
                                    from forensic_assistant.briefing import execute_query
                                    result = execute_query(db, request['arguments'], cross=bool(config.get('_briefing_all')))
                                elif op == 'inspect_context' and grant is not None:
                                    from forensic_assistant.investigation_ai import context_inspection
                                    if request['arguments']['evidence_id'] not in request['known_ids']:raise ValueError('CONTEXT_RECORD_NOT_DISCLOSED')
                                    result=context_inspection.inspect(db,grant,request['arguments'],follow_records)
                                elif op == 'follow_up' and grant is not None:
                                    from forensic_assistant.investigation_ai import follow_up
                                    from forensic_assistant.investigation_ai.transcript import digest
                                    plan=follow_up.record_window(grant,request['arguments'],follow_records)
                                    key=digest(plan)
                                    from forensic_assistant.investigation_ai.extended import enabled
                                    if enabled(grant) and batch_searches>=2:raise ValueError('RESOURCE_BUDGET_EXHAUSTED')
                                    if key in follow_searches or len(follow_searches)>=grant['follow_up']['searches']:
                                        raise ValueError('FOLLOW_UP_BUDGET_OR_DUPLICATE')
                                    follow_searches.add(key)
                                    batch_searches+=1
                                    with profile.phase('temporal_search'):
                                        try:result=follow_up.search(db,grant,request['arguments'],follow_records,deadline=profile.deadline)
                                        finally:
                                            if pinned:view.deadline(profile.deadline)
                                else:
                                    if grant is not None:
                                        autonomous_policy.dispatch(db,grant,config['case_path'],op,request['arguments'])
                                    result = tools.execute(
                                        db,
                                        op,
                                        request['arguments'],
                                        {**tool_config, 'known_ids': request['known_ids']},
                                        model
                                    )
                            from forensic_assistant.investigation_ai.follow_up import supported
                            if grant is not None and supported(grant):
                                for record in result.get('records',[]):
                                    follow_records[record['id']]=record
                                if len(follow_records)>grant['follow_up']['distinct_disclosures']:raise ValueError('RESOURCE_BUDGET_EXHAUSTED')
                            if view is not None:
                                view.check_identity()
                                integrity.update(fingerprint_count=view.fingerprint_count,
                                                 fingerprint_seconds=view.fingerprint_seconds)
                            response = {
                                'result': result,
                                'fingerprint': observed,
                                **({'evidence_state': view.state} if view is not None else {}),
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
                from forensic_assistant.investigation_ai.worker_diagnostics import classify
                exceeded=bool(profile and time.monotonic() >= profile.deadline-(.1 if profile.current=='temporal_search' else 0))
                diagnostic=classify(exc,profile.current if profile else phase,exceeded)
                safe_codes={'ADDITIONAL_SCOPE_REQUIRED','AUTHORIZATION_INVALID','AUTHORIZATION_EXPIRED','AUTHORIZATION_CASE_CHANGED','FOLLOW_UP_BUDGET_OR_DUPLICATE','FOLLOW_UP_ANCHOR_NOT_RETRIEVED','FOLLOW_UP_ANCHOR_OUTSIDE_WINDOW','RESOURCE_BUDGET_EXHAUSTED','CONTEXT_DUPLICATE'}
                safe_error=str(exc) if type(exc) is ValueError and str(exc) in safe_codes else 'EVIDENCE_STATE_CHANGED' if str(exc).startswith('EVIDENCE_STATE_CHANGED') else diagnostic['category']
                response = {
                    'error': safe_error,
                    'worker_diagnostic':diagnostic,
                    'error_type': type(exc).__name__,
                    'stage': profile.current if profile else phase,
                    'timed_out': exceeded,
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

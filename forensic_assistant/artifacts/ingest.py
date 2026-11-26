"""Read-only hashed sources, bounded parser workers, and atomic stage publication."""
import importlib.metadata
import json
import os
import signal
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
from .progress import Deadline, WorkerFailure, ProgressError, policy, read_snapshot, snapshot_path, safe_diagnostics
from forensic_assistant.ingest.observation import emit
from forensic_assistant.ingest.evtx import digest
from forensic_assistant.database.db import now, register_source
from forensic_assistant.database.artifacts import dump
from forensic_assistant.artifacts.context import bind_context
from forensic_assistant.artifacts.worker import PARSERS
from forensic_assistant.investigation_ai.lifecycle import WorkerJob, CleanupError

TABLES = (
    'evidence_records',
    'evidence_timestamps',
    'evidence_objects',
    'mft_records',
    'mft_names',
    'prefetch_records',
    'prefetch_references',
    'prefetch_volumes',
    'registry_hives',
    'registry_keys',
    'registry_values',
    'registry_views'
)


def worker(kind, path, sha, stage, options, timeout):
    deadline = None
    if kind in ('mft','defender'):
        configuration = options.get('_supervision', policy(inactivity=timeout))
        deadline = Deadline(configuration, Path(path).stat().st_size, clock=time.monotonic)
    failure = None
    args = [
        sys.executable,
        '-m',
        'forensic_assistant.artifacts.worker',
        kind,
        path,
        sha,
        str(stage),
        dump(options),
        '--parent-guard'
    ]
    # Diagnostics go to disk so a noisy native parser cannot grow parent memory.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            proc = subprocess.Popen(
                args,
                stdout=stdout,
                stderr=stderr,
                stdin=subprocess.PIPE,
                start_new_session=sys.platform != 'win32',
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
        except OSError as exc:
            if deadline:
                raise WorkerFailure('startup_failure', dict(deadline.details(), cleanup='no process created',
                                                           exception_class=type(exc).__name__)) from exc
            raise
        job = None
        permitted = False
        ready = Path(str(stage) + '.ready')
        started = time.monotonic()
        emit(parser_stage="worker starting", parser=PARSERS.get(kind, kind), worker_pid=proc.pid)
        try:
            while True:
                emit(worker_alive=proc.poll() is None, worker_exit_code=proc.returncode)
                try:
                    emit(stage_bytes=stage.stat().st_size)
                except OSError:
                    pass  # Diagnostic availability never determines parser outcome.
                if deadline:
                    category = deadline.check()
                    if category:
                        raise WorkerFailure(category, deadline.details())
                    progress_file = snapshot_path(stage)
                    if progress_file.exists():
                        deadline.observe(read_snapshot(progress_file))
                        emit(parser_stage=deadline.phase, records_processed=deadline.counts['records'],
                             bytes_read=deadline.counts['bytes_read'], paths_processed=deadline.counts['paths'])
                if not deadline and time.monotonic() - started > timeout:
                    raise ValueError('Parser worker timed out; staged output rejected')
                if stage.exists() and stage.stat().st_size > 8 * 1024 ** 3:
                    raise WorkerFailure('resource_limit', dict(deadline.details(), reason='Parser stage exceeds 8 GiB')) if deadline else ValueError('Parser stage exceeds 8 GiB; staged output rejected')
                if kind in ('sqlite_recovery', 'sqlite_immutable'):
                    from .sqlite_recovery import MAX_BYTES
                    sizes = sum(p.stat().st_size for p in stage.parent.rglob('*') if p.is_file())
                    if sizes > MAX_BYTES:
                        raise ValueError('SQLite recovery staging limit exceeded')
                if any(os.fstat(f.fileno()).st_size > 65536 for f in (stdout, stderr)):
                    raise WorkerFailure('resource_limit', dict(deadline.details(), reason='Parser diagnostic limit exceeded')) if deadline else ValueError('Parser worker diagnostic limit exceeded')
                if not permitted and ready.exists():
                    with ready.open('rb') as handshake:
                        raw = handshake.read(129)
                    if len(raw) > 128:
                        raise ValueError('Invalid parser worker handshake')
                    message = json.loads(raw)
                    if set(message) != {'worker_pid'} or type(message['worker_pid']) is not int or message['worker_pid'] <= 0:
                        raise ValueError('Invalid parser worker handshake')
                    emit(worker_pid=message['worker_pid'], parser_stage="parsing")
                    job = WorkerJob(message['worker_pid'])
                    proc.stdin.write(b'go\n')
                    proc.stdin.flush()
                    proc.stdin.close()
                    permitted = True
                if proc.poll() is not None:
                    if deadline and snapshot_path(stage).exists():
                        deadline.observe(read_snapshot(snapshot_path(stage)))
                    break
                time.sleep(.25)
            stdout.seek(0)
            stderr.seek(0)
            out = stdout.read(65537)
            err = stderr.read(65537)
            if len(out) > 65536 or len(err) > 65536:
                raise WorkerFailure('resource_limit', dict(deadline.details(), reason='Parser diagnostic limit exceeded')) if deadline else ValueError('Parser worker diagnostic limit exceeded')
            if deadline and proc.returncode:
                diagnostics = {}
                try:
                    message = json.loads(out)
                    category = message.get('error_category')
                    if category == 'progress_communication':
                        diagnostics = safe_diagnostics(message.get('progress_diagnostics'))
                except (ValueError, AttributeError):
                    category = None
                raise WorkerFailure('startup_failure' if not permitted else category if category in ('parser_exception', 'progress_communication') else 'worker_crash',
                                    dict(deadline.details(), **diagnostics))
            if deadline and (not permitted or deadline.phase != 'complete'):
                raise WorkerFailure('incomplete_progress', deadline.details())
            if proc.returncode:
                if kind in ('sqlite_recovery', 'sqlite_validate', 'sqlite_immutable'):
                    from .browser_journal import SnapshotError
                    details = {}
                    try:
                        details = json.loads(out)['sqlite_diagnostics']
                        category = details['category']
                    except (ValueError, KeyError, TypeError):
                        category = 'sqlite_recovery_failed'
                    allowed = ('recovery_unsupported', 'inconsistent_acquisition', 'journal_malformed',
                               'journal_incomplete', 'resource_limit', 'sqlite_recovery_failed', 'derived_validation_failed',
                               'sqlite_validation_failed', 'snapshot_consistency_not_established', 'journal_active_or_hot',
                               'journal_indeterminate', 'missing_required_companion')
                    from forensic_assistant.retrieval.presentation import safe_text
                    reason = safe_text(details.get('reason', 'SQLite snapshot worker rejected the acquired set'))[:300] if category in allowed else 'SQLite snapshot worker failed'
                    error = SnapshotError(category if category in allowed else 'sqlite_recovery_failed',
                                          reason, options['manifest'], attempted=details.get('recovery_attempted') is True)
                    for key in ('sqlite_errorcode', 'errno', 'winerror'):
                        if type(details.get(key)) is int: error.diagnostics[key] = details[key]
                    raise error
                raise ValueError('Parser worker failed; staged output rejected: ' + out.decode(errors='replace')[:1000] + err.decode(errors='replace')[:1000])
            return json.loads(out)
        except BaseException as exc:
            if deadline:
                if isinstance(exc, WorkerFailure):
                    failure = exc
                elif isinstance(exc, KeyboardInterrupt):
                    failure = exc
                    failure.diagnostics = dict(deadline.details(), category='cancelled', staged_output='rejected')
                else:
                    failure = WorkerFailure('progress_communication' if isinstance(exc, ProgressError) else 'worker_failure', deadline.details())
                    failure.diagnostics['exception_class'] = type(exc).__name__
                    if isinstance(exc, ProgressError):
                        failure.diagnostics.update(safe_diagnostics(exc.diagnostics))
                    raise failure from exc
            raise
        finally:
            if failure is not None:
                failure.diagnostics['worker_exit_code_before_cleanup'] = proc.poll()
            contained = False
            try:
                if job:
                    job.close()
                elif proc.poll() is None:
                    # Before permission, the real child cannot parse or spawn.
                    # EOF lets it exit; wait for the launcher to reap it rather
                    # than killing only the launcher and leaving an orphan.
                    proc.stdin.close()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired as exc:
                        raise CleanupError('Unconfirmed parser startup cleanup; exiting session') from exc
                contained = True
            finally:
                try:
                    if sys.platform != 'win32':
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise CleanupError('Parser process cleanup failed') from exc
                finally:
                    stream = getattr(proc, 'stdin', None)
                    if stream and not stream.closed:
                        stream.close()
                    if failure is not None:
                        failure.diagnostics.update(worker_exit_code=proc.poll(),
                                                   cleanup='confirmed' if contained and proc.poll() is not None else 'unconfirmed')


def ingest_artifact(
    db,
    path,
    kind,
    *,
    hostname=None,
    username=None,
    volume_root=None,
    timeout=None,
    mft_startup_timeout=60,
    mft_hard_timeout=21600,
    record_size=None,
    runner=worker,
    batch_id=None,
    browser_product=None,
    profile=None,
    acquisition=None,
    source_label=None
):
    if kind == 'browser':
        from forensic_assistant.database.browser import require5
        from .browser import validate_options
        require5(db)
        validate_options(browser_product, profile)
        if batch_id is None or not db.execute('SELECT 1 FROM ingestion_batches WHERE batch_id=?', (batch_id,)).fetchone():
            raise ValueError('Browser ingestion requires an explicit source-associated ingestion batch')
    if kind not in PARSERS:
        raise ValueError('Unknown artifact type')
    timeout = (900 if kind in ('mft','defender') else 300) if timeout is None else timeout
    supervision = policy(timeout, mft_startup_timeout, mft_hard_timeout) if kind in ('mft','defender') else None
    if not 1 <= timeout <= 3600:
        raise ValueError('Parser timeout must be 1..3600 seconds')
    if kind in ('browser','defender'):
        from .sqlite_recovery import regular
        regular(path)  # Reject redirects before resolve could erase their identity.
    path = str(Path(path).resolve())
    source_file = source_label or path
    if acquisition is not None and (kind != 'mft' or source_label is None):
        raise ValueError('Acquisition provenance requires native MFT source context')
    from .registry_logs import is_log, describe, CLASSIFIER
    companion = kind == 'registry' and is_log(path)
    parser = CLASSIFIER if companion else PARSERS[kind]
    version = '1' if companion or kind == 'defender' else sqlite3.sqlite_version if kind == 'browser' else importlib.metadata.version(parser)
    # Validate context before starting a run (no live environment expansion).
    if volume_root:
        import re
        if not re.fullmatch(r'[A-Za-z]:\\?', volume_root):
            raise ValueError('Volume root must be an explicit drive letter such as C:')
    options = {'record_size': record_size} if kind == 'mft' else {}
    if supervision is not None:
        options['_supervision'] = supervision
    if source_label is not None:
        options['_source_path'] = source_file
    parameters = {**options, 'acquisition': acquisition} if acquisition is not None else options
    run_id = None
    inserted = duplicates = errors = 0
    status = 'failed'
    attached = False
    def report(message, stage='file', locator=None):
        nonlocal errors
        errors += 1
        locator = locator or {}
        eid = db.execute(
            'INSERT INTO ingestion_errors(run_id,record_offset,stage,message) VALUES (?,?,?,?)',
            (run_id, locator.get('offset'), stage, message)
        ).lastrowid
        db.execute('INSERT INTO artifact_errors VALUES (?,?)', (eid, dump(locator)))
    try:
        with db:
            run_id = db.execute(
                'INSERT INTO ingestion_runs(source_file,started_utc,status) VALUES (?,?,?)',
                (source_file, now(), 'running')
            ).lastrowid
            if batch_id is not None:
                db.execute('UPDATE ingestion_runs SET batch_id=? WHERE id=?', (batch_id, run_id))
            db.execute(
                'INSERT INTO artifact_runs VALUES (?,?,?,?,?,?,?)',
                (run_id, kind, parser, version, '1', None, dump(parameters))
            )
        sha = digest(path)
        size = Path(path).stat().st_size
        if acquisition is not None and (sha != acquisition['sha256'] or size != acquisition['bytes_written']):
            raise ValueError('Acquired MFT changed before parsing; rejected')
        with db:
            db.execute('UPDATE artifact_runs SET source_sha256=? WHERE run_id=?', (sha, run_id))
        if companion:
            classification = describe(path)
            with db:
                db.execute('UPDATE artifact_runs SET parameters_json=? WHERE run_id=?', (dump(classification), run_id))
                if digest(path) != sha or Path(path).stat().st_size != size:
                    report('Source changed during classification; companion rejected', 'integrity')
                    status = 'changed'
                else:
                    register_source(db, sha, size, path)
                    bind_context(db, sha, path, hostname, username, volume_root)
                    db.execute('UPDATE ingestion_runs SET file_sha256=? WHERE id=?', (sha, run_id))
                    status = 'unsupported'
                db.execute('UPDATE ingestion_runs SET finished_utc=?,status=?,error_count=? WHERE id=?',
                           (now(), status, errors, run_id))
            return dict(run_id=run_id, source_file=path, source_type=kind, status=status,
                        inserted=0, duplicates=0, errors=errors, parser=parser, parser_version=version,
                        **classification)
        with tempfile.TemporaryDirectory(prefix='locard-artifact-') as temp:
            stage = Path(temp) / 'stage.db'
            parse_path = path
            if kind == 'browser':
                from .browser import snapshot, inventory
                from forensic_assistant.investigation_ai.snapshot import _private_mkdir
                acquired_directory = Path(temp) / 'sqlite-acquired'
                _private_mkdir(acquired_directory)
                parse_path = str(acquired_directory / 'History')
                source_row = db.execute('SELECT source_id FROM ingestion_batches WHERE batch_id=?', (batch_id,)).fetchone()
                options = snapshot(path, parse_path, browser_product, profile,
                                   dict(run_id=run_id, batch_id=batch_id, source_id=source_row[0] if source_row else None))
                parse_path = options.pop('_database_path', parse_path)
                if options['manifest']['']['sha256'] != sha:
                    raise ValueError('History changed before snapshot; rejected')
                options['_source_path'] = path
                with db:
                    db.execute('UPDATE artifact_runs SET parameters_json=? WHERE run_id=?', (dump(options), run_id))
            try:
                if kind == 'browser' and options.get('extraction'):
                    from .sqlite_immutable import extract
                    result = extract(runner, parse_path, sha, stage, options, timeout)
                    options['extraction'] = result['extraction']
                    with db:
                        db.execute('UPDATE artifact_runs SET parameters_json=? WHERE run_id=?', (dump(options), run_id))
                else:
                    result = runner(kind, parse_path, sha, stage, options, timeout)
            finally:
                if kind == 'browser' and options.get('recovery'):
                    from .sqlite_recovery import release
                    release(parse_path, options['recovery'])
            changed_companions = kind == 'browser' and inventory(path) != options['manifest']
            if changed_companions or digest(path) != sha or Path(path).stat().st_size != size:
                with db:
                    report('Source changed during ingestion; staged records rejected', 'integrity')
                status = 'changed'
            else:
                db.execute('ATTACH DATABASE ? AS artifact_stage', (str(stage),))
                attached = True
                try:
                    with db:
                        register_source(db, sha, size, source_file)
                        for row in db.execute('SELECT e.*,a.locator_json FROM artifact_stage.ingestion_errors e LEFT JOIN artifact_stage.artifact_errors a ON a.error_id=e.id'):
                            report(row['message'], row['stage'], json.loads(row['locator_json'] or '{}'))
                        for table in TABLES:
                            # Identifiers are fixed application constants, never artifact text.
                            count = db.execute(f'INSERT OR IGNORE INTO main.{table} SELECT * FROM artifact_stage.{table}').rowcount
                            if table == 'evidence_records':
                                inserted = count
                        duplicates = result['records'] - inserted
                        if kind == 'browser':
                            db.execute('INSERT INTO browser_contexts VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING',
                                       (options['context_id'], sha, browser_product, profile, options['snapshot_sha256'], dump(options['manifest'])))
                            db.execute('INSERT INTO browser_record_occurrences SELECT evidence_id,?,? FROM artifact_stage.evidence_records',
                                       (options['context_id'], run_id))
                        else:
                            bind_context(db, sha, source_file, hostname, username, volume_root)
                        db.execute('UPDATE ingestion_runs SET file_sha256=? WHERE id=?', (sha, run_id))
                finally:
                    db.rollback()
                    db.execute('DETACH DATABASE artifact_stage')
                    attached = False
                status = ('partial' if inserted or duplicates else 'failed') if errors and kind in ('browser','defender') else 'partial' if errors else 'complete'
                if kind == 'browser' and options.get('extraction'):
                    status = 'partial' if inserted or duplicates or options['extraction'].get('empty_readable') else 'failed'
                    options['extraction']['counts'].update(retained=inserted, duplicates=duplicates)
                    with db:
                        db.execute('UPDATE artifact_runs SET parameters_json=? WHERE run_id=?', (dump(options), run_id))
        with db:
            db.execute(
                'UPDATE ingestion_runs SET finished_utc=?,status=?,inserted_count=?,duplicate_count=?,error_count=? WHERE id=?',
                (now(), status, inserted, duplicates, errors, run_id)
            )
    except KeyboardInterrupt as exc:
        from forensic_assistant.ingest.interruption import record_interruption
        record_interruption(db, run_id, inserted, duplicates)
        if getattr(exc, 'diagnostics', None):
            with db:
                error_id = db.execute("SELECT id FROM ingestion_errors WHERE run_id=? AND stage='interruption' ORDER BY id DESC LIMIT 1", (run_id,)).fetchone()
                if error_id:
                    db.execute('INSERT INTO artifact_errors VALUES (?,?)', (error_id[0], dump(exc.diagnostics)))
        raise
    except CleanupError:
        if kind in ('mft','defender') and run_id is not None:
            db.rollback()
            with db:
                report(('Defender' if kind=='defender' else 'MFT')+' worker cleanup could not be confirmed; staged output rejected',
                       locator=dict(artifact=kind, category='cleanup_failure', policy=supervision,
                                    cleanup='unconfirmed', staged_output='rejected'))
                db.execute("UPDATE ingestion_runs SET finished_utc=?,status='failed',error_count=? WHERE id=?",
                           (now(), errors, run_id))
        raise
    except Exception as exc:
        db.rollback()
        if attached:
            db.execute('DETACH DATABASE artifact_stage')
        if run_id is None:
            raise
        published = db.execute('SELECT file_sha256 FROM ingestion_runs WHERE id=?', (run_id,)).fetchone()
        if not published:
            raise
        if published[0] is None:
            inserted = duplicates = 0
        status = 'partial' if published[0] is not None else 'failed'
        with db:
            message=str(exc)
            if kind=='defender' and isinstance(exc,WorkerFailure):message=message.replace('MFT worker','Defender worker',1);exc.diagnostics['artifact']='defender'
            report(f'{type(exc).__name__}: {message}', locator=getattr(exc, 'diagnostics', None))
            db.execute(
                'UPDATE ingestion_runs SET finished_utc=?,status=?,inserted_count=?,duplicate_count=?,error_count=? WHERE id=?',
                (now(), status, inserted, duplicates, errors, run_id)
            )
    return dict(
        run_id=run_id,
        source_file=source_file,
        source_type=kind,
        status=status,
        inserted=inserted,
        duplicates=duplicates,
        errors=errors,
        parser=parser,
        parser_version=version,
        **({'extraction_mode': 'best_effort_immutable' if options.get('extraction') else
             'recovered' if options.get('recovery') else 'normal' if options.get('manifest') else 'unknown'} if kind == 'browser' else {}),
        **({'extraction': options['extraction']} if kind == 'browser' and options.get('extraction') else {})
    )


DISCOVERY_LABELS = {'evtx': 'EVTX', 'mft': 'MFT', 'prefetch': 'Prefetch', 'registry': 'Registry', 'browser': 'Browser', 'defender': 'Defender'}


def identify(path, *, include_browser=False):
    from forensic_assistant.activity import is_sidecar
    if is_sidecar(path):
        return None
    with open(path, 'rb') as f:
        head = f.read(84)
    if include_browser and head.startswith(b'SQLite format 3\x00'):
        with tempfile.TemporaryDirectory(prefix='locard-discovery-') as directory:
            result = worker('browser_probe', str(path), '', Path(directory) / 'probe', {}, 60)
        return 'browser' if result.get('supported') is True else None
    if head.startswith(b'ElfFile\x00'):
        return 'evtx'
    from .registry_logs import is_log
    if head.startswith(b'regf') or (is_log(path) and head.startswith(b'HvLE')):
        return 'registry'
    if head.startswith(b'FILE'):
        return 'mft'
    if head.startswith(b'MAM') or head[4:8] == b'SCCA':
        return 'prefetch'
    from .defender import supported
    text_candidate = Path(path).suffix.lower()=='.log' or any(marker in head for marker in (b'Engine:',b'ASR Notification:',b'BEGIN BM',b'Microsoft Defender'))
    if text_candidate and supported(path):return 'defender'
    return None


def discover(path, kind=None, *, include_browser=False):
    from .ntfs_acquisition import mounted_volume
    volume = mounted_volume(path)
    if volume and kind in (None, 'mft'):
        yield volume, 'mft'
        if kind == 'mft':
            return
    def classify(candidate):
        # Explicit EVTX ingestion also records attempts for damaged .evtx files.
        # Keep signature recognition for renamed files and the traversal guards below.
        from .registry_logs import is_log
        if kind == 'registry' and is_log(candidate):
            return 'registry'  # Existing filename-designated companion classifier; no replay.
        if kind == 'defender' and candidate.name.lower().startswith(('mplog-','mpdetection-')) and candidate.suffix.lower()=='.log':
            return 'defender'  # Parser validates contents and records malformed attempts.
        if kind == 'defender':
            from .defender import supported
            if supported(candidate):return 'defender'
        if kind == 'evtx' and candidate.suffix.casefold() == '.evtx':
            return 'evtx'
        return identify(candidate, include_browser=include_browser)
    root = Path(volume + '\\') if volume else Path(path)
    if not root.exists():
        raise ValueError('Evidence path does not exist')
    if root.is_file():
        found = classify(root)
        if kind and found != kind:
            raise ValueError('Source signature does not match requested artifact type')
        if not found:
            raise ValueError('Unsupported or invalid artifact signature')
        yield root, found
        return
    def fail(error):
        raise error
    for parent, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        dirs[:] = sorted(d for d in dirs if not (Path(parent) / d).is_symlink())
        for name in sorted(files):
            p = Path(parent) / name
            if volume and p.parent == root and name.casefold() == '$mft':
                continue  # The native candidate replaces inaccessible filesystem access.
            if p.is_symlink():
                continue
            found = classify(p)
            if found and (not kind or found == kind):
                yield p, found

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
from forensic_assistant.ingest.evtx import digest
from forensic_assistant.database.db import now,register_source
from forensic_assistant.database.artifacts import dump
from forensic_assistant.artifacts.context import bind_context
from forensic_assistant.artifacts.worker import PARSERS
from forensic_assistant.investigation_ai.lifecycle import WorkerJob, CleanupError

TABLES=('evidence_records','evidence_timestamps','evidence_objects','mft_records','mft_names',
        'prefetch_records','prefetch_references','prefetch_volumes','registry_hives','registry_keys','registry_values','registry_views')


def worker(kind,path,sha,stage,options,timeout):
    args=[sys.executable,'-m','forensic_assistant.artifacts.worker',kind,path,sha,str(stage),dump(options),'--parent-guard']
    # Diagnostics go to disk so a noisy native parser cannot grow parent memory.
    with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
        proc=subprocess.Popen(args,stdout=stdout,stderr=stderr,stdin=subprocess.PIPE,
                              start_new_session=sys.platform!='win32',
                              creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        job=None;permitted=False
        ready=Path(str(stage)+'.ready')
        started=time.monotonic()
        try:
            while True:
                if time.monotonic()-started>timeout:raise ValueError('Parser worker timed out; staged output rejected')
                if stage.exists() and stage.stat().st_size>8*1024**3:raise ValueError('Parser stage exceeds 8 GiB; staged output rejected')
                if any(os.fstat(f.fileno()).st_size>65536 for f in (stdout,stderr)):
                    raise ValueError('Parser worker diagnostic limit exceeded')
                if not permitted and ready.exists():
                    raw=ready.read_bytes()
                    if len(raw)>128:raise ValueError('Invalid parser worker handshake')
                    message=json.loads(raw)
                    if set(message)!={'worker_pid'} or type(message['worker_pid']) is not int or message['worker_pid']<=0:
                        raise ValueError('Invalid parser worker handshake')
                    job=WorkerJob(message['worker_pid'])
                    proc.stdin.write(b'go\n');proc.stdin.flush();proc.stdin.close()
                    permitted=True
                if proc.poll() is not None:break
                time.sleep(.25)
            stdout.seek(0);stderr.seek(0);out=stdout.read(65537);err=stderr.read(65537)
            if len(out)>65536 or len(err)>65536:raise ValueError('Parser worker diagnostic limit exceeded')
            if proc.returncode:raise ValueError('Parser worker failed; staged output rejected: '+out.decode(errors='replace')[:1000]+err.decode(errors='replace')[:1000])
            return json.loads(out)
        finally:
            try:
                if job:job.close()
                elif proc.poll() is None:
                    # Before permission, the real child cannot parse or spawn.
                    # EOF lets it exit; wait for the launcher to reap it rather
                    # than killing only the launcher and leaving an orphan.
                    proc.stdin.close()
                    try:proc.wait(timeout=5)
                    except subprocess.TimeoutExpired as exc:
                        raise CleanupError('Unconfirmed parser startup cleanup; exiting session') from exc
            finally:
                try:
                    if sys.platform!='win32':
                        try:os.killpg(proc.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                    if proc.poll() is None:proc.kill()
                    proc.wait(timeout=5)
                except (OSError,subprocess.TimeoutExpired) as exc:
                    raise CleanupError('Parser process cleanup failed') from exc
                finally:
                    stream=getattr(proc,'stdin',None)
                    if stream and not stream.closed:stream.close()


def ingest_artifact(db,path,kind,*,hostname=None,username=None,volume_root=None,timeout=300,record_size=None,runner=worker):
    if kind not in PARSERS:raise ValueError('Unknown artifact type')
    if not 1<=timeout<=3600:raise ValueError('Parser timeout must be 1..3600 seconds')
    path=str(Path(path).resolve(strict=True));version=importlib.metadata.version(PARSERS[kind])
    # Validate context before starting a run (no live environment expansion).
    if volume_root:
        import re
        if not re.fullmatch(r'[A-Za-z]:\\?',volume_root):raise ValueError('Volume root must be an explicit drive letter such as C:')
    options={'record_size':record_size} if kind=='mft' else {}
    run_id=None
    inserted=duplicates=errors=0;status='failed';attached=False
    def report(message,stage='file',locator=None):
        nonlocal errors
        errors+=1;locator=locator or {}
        eid=db.execute('INSERT INTO ingestion_errors(run_id,record_offset,stage,message) VALUES (?,?,?,?)',(run_id,locator.get('offset'),stage,message)).lastrowid
        db.execute('INSERT INTO artifact_errors VALUES (?,?)',(eid,dump(locator)))
    try:
        with db:
            run_id=db.execute('INSERT INTO ingestion_runs(source_file,started_utc,status) VALUES (?,?,?)',(path,now(),'running')).lastrowid
            db.execute('INSERT INTO artifact_runs VALUES (?,?,?,?,?,?,?)',(run_id,kind,PARSERS[kind],version,'1',None,dump(options)))
        sha=digest(path);size=Path(path).stat().st_size
        with db:db.execute('UPDATE artifact_runs SET source_sha256=? WHERE run_id=?',(sha,run_id))
        with tempfile.TemporaryDirectory(prefix='locard-artifact-') as temp:
            stage=Path(temp)/'stage.db';result=runner(kind,path,sha,stage,options,timeout)
            if digest(path)!=sha or Path(path).stat().st_size!=size:
                with db:report('Source changed during ingestion; staged records rejected','integrity')
                status='changed'
            else:
                db.execute('ATTACH DATABASE ? AS artifact_stage',(str(stage),));attached=True
                try:
                    with db:
                        register_source(db,sha,size,path)
                        for row in db.execute('SELECT e.*,a.locator_json FROM artifact_stage.ingestion_errors e LEFT JOIN artifact_stage.artifact_errors a ON a.error_id=e.id'):
                            report(row['message'],row['stage'],json.loads(row['locator_json'] or '{}'))
                        for table in TABLES:
                            # Identifiers are fixed application constants, never artifact text.
                            count=db.execute(f'INSERT OR IGNORE INTO main.{table} SELECT * FROM artifact_stage.{table}').rowcount
                            if table=='evidence_records':inserted=count
                        duplicates=result['records']-inserted
                        bind_context(db,sha,path,hostname,username,volume_root)
                        db.execute('UPDATE ingestion_runs SET file_sha256=? WHERE id=?',(sha,run_id))
                finally:
                    db.rollback()
                    db.execute('DETACH DATABASE artifact_stage');attached=False
                status='partial' if errors else 'complete'
        with db:
            db.execute('UPDATE ingestion_runs SET finished_utc=?,status=?,inserted_count=?,duplicate_count=?,error_count=? WHERE id=?',
                       (now(),status,inserted,duplicates,errors,run_id))
    except KeyboardInterrupt:
        from forensic_assistant.ingest.interruption import record_interruption
        record_interruption(db,run_id,inserted,duplicates)
        raise
    except CleanupError:
        raise
    except Exception as exc:
        db.rollback()
        if attached:db.execute('DETACH DATABASE artifact_stage')
        if run_id is None:raise
        published=db.execute('SELECT file_sha256 FROM ingestion_runs WHERE id=?',(run_id,)).fetchone()
        if not published:raise
        if published[0] is None:inserted=duplicates=0
        status='partial' if published[0] is not None else 'failed'
        with db:
            report(f'{type(exc).__name__}: {exc}')
            db.execute('UPDATE ingestion_runs SET finished_utc=?,status=?,inserted_count=?,duplicate_count=?,error_count=? WHERE id=?',
                       (now(),status,inserted,duplicates,errors,run_id))
    return dict(run_id=run_id,source_file=path,source_type=kind,status=status,inserted=inserted,duplicates=duplicates,errors=errors,parser=PARSERS[kind],parser_version=version)


def identify(path):
    with open(path,'rb') as f:head=f.read(84)
    if head.startswith(b'ElfFile\x00'):return 'evtx'
    if head.startswith(b'regf'):return 'registry'
    if head.startswith(b'FILE'):return 'mft'
    if head.startswith(b'MAM') or head[4:8]==b'SCCA':return 'prefetch'
    return None


def discover(path,kind=None):
    root=Path(path)
    if not root.exists():raise ValueError('Evidence path does not exist')
    if root.is_file():
        found=identify(root)
        if kind and found!=kind:raise ValueError('Source signature does not match requested artifact type')
        if not found:raise ValueError('Unsupported or invalid artifact signature')
        yield root,found;return
    def fail(error):raise error
    for parent,dirs,files in os.walk(root,followlinks=False,onerror=fail):
        dirs[:]=sorted(d for d in dirs if not (Path(parent)/d).is_symlink())
        for name in sorted(files):
            p=Path(parent)/name
            if p.is_symlink():continue
            found=identify(p)
            if found and (not kind or found==kind):yield p,found

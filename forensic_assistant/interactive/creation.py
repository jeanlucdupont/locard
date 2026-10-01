"""Confirmed analyst-side creation; all forensic ingestion stays in the shared engine."""
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
import os
import sqlite3
import tempfile

from forensic_assistant.database.db import connect
from forensic_assistant.interactive.case import validate, open_existing
from forensic_assistant.interactive.console import safe
from forensic_assistant.reporting.transcripts import safe_path
from forensic_assistant import v2_cli


def destination(value):
    if not str(value).strip() or '\x00' in str(value):
        raise ValueError('Enter a database filename')
    target = safe_path(Path(value).absolute()).resolve()
    if os.name == 'nt':
        for part in target.parts[1:]:
            if (any(c in part for c in '<>:"|?*') or any(ord(c)<32 for c in part)
                    or part.endswith((' ', '.')) or Path(part).is_reserved()):
                raise ValueError('Invalid Windows destination')
    for parent in target.parents:
        if parent.exists() and not parent.is_dir():
            raise ValueError('Destination parent is not a directory')
    return target


def source_path(value, target):
    source = safe_path(Path(value).absolute()).resolve(strict=True)
    if not source.is_file() and not source.is_dir():
        raise ValueError('Source must be a file or directory')
    if target == source or (source.is_dir() and target.is_relative_to(source)):
        raise ValueError('Database must be outside the evidence source')
    return source


def preflight(source):
    # Discovery is reused, read-only, and repeated by ingestion. No parsing/hashing here.
    iterator = v2_cli.discover(source)
    try:return next(iterator, None) is not None
    finally:iterator.close()


def initialize(target, create_parents=False, on_publish=None):
    target = destination(target)
    if target.exists():raise FileExistsError('Destination already exists')
    if create_parents:
        # Check each component again around mkdir; never remove analyst-requested dirs.
        for parent in reversed(target.parents):
            safe_path(parent)
            if parent.is_dir():continue
            try:parent.mkdir()
            except FileExistsError:
                if not parent.is_dir():raise
            safe_path(parent)
    if not target.parent.is_dir():raise ValueError('Destination directory is missing')
    with tempfile.TemporaryDirectory(prefix='.locard-init-', dir=target.parent) as directory:
        staged = Path(directory)/'case.db'
        with closing(connect(staged)):pass
        validate(staged)
        destination(target)
        identity = staged.stat()
        # Never replace: both operations fail if a competing destination exists.
        try:
            if os.name == 'nt':os.rename(staged, target)
            else:os.link(staged, target)
        finally:
            # Publication may finish immediately before Ctrl+C or cleanup failure.
            # Identify our own file, never a competing destination, for retention reporting.
            if on_publish is not None and target.exists():
                actual = target.stat()
                if (actual.st_dev,actual.st_ino)==(identity.st_dev,identity.st_ino):on_publish()
    return target


def summarize(target):
    with closing(open_existing(target)) as db:
        counts = v2_cli.dispatch(db, SimpleNamespace(command='status'))[0]['artifact_counts']
        runs = {r[0]:r[1] for r in db.execute('SELECT status,count(*) FROM ingestion_runs GROUP BY status')}
        totals = db.execute('SELECT coalesce(sum(inserted_count),0),coalesce(sum(duplicate_count),0),coalesce(sum(error_count),0) FROM ingestion_runs').fetchone()
        print('Stored evidence records: '+safe(counts))
        print('File run outcomes: '+safe(runs))
        print(f'Inserted: {totals[0]}; duplicates: {totals[1]}; recorded errors: {totals[2]}')
        for row in db.execute('SELECT stage,message FROM ingestion_errors ORDER BY id'):
            print('Recorded limitation: '+safe(row['stage'])+': '+safe(row['message']))
    return sum(counts.values()), runs


_BACK = object()


def create(shell):
    while True:
        result = _attempt(shell)
        if result is not _BACK:return result


def _attempt(shell):
    target = None
    published = False
    initializing = False
    def mark_published():
        nonlocal published
        published = True
    def read(prompt):return shell.reader.read(prompt).strip()
    def path(prompt):
        value = read(prompt)
        if not value or value.casefold() in ('cancel','exit','quit'):raise EOFError
        if value.startswith(('"', "'")):
            from .shell import split
            words = split(value)
            if len(words)!=1:raise ValueError('Enter one path')
            value = words[0]
        return value
    def yes(prompt):return read(prompt).casefold() in ('y','yes')
    try:
        while True:
            try:
                target = destination(path('New database file (Enter cancels): '))
                if target.exists():
                    validate(target)
                    print('An existing Locard database is at '+safe(target))
                    if yes('Open it without ingesting? [y/N]: '):shell.activate(target);return True
                    continue
                parents = not target.parent.exists()
                if parents:
                    print('Directory does not exist:\n  '+safe(target.parent))
                    if not yes('Create this directory at final confirmation? [y/N]: '):continue
                break
            except (ValueError,OSError,sqlite3.Error) as exc:print('Invalid destination: '+safe(exc))
        while True:
            try:
                source = source_path(path('Evidence file or directory (Enter cancels): '),target)
                found = preflight(source)
                if found:break
                print('No supported artifacts found (EVTX, MFT, Prefetch, Registry).')
                choice = read('Choose another source [A], create an empty case [E], or cancel [C]: ').casefold()
                if choice=='e':break
                if choice!='a':return False
            except (ValueError,OSError) as exc:print('Invalid evidence source: '+safe(exc))
        source_name = read('Source name (Enter = generated label): ') or None
        hostname = read('Source hostname (Enter = unknown): ') or None
        username = read('Source user (Enter = unknown): ') or None
        from forensic_assistant.artifacts.context import normalize_volume_root
        while True:
            try:volume = normalize_volume_root(read('Original drive, e.g. C: (Enter = unknown): '));break
            except ValueError as exc:print(safe(exc))
        print('New case:\n  Database: '+safe(target)+'\n  Evidence: '+safe(source))
        print('Analyst-supplied metadata: '+safe(dict(name=source_name,hostname=hostname,user=username,volume_root=volume)))
        if parents:print('Requested directories will be created and retained even if later steps fail.')
        action = read(('Create empty case' if not found else 'Create case and begin ingestion')+'? [y/N; B = back]: ').casefold()
        if action=='b':return _BACK
        if action not in ('y','yes'):return False
        # Revalidate paths after interaction, before any filesystem mutation.
        source_path(source,target)
        initializing = True
        initialize(target,parents,on_publish=mark_published)
        print('Initialized database: '+safe(target))
        from forensic_assistant.database import sources
        with closing(open_existing(target)) as db:
            with db:source_id=sources.create(db,name=source_name,hostname=hostname,username=username,volume_root=volume)
        if not found:
            from forensic_assistant.database.db import now
            with closing(open_existing(target)) as db:
                with db:db.execute('INSERT INTO ingestion_batches VALUES (?,?,?,?,?,?,?)',
                    (sources.identifier('batch'),source_id,now(),now(),str(source),'case new: empty preflight selection','empty'))
            print('Empty case explicitly requested; no ingestion performed.')
            shell.activate(target);return True
        def progress(file,kind,result):
            print(safe(file)+' ['+kind+']: '+safe({k:result[k] for k in ('status','inserted','duplicates','errors')}))
        args = SimpleNamespace(command='ingest-all',path=source,source=source_id,hostname=None,user=None,
                               volume_root=None,parser_timeout=300,record_size=None)
        while True:
            source_path(args.path,target)
            with closing(open_existing(target)) as db:results = v2_cli.ingest_sources(db,args,progress)
            stored,runs = summarize(target)
            if stored:
                complete = bool(results) and set(runs)=={'complete'} and all(r['status']=='complete' for r in results)
                print('Ingestion completed successfully.' if complete else 'Ingestion completed with errors/limitations; committed evidence retained.')
                shell.activate(target);return True
            print('No evidence records were stored. This is not a successful evidence ingestion.')
            if not results:print('No supported artifacts remained at ingestion time.')
            choice = read('Choose another source [A], activate empty/failed-ingestion case [E], or cancel [C]: ').casefold()
            if choice=='e':shell.activate(target);return True
            if choice!='a':
                print('Database retained without activation: '+safe(target));return False
            while True:
                try:
                    args.path = source_path(path('Evidence file or directory (Enter cancels): '),target)
                    if preflight(args.path):break
                    print('No supported artifacts found; select another source or cancel.')
                except (OSError,ValueError) as exc:print('Invalid evidence source: '+safe(exc))
            if not yes('Begin ingestion from '+safe(args.path)+'? [y/N]: '):return False
    except (EOFError,KeyboardInterrupt):
        print('\nCreation cancelled. Previous active case unchanged.')
        if initializing and parents:print('Any analyst-requested directories already created are retained.')
        if published:
            print('Database retained: '+safe(target)+'. Already committed evidence was not rolled back.')
            summarize(target)
        return False
    except (ValueError,OSError,sqlite3.Error) as exc:
        print('Creation/ingestion failed: '+safe(exc))
        print('Any analyst-requested directories are retained; existing files were not overwritten.')
        if published:
            print('Database retained: '+safe(target)+'. Already committed evidence was not rolled back.')
            summarize(target)
            try:
                if yes('Open the retained database explicitly? [y/N]: '):shell.activate(target);return True
            except (EOFError,KeyboardInterrupt):pass
        return False

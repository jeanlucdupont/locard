"""Confirmed analyst-side creation; all forensic ingestion stays in the shared engine."""
from forensic_assistant.retrieval.presentation import human_error
from contextlib import closing
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
import os
import sqlite3
import tempfile

from forensic_assistant.database.db import connect
from forensic_assistant.interactive.case import validate, open_existing
from forensic_assistant.retrieval.presentation import safe_text as safe
from forensic_assistant.reporting.transcripts import safe_path
from forensic_assistant import v2_cli
from forensic_assistant.terminal import Palette, enabled


def destination(value):
    if not str(value).strip() or '\x00' in str(value):
        raise ValueError('Enter a database filename')
    target = safe_path(Path(value).absolute()).resolve()
    if os.name == 'nt':
        for part in target.parts[1:]:
            if (any(c in part for c in '<>:"|?*') or any(ord(c) < 32 for c in part)
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
    # Browser candidates are validated by the bounded worker on private copies.
    return list(v2_cli.discover(source, include_browser=True))


def browser_choices(found, read, palette=None):
    """Every History has explicit analyst-supplied product/profile; no path inference."""
    from forensic_assistant.artifacts.browser import validate_options
    choices = []
    palette = palette or Palette()
    candidates = [file for file, kind in found if kind == 'browser']
    if candidates:
        print(palette('key', f'Found {len(candidates)} Chromium History databases:'))
    for index, file in enumerate(candidates, 1):
        print(f'  {index}. ' + safe(file))
        while True:
            product = read('  Browser [chrome/edge]: ').casefold()
            if not product or product in ('cancel', 'exit', 'quit'):
                raise EOFError
            if product in ('chrome', 'edge'):
                break
            print(palette('warning', 'Choose chrome or edge explicitly; product is not inferred from the path.'))
        while True:
            profile = read('  Profile (required): ')
            if not profile or profile.casefold() in ('cancel', 'exit', 'quit'):
                raise EOFError
            try:
                validate_options(product, profile)
                break
            except ValueError as exc:
                print(palette('error', human_error(exc)))
        choices.append((file, product, profile))
    return choices


def initialize(target, create_parents=False, on_publish=None):
    target = destination(target)
    if target.exists():
        raise FileExistsError('Destination already exists')
    if create_parents:
        # Check each component again around mkdir; never remove analyst-requested dirs.
        for parent in reversed(target.parents):
            safe_path(parent)
            if parent.is_dir():
                continue
            try:
                parent.mkdir()
            except FileExistsError:
                if not parent.is_dir():
                    raise
            safe_path(parent)
    if not target.parent.is_dir():
        raise ValueError('Destination directory is missing')
    with tempfile.TemporaryDirectory(prefix='.locard-init-', dir=target.parent) as directory:
        staged = Path(directory) / 'case.db'
        with closing(connect(staged)):
            pass
        validate(staged)
        destination(target)
        identity = staged.stat()
        # Never replace: both operations fail if a competing destination exists.
        try:
            if os.name == 'nt':
                os.rename(staged, target)
            else:
                os.link(staged, target)
        finally:
            # Publication may finish immediately before Ctrl+C or cleanup failure.
            # Identify our own file, never a competing destination, for retention reporting.
            if on_publish is not None and target.exists():
                actual = target.stat()
                if (actual.st_dev, actual.st_ino) == (identity.st_dev, identity.st_ino):
                    on_publish()
    return target


class IngestionProgress:
    """Display primary results immediately; defer only identified unsupported companions."""
    def __init__(self, browsers=(), palette=None):
        self.browsers = {str(path): product.capitalize() + ' / ' + profile for path, product, profile in browsers}
        self.palette = palette or Palette()
        self.companions = []
        self.limitations = Counter()

    def __call__(self, file, kind, result):
        from forensic_assistant.artifacts.registry_logs import CLASSIFIER
        if result.get('parser') == CLASSIFIER and result['status'] == 'unsupported' and not result['errors']:
            self.companions.append(str(file))
            return
        label = self.browsers.get(str(file), str(file))
        status = result['status']
        role = 'success' if status == 'complete' else (
            'warning' if status in ('partial', 'unsupported', 'cancelled', 'interrupted') else 'error')
        print('  ' + safe(label) + '   ' + self.palette(
            'success' if result['inserted'] else 'secondary_text', f"{result['inserted']:,} records"))
        if result['duplicates'] or result['errors'] or status != 'complete':
            print('    ' + self.palette(role, safe(status)) + ' | ' +
                  self.palette('warning' if result['duplicates'] else 'secondary_text', f"{result['duplicates']:,} duplicates") + ' | ' +
                  self.palette('error' if result['errors'] else 'secondary_text', f"{result['errors']:,} errors"))
        if result.get('limitation'):
            self.limitations[result['limitation']] += 1

    def finish(self):
        for limitation, count in self.limitations.items():
            print(self.palette('warning', 'Limitation: ' + safe(limitation) + f' ({count} result occurrences)'))
        self.limitations.clear()
        if self.companions:
            print(self.palette('key', 'Skipped companion transaction logs:'))
            for file in self.companions:
                print(self.palette('warning', '  ' + safe(file)))
            print(self.palette('warning', 'Limitation: Registry transaction-log replay is not supported; companion logs were not parsed as hives.'))
            self.companions.clear()


def summarize(target, palette=None):
    palette = palette or Palette()
    with closing(open_existing(target)) as db:
        counts = v2_cli.dispatch(db, SimpleNamespace(command='status'))[0]['artifact_counts']
        runs = {r[0]: r[1] for r in db.execute('SELECT status,count(*) FROM ingestion_runs GROUP BY status')}
        totals = db.execute('SELECT coalesce(sum(inserted_count),0),coalesce(sum(duplicate_count),0),coalesce(sum(error_count),0) FROM ingestion_runs').fetchone()
        evidence_count = sum(counts.values())
        print('Evidence: ' + palette('success' if evidence_count else 'secondary_text', f'{evidence_count:,} records') + ' | ' +
              palette('error' if totals[2] else 'secondary_text', f'{totals[2]:,} errors'))
        if totals[1]:
            print(palette('warning', f'Duplicates: {totals[1]:,}'))
        for status, count in runs.items():
            if status != 'complete':
                print(palette('warning' if status in ('partial', 'unsupported', 'cancelled', 'interrupted') else 'error', f'File outcomes: {count:,} {status} (ingestion attempts)'))
        import json
        from forensic_assistant.ingest.validation import is_identifier_note, LABEL
        notes = sum(any(is_identifier_note(note) for note in json.loads(row[0]))
                    for row in db.execute('SELECT normalization_warnings_json FROM events'))
        if notes:
            print(palette('key', 'Validation notes:') + '\n  ' + palette('warning', LABEL + f': {notes} records'))
        limitations = db.execute(
            'SELECT stage,message,count(*) AS occurrences,count(DISTINCT run_id) AS attempts '
            'FROM ingestion_errors GROUP BY stage,message ORDER BY min(id)').fetchall()
        if limitations:
            print(palette('heading', 'Limitations'))
        for row in limitations:
            print(palette('warning', '- ' + safe(row['stage']) + ': ' + safe(row['message']) +
                          f" — {row['occurrences']:,} occurrence" + ('s' if row['occurrences'] != 1 else '') +
                          f" across {row['attempts']:,} ingestion attempt" + ('s' if row['attempts'] != 1 else '')))
    return sum(counts.values()), runs, totals[2]


_BACK = object()


def create(shell):
    while True:
        result = _attempt(shell)
        if result is not _BACK:
            return result


def _attempt(shell):
    palette = Palette(enabled(shell))
    target = None
    published = False
    initializing = False
    audit_session = audit_token = None
    from forensic_assistant import activity
    def mark_published():
        nonlocal published
        published = True
    def read(prompt):
        return shell.reader.read(palette('prompt', prompt)).strip()
    def path(prompt):
        value = read(prompt)
        if not value or value.casefold() in ('cancel', 'exit', 'quit'):
            raise EOFError
        if value.startswith(('"', "'")):
            from .shell import split
            words = split(value)
            if len(words) != 1:
                raise ValueError('Enter one path')
            value = words[0]
        return value
    def yes(prompt):
        return read(prompt).casefold() in ('y', 'yes')
    try:
        while True:
            try:
                target = destination(path('Case name or path (Enter cancels): '))
                if target.is_dir():
                    raise ValueError('a directory exists at that path. Enter a new case name or file path.')
                if target.exists():
                    validate(target)
                    print('An existing Locard database is at ' + safe(target))
                    if yes('Open it without ingesting? [y/N]: '):
                        shell.activate(target)
                        return True
                    continue
                parents = not target.parent.exists()
                if parents:
                    print('Directory does not exist:\n  ' + safe(target.parent))
                    if not yes('Create this directory at final confirmation? [y/N]: '):
                        continue
                break
            except (ValueError, OSError, sqlite3.Error) as exc:
                print(palette('error', 'Invalid destination: ' + human_error(exc)))
        while True:
            try:
                source = source_path(path('Evidence file or directory: '), target)
                found = preflight(source)
                if found:
                    break
                from forensic_assistant.artifacts.ingest import DISCOVERY_LABELS
                print(palette('warning', 'No supported artifacts found (' + ', '.join(DISCOVERY_LABELS.values()) + ').'))
                choice = read('Choose another source [A], create an empty case [E], or cancel [C]: ').casefold()
                if choice == 'e':
                    break
                if choice != 'a':
                    return False
            except (ValueError, OSError) as exc:
                print(palette('error', 'Invalid evidence source: ' + human_error(exc)))
        browsers = browser_choices(found, read, palette)
        if found:
            print(palette('key', 'Optional source information'))
            source_name = read('Source name [' + safe(target.stem) + ']: ') or target.stem
            hostname = read('Hostname (Enter = unknown): ') or None
            username = read('User (Enter = unknown): ') or None
            from forensic_assistant.artifacts.context import normalize_volume_root
            while True:
                try:
                    volume = normalize_volume_root(read('Original drive, e.g. C: (Enter = unknown): '))
                    break
                except ValueError as exc:
                    print(palette('error', human_error(exc)))
        print(palette('key', 'New case') + '\n  Case: ' + safe(target) + '\n  Evidence: ' + safe(source))
        if found:
            for label, value in [('Source', source_name), ('Hostname', hostname), ('User', username), ('Original drive', volume)]:
                print('  ' + label + ': ' + safe(value or 'unknown'))
        for file, product, profile in browsers:
            print('  Browser: ' + safe(file) + ' | ' + product + ' / ' + safe(profile))
        if parents:
            print('Requested directories will be created and retained even if later steps fail.')
        action = read(('Create empty case' if not found else f'Create case and ingest {len(found)} file' + ('s' if len(found) != 1 else '')) + '? [y/N; B = back]: ').casefold()
        if action == 'b':
            return _BACK
        if action not in ('y', 'yes'):
            return False
        # Revalidate paths after interaction, before any filesystem mutation.
        source_path(source, target)
        initializing = True
        initialize(target, parents, on_publish=mark_published)
        from importlib.metadata import version
        audit_session = activity.Session(target)
        audit_token = activity.CURRENT.set(audit_session)
        audit_session.record('CASE_CREATE', required=True, case_path=str(target), application_version=version('locard-forensics'),
                             evidence_path=str(source), selected_files=len(found),
                             metadata=dict(name=source_name, hostname=hostname, username=username, volume_root=volume) if found else {})
        if not found:
            print('Empty case explicitly requested; no ingestion performed.')
            shell.activate(target, activity_session=audit_session, announce=False)
            print(palette('success', 'Case ready: ' + safe(target)))
            return True
        from forensic_assistant.database import sources
        with closing(open_existing(target)) as db:
            with activity.mutation('SOURCE_CREATE', basis='case creation') as audit_result, db:
                source_id = sources.create(db, name=source_name, hostname=hostname,
                                           username=username, volume_root=volume)
                audit_result.update(source_id=source_id, assertion=sources.current(db, source_id))
        print(palette('key', 'Ingesting evidence...'))
        args = SimpleNamespace(
            command='ingest-all',
            path=source,
            source=source_id,
            hostname=None,
            user=None,
            volume_root=None,
            parser_timeout=300,
            record_size=None
        )
        while True:
            source_path(args.path, target)
            progress = IngestionProgress(browsers, palette)
            try:
                with closing(open_existing(target)) as db:
                    results = []
                    if any(kind != 'browser' for _, kind in found):
                        results.extend(v2_cli.ingest_sources(db, args, progress))
                    for file, product, profile in browsers:
                        options = SimpleNamespace(**{**vars(args), 'command': 'ingest-browser',
                                                    'path': file, 'browser': product, 'profile': profile})
                        results.extend(v2_cli.ingest_sources(db, options, progress))
            finally:
                progress.finish()
            stored, runs, error_count = summarize(target, palette)
            if stored:
                complete = bool(results) and set(runs) == {'complete'} and all(r['status'] == 'complete' for r in results)
                if not complete:
                    has_errors = bool(error_count) or any(status in ('failed', 'changed') for status in runs)
                    outcome = 'errors/limitations' if has_errors else 'limitations'
                    print(palette('warning', 'Ingestion completed with ' + outcome + '; committed evidence retained.'))
                shell.activate(target, activity_session=audit_session, announce=False)
                print(palette('success', 'Case ready: ' + safe(target)))
                return True
            print(palette('warning', 'No evidence records were stored. This is not a successful evidence ingestion.'))
            if not results:
                print('No supported artifacts remained at ingestion time.')
            choice = read('Choose another source [A], activate empty/failed-ingestion case [E], or cancel [C]: ').casefold()
            if choice == 'e':
                shell.activate(target, activity_session=audit_session, announce=False)
                print(palette('success', 'Case ready: ' + safe(target)))
                return True
            if choice != 'a':
                print('Database retained without activation: ' + safe(target))
                return False
            while True:
                try:
                    args.path = source_path(path('Evidence file or directory: '), target)
                    found = preflight(args.path)
                    if found:
                        browsers = browser_choices(found, read, palette)
                        break
                    print('No supported artifacts found; select another source or cancel.')
                except (OSError, ValueError) as exc:
                    print(palette('error', 'Invalid evidence source: ' + human_error(exc)))
            if not yes('Begin ingestion from ' + safe(args.path) + '? [y/N]: '):
                return False
    except (EOFError, KeyboardInterrupt):
        if audit_session:
            audit_session.record('CASE_PREPARATION', 'cancelled')
        print('\nCreation cancelled. Previous active case unchanged.')
        if initializing and parents:
            print('Any analyst-requested directories already created are retained.')
        if published:
            print('Database retained: ' + safe(target) + '. Already committed evidence was not rolled back.')
            summarize(target, palette)
        return False
    except (ValueError, OSError, sqlite3.Error) as exc:
        if audit_session:
            audit_session.record('CASE_PREPARATION', 'failure', **activity.error_data(exc))
        print(palette('error', 'Creation/ingestion failed: ' + human_error(exc)))
        print('Any analyst-requested directories are retained; existing files were not overwritten.')
        if published:
            print('Database retained: ' + safe(target) + '. Already committed evidence was not rolled back.')
            summarize(target, palette)
            try:
                if yes('Open the retained database explicitly? [y/N]: '):
                    shell.activate(target)
                    return True
            except (EOFError, KeyboardInterrupt):
                pass
        return False

    finally:
        if audit_token is not None:
            activity.CURRENT.reset(audit_token)

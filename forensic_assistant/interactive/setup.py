"""Examiner-approved setup plans over the existing initialization/ingestion APIs."""
from collections import Counter
from contextlib import closing
from dataclasses import dataclass, field
from types import SimpleNamespace
import sqlite3

from forensic_assistant import activity, v2_cli
from forensic_assistant.database import sources
from forensic_assistant.interactive import creation, discovery
from forensic_assistant.retrieval.presentation import human_error, safe_text as safe
from forensic_assistant.terminal import Palette, enabled

WORKFLOW = ('Locard workflow\n1. Create a case and ingest evidence\n'
            '2. Investigate in Expert or AI-assisted mode\n3. Generate a report\n'
            'You are starting with step 1.')


@dataclass
class Plan:
    name: str
    identifier: str
    target: object
    parents: bool
    metadata: dict = field(default_factory=dict)
    roots: list = field(default_factory=list)
    items: list = field(default_factory=list)
    browsers: list = field(default_factory=list)


def outside_evidence(target, roots):
    for root in roots:
        root = discovery.input_path(root)
        directory = root if root.is_dir() else root.parent
        if target == root or target.is_relative_to(directory):
            raise ValueError('Case database and generated sidecars must be outside every evidence directory')


def inventory_text(inventory, *, details=False):
    lines = ['Supported artifact candidates found (not yet parsed)']
    for kind in discovery.CATEGORIES:
        items = [i for i in inventory.candidates if i.kind == kind]
        if not items:
            continue
        lines.append('  ' + kind + ': ' + str(len(items)) + ' files')
        groups = Counter(i.group for i in items if i.group)
        lines.extend('    ' + label + ': ' + str(count) for label, count in groups.items())
        if details:
            lines.extend('    ' + safe(i.path) for i in items)
    notes = list(dict.fromkeys(inventory.notes))
    lines.extend('  ' + safe(note) for note in (notes if details else notes[:10]))
    if not details and len(notes) > 10:
        lines.append(f'  {len(notes) - 10} further discovery notes; choose review for details.')
    return '\n'.join(lines)


def select_categories(value, available):
    if value.casefold() in ('', 'all'):
        return set(available)
    selected = {part.strip().casefold() for part in value.split(',')}
    if not selected or not selected <= set(available):
        raise ValueError('Select all or comma-separated detected categories: ' + ','.join(available))
    return selected


def collect(shell):
    palette = Palette(enabled(shell))

    def read(prompt):
        value = shell.reader.read(palette('prompt', prompt)).strip()
        if value.casefold() in ('cancel', 'exit', 'quit'):
            raise EOFError
        if len(value) > 4096 or '\x00' in value:
            raise ValueError('Setup input exceeds bounds or contains NUL')
        return value

    def path(prompt):
        value = read(prompt)
        if not value:
            raise EOFError
        if value.startswith(('"', "'")):
            from .shell import split
            words = split(value)
            if len(words) != 1:
                raise ValueError('Enter one path')
            value = words[0]
        return value

    print(WORKFLOW)
    print('Type cancel at any prompt to stop; nothing is created before final confirmation.')
    name = read('Case name (Enter cancels): ')
    if not name:
        raise EOFError
    while True:
        try:
            target = creation.destination(path('New database path (Enter cancels): '))
            if target.exists():
                raise ValueError('Destination already exists; choose a new file or use case to open it')
            parents = not target.parent.exists()
            if parents:
                print('Directory does not exist:\n  ' + safe(target.parent))
                if read('Create this directory at final confirmation? [y/N]: ').casefold() not in ('y', 'yes'):
                    continue
            break
        except (ValueError, OSError) as exc:
            print(palette('error', human_error(exc)))
    identifier = read('Case identifier (optional): ')
    print('Case name/identifier are analyst labels in the derived activity trail, not evidence.')
    plan = Plan(name, identifier, target, parents)
    print('Optional analyst-supplied source metadata (Enter leaves unknown/generated).')
    metadata = dict(name=read('Source display name (optional): ') or None,
                    hostname=read('Hostname (optional): ') or None,
                    username=read('Username (optional): ') or None,
                    volume_root=read('Original volume root, e.g. C: (optional): ') or None)
    sources.metadata(**metadata)
    plan.metadata = metadata
    while True:
        print('How would you like to add evidence?\n1. Scan a mounted Windows volume or folder (recommended)\n'
              '2. Select artifacts manually\n3. Skip ingestion for now')
        mode = read('Selection [1]: ') or '1'
        inventory = discovery.Inventory()
        roots = []
        try:
            if mode == '1':
                supplied = discovery.input_path(path('Mounted/extracted root or parent folder: '))
                outside_evidence(target, [supplied])
                candidates, notes = discovery.windows_roots(supplied)
                if not candidates:
                    print('No Windows root found within two directory levels; choose a narrower root or manual selection.')
                    continue
                if len(candidates) == 1:
                    root = candidates[0]
                    print('Windows root: ' + safe(root))
                else:
                    print('Multiple Windows roots found; select one (not combined):')
                    for number, candidate in enumerate(candidates, 1):
                        print(f'  {number}. ' + safe(candidate))
                    choice = read('Windows root number: ')
                    if not choice.isdecimal() or not 1 <= int(choice) <= len(candidates):
                        raise ValueError('Choose one listed Windows root')
                    root = candidates[int(choice) - 1]
                inventory = discovery.scan(root)
                inventory.notes[:0] = notes
                roots = [supplied]
            elif mode == '2':
                while True:
                    kind = read('Artifact category [mft,registry,prefetch,evtx,browser; Enter finishes]: ').casefold()
                    if not kind:
                        break
                    source = discovery.input_path(path('Artifact file or folder: '))
                    outside_evidence(target, [source])
                    found = discovery.manual(source, kind)
                    for item in found.candidates:
                        inventory.add(item.path, item.kind, item.group)
                    inventory.notes.extend(found.notes)
                    roots.append(source)
            elif mode == '3':
                break
            else:
                print('Choose 1, 2, or 3.')
                continue
        except (OSError, ValueError) as exc:
            print(palette('error', human_error(exc)))
            continue
        print(inventory_text(inventory))
        if not inventory.candidates:
            print('No supported candidates selected. Choose another source or explicitly skip ingestion.')
            continue
        available = [k for k in discovery.CATEGORIES if any(i.kind == k for i in inventory.candidates)]
        while True:
            selection = read('Artifacts to ingest [all], comma-separated categories, or review: ')
            if selection.casefold() == 'review':
                print(inventory_text(inventory, details=True))
                continue
            try:
                categories = select_categories(selection, available)
                break
            except ValueError as exc:
                print(palette('error', human_error(exc)))
        plan.items = [i for i in inventory.candidates if i.kind in categories]
        plan.roots = roots
        plan.browsers = creation.browser_choices([(i.path, i.kind) for i in plan.items], read, palette)
        break
    print('Proposed ingestion\n  Case: ' + safe(plan.name) + '\n  Database: ' + safe(target))
    print('  Case identifier: ' + safe(identifier or 'not supplied'))
    for key, value in metadata.items():
        print('  ' + key + ' (analyst supplied): ' + safe(value or 'unknown/generated'))
    for root in plan.roots:
        print('  Evidence selection: ' + safe(root))
    print(inventory_text(discovery.Inventory(plan.items)))
    for file, product, profile in plan.browsers:
        print('  Browser: ' + safe(file) + ' | ' + product + ' / ' + safe(profile))
    if not plan.items:
        print('No ingestion: create an empty case.')
    if parents:
        print('Requested directories will be created and retained if subsequent steps fail.')
    if read('Create case and proceed with this plan? [y/N]: ').casefold() not in ('y', 'yes'):
        raise EOFError
    return plan


class Progress:
    def __init__(self):
        self.statuses = Counter()
        self.records = self.duplicates = self.errors = 0
        self.limitations = Counter()

    def __call__(self, path, kind, result):
        self.statuses[result['status']] += 1
        self.records += result['inserted']
        self.duplicates += result['duplicates']
        self.errors += result['errors']
        if result.get('limitation'):
            self.limitations[result['limitation']] += 1

    @property
    def outcome(self):
        if not self.statuses:
            return 'skipped'
        if set(self.statuses) == {'complete'}:
            return 'complete'
        if set(self.statuses) == {'unsupported'}:
            return 'skipped'
        return 'partial' if self.records or self.duplicates or self.statuses['complete'] else 'failed'


def execute(plan, session, palette):
    """Only selected individual files are dispatched; never rescan a whole root."""
    browser_options = {path: (product, profile) for path, product, profile in plan.browsers}
    with closing(creation.open_existing(plan.target)) as db:
        with activity.mutation('SOURCE_CREATE', basis='guided case setup') as event, db:
            source_id = sources.create(db, **plan.metadata)
            event.update(source_id=source_id, assertion=sources.current(db, source_id))
    outcomes = {}
    for kind in discovery.CATEGORIES:
        selected = [i for i in plan.items if i.kind == kind]
        if not selected:
            continue
        progress = Progress()
        print(f'Ingesting {kind}: {len(selected)} selected files...')
        for item in selected:
            try:
                outside_evidence(plan.target, plan.roots)
                source = discovery.input_path(item.path)
                args = SimpleNamespace(command='ingest-' + kind, path=source, source=source_id,
                                       hostname=None, user=None, volume_root=None, parser_timeout=300, record_size=None)
                if kind == 'browser':
                    args.browser, args.profile = browser_options[item.path]
                with closing(creation.open_existing(plan.target)) as db:
                    results = v2_cli.ingest_sources(db, args, progress)
                if not results:
                    progress.statuses['failed'] += 1
                    progress.errors += 1
                    progress.limitations['Selected file produced no ingestion result'] += 1
            except activity.AuditError:
                raise  # Required audit failures stop setup, as in ordinary ingestion.
            except (OSError, ValueError, sqlite3.Error) as exc:
                # Shared pipeline already retains any committed evidence/run state.
                progress.statuses['failed'] += 1
                progress.errors += 1
                progress.limitations[human_error(exc)] += 1
                session.record('SETUP_FILE', 'failure', path=str(item.path), **activity.error_data(exc))
        outcomes[kind] = progress.outcome
        print(palette('success' if progress.outcome == 'complete' else 'warning',
                      f'  {kind}: {progress.outcome} | {progress.records:,} records | '
                      f'{progress.duplicates:,} duplicates | {progress.errors:,} errors'))
        print('    File outcomes: ' + ', '.join(f'{count} {status}' for status, count in progress.statuses.items()))
        for limitation, count in progress.limitations.items():
            print('    ' + safe(limitation) + f' ({count} occurrences)')
    return outcomes


def create(shell):
    palette = Palette(enabled(shell))
    plan = None
    published = False
    session = None

    def mark_published():
        nonlocal published
        published = True

    try:
        plan = collect(shell)
        outside_evidence(plan.target, plan.roots)
        # Recheck all redirects before creating the case or its audit sidecar.
        for item in plan.items:
            discovery.input_path(item.path)
        creation.initialize(plan.target, plan.parents, on_publish=mark_published)
        session = activity.Session(plan.target)
        with activity.bind(session):
            session.record('CASE_CREATE', required=True, case_path=str(plan.target),
                           case_name=plan.name, case_identifier=plan.identifier or None,
                           basis='Analyst-supplied setup labels; derived activity, not evidence',
                           selected_files=len(plan.items), metadata=plan.metadata)
            outcomes = execute(plan, session, palette) if plan.items else {}
            if plan.items:
                stored, runs, errors = creation.summarize(plan.target, palette)
                if not stored:
                    print('Case created, but no evidence records were stored. Ingestion was not successful.')
                    response = shell.reader.read('Activate this empty/failed-ingestion case explicitly? [y/N]: ').strip().casefold()
                    if response not in ('y', 'yes'):
                        print('Database retained without activation: ' + safe(plan.target))
                        return False
            session.record('CASE_SETUP', case_name=plan.name, case_identifier=plan.identifier or None,
                           selected_counts=dict(Counter(i.kind for i in plan.items)), ingestion=outcomes)
        shell.activate(plan.target, activity_session=session, announce=False)
        from .shell import Mode
        shell.mode = Mode.EXPERT
        session.record('SHELL_MODE', mode='EXPERT', basis='Completed guided case setup')
        print(palette('success', 'Case ready.') + '\nCase: ' + safe(plan.name) + '\nDatabase: ' + safe(plan.target))
        for kind, count in Counter(i.kind for i in plan.items).items():
            print(f'  {kind}: {count} selected files — {outcomes[kind]}')
        print('Ingestion: ' + ('Skipped (empty case)' if not outcomes else
              'Complete' if set(outcomes.values()) == {'complete'} else 'Completed with limitations; inspect file outcomes above'))
        print('Next: investigate in Expert mode. Type ai for advisory AI-assisted mode; report generates reports.')
        return True
    except (KeyboardInterrupt, EOFError):
        if session:
            session.record('CASE_PREPARATION', 'cancelled')
        if published and shell.active == plan.target:
            print('\nSetup summary interrupted. The new case remains active.')
            return True
        print('\nSetup cancelled. Previous active case unchanged.')
        return False
    except (OSError, ValueError, sqlite3.Error) as exc:
        if session:
            session.record('CASE_PREPARATION', 'failure', **activity.error_data(exc))
        print(palette('error', 'Setup failed: ' + human_error(exc)))
        return False
    finally:
        if published and shell.active != plan.target:
            print('Database retained: ' + safe(plan.target) + '. Already committed evidence was not rolled back.')
        if plan and plan.parents and not published:
            print('Any analyst-requested directories already created are retained.')
        if session and shell.audit is not session:
            session.end('setup not activated')

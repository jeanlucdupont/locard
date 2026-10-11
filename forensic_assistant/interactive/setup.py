"""Examiner-approved setup plans over the existing initialization/ingestion APIs."""
from collections import Counter
from contextlib import closing
from dataclasses import dataclass, field
from types import SimpleNamespace
import sqlite3

from forensic_assistant import activity, v2_cli
from forensic_assistant.database import sources
from forensic_assistant.interactive import creation, discovery, workspace, setup_display
from forensic_assistant.retrieval.presentation import human_error, safe_text as safe
from forensic_assistant.terminal import Palette, enabled
from forensic_assistant.cli import get_thin

WORKFLOW = (get_thin() + '\nA Locard investigation has three steps:\n  1. Create a case and ingest evidence\n'
            '  2. Investigate in Expert or AI-assisted mode\n  3. Generate a report\n\n'
            'This guided setup will help you complete step 1.')


@dataclass
class Plan:
    name: str
    analyst: str
    organization: str
    target: object
    metadata: dict = field(default_factory=dict)
    roots: list = field(default_factory=list)
    items: list = field(default_factory=list)
    browsers: list = field(default_factory=list)
    deferred: list = field(default_factory=list)
    limited: bool = False
    browser_scanned: bool = False
    browser_found: int = 0


def outside_evidence(target, roots):
    for root in roots:
        root = discovery.input_path(root)
        directory = root if root.is_dir() else root.parent
        if target == root or target.is_relative_to(directory):
            raise ValueError('Case database and generated sidecars must be outside every evidence directory')


def inventory_text(inventory, *, details=False, palette=None):
    palette = palette or Palette()
    print('\n' + get_thin())
    lines = [palette('key', 'Supported artifacts found (contents checked during ingestion)')]
    for kind in discovery.CATEGORIES:
        items = [i for i in inventory.candidates if i.kind == kind]
        if not items:
            continue
        lines.append('  ' + palette('key', kind.ljust(10)) + palette('success', str(len(items))) + ' files')
        groups = Counter(i.group for i in items if i.group)
        lines.extend('    ' + label + ': ' + str(count) for label, count in groups.items())
        if details:
            lines.extend('    ' + safe(i.path) for i in items)
    if inventory.profiles_scanned or inventory.access_limits.get('User profiles') or inventory.redirected.get('User profiles'):
        lines.append(palette('key', 'User profile discovery'))
        if inventory.profiles_scanned:
            lines.append('  Profiles found: ' + str(inventory.profiles_found))
        if inventory.access_limits.get('User profiles'):
            lines.append('  Inaccessible: ' + palette('warning', str(len(inventory.access_limits['User profiles']))))
        if inventory.redirected.get('User profiles'):
            lines.append('  Redirected/junction entries skipped: ' + str(len(inventory.redirected['User profiles'])))
    access = {k: v for k, v in inventory.access_limits.items() if k != 'User profiles'}
    if access:
        lines.append(palette('key', 'Access limitations'))
        lines.extend('  ' + label + ': ' + palette('warning', f'{len(paths)} inaccessible') for label, paths in access.items())
    redirects = {k: v for k, v in inventory.redirected.items() if k != 'User profiles'}
    if redirects:
        lines.append(palette('key', 'Redirected/junction entries skipped'))
        lines.extend('  ' + label + ': ' + str(len(paths)) for label, paths in redirects.items())
    if inventory.unsupported:
        lines.append(palette('key', 'Other forensic artifacts detected'))
        lines.extend('  ' + safe(path if details else path.name) + ' — not currently supported' for path in inventory.unsupported)
    unsupported_notes = {'Not currently supported by Locard: ' + str(p) for p in inventory.unsupported}
    notes = list(dict.fromkeys(n for n in inventory.notes if n not in unsupported_notes and (details or n not in inventory.access_notes)))
    if notes:
        lines.append(palette('key', 'Discovery notes'))
    lines.extend('  ' + palette('warning', safe(note)) for note in (notes if details else notes[:10]))
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


def read_input(shell, palette, prompt, *, required=False):
    while True:
        value = shell.reader.read(palette('prompt', prompt)).strip()
        if value.casefold() == 'cancel':
            raise EOFError
        if len(value) > 4096 or any(c in value for c in '\x00\r\n'):
            raise ValueError('Setup input exceeds bounds or contains control characters')
        if value or not required:
            return value
        print(palette('warning', 'A value is required. Type cancel to stop setup.'))


def choice(read, prompt, allowed, default=None):
    while True:
        value = read(prompt).casefold() or default
        if value in allowed:
            return value
        print('Choose ' + ', '.join(allowed) + '; type cancel to stop setup.')


def access_guidance(read, palette):
    if workspace.elevated() is not False:
        return
    print('\n' + get_thin())
    print(palette('warning', 'Limited access may prevent complete Windows artifact discovery.'))
    print('Administrator privileges are recommended for mounted Windows evidence.\n'
          'Administrator status does not guarantee access to every evidence path.\n'
          '1. Cancel and restart Locard as Administrator\n2. Continue with limited discovery\n3. Cancel setup')
    if choice(read, 'Selection: ', ('1', '2', '3')) != '2':
        raise EOFError


def browser_selection(items, read, palette):
    candidates = [i for i in items if i.kind == 'browser']
    if not candidates:
        return items, []
    print(palette('key', 'Browser profiles found'))
    for n, item in enumerate(candidates, 1):
        print(f'  [{n}] ' + safe(item.browser_product or 'unspecified') + '  ' +
              safe(item.owner or 'owner not supplied') + '  ' + safe(item.profile or item.path.name))
    print('Location labels are not asserted Windows identities. Selection confirms browser/profile context.')
    print('Choose browser profiles to ingest: all, none, or comma-separated numbers.')
    while True:
        value = read('Selection [1]: ' if len(candidates) == 1 else 'Selection (required): ').casefold()
        if not value and len(candidates) == 1:
            value = '1'
        if value == 'none':
            selected = []
            break
        if value == 'all':
            selected = candidates
            break
        try:
            indexes = {int(part.strip()) for part in value.split(',')}
            if not indexes or not indexes <= set(range(1, len(candidates) + 1)):
                raise ValueError
            selected = [item for n, item in enumerate(candidates, 1) if n in indexes]
            break
        except ValueError:
            print(palette('warning', 'Select all, none, or listed profile numbers; multiple profiles have no default.'))
    options = []
    from forensic_assistant.artifacts.browser import validate_options
    for item in selected:
        product, profile = item.browser_product, item.profile
        if not product:
            product = choice(read, 'Browser [chrome/edge]: ', ('chrome', 'edge'))
        while not profile:
            profile = read('Browser profile (required): ')
        validate_options(product, profile)
        options.append((item.path, product, profile))
    return [i for i in items if i.kind != 'browser'] + selected, options


def collect(shell, *, adding=False):
    palette = Palette(enabled(shell))
    def read(prompt, **kwargs):
        return read_input(shell, palette, prompt, **kwargs)
    def path(prompt):
        value = read(prompt, required=True)
        if value.startswith(('"', "'")):
            from .shell import split
            words = split(value)
            if len(words) != 1:
                raise ValueError('Enter one path')
            value = words[0]
        return value
    if adding:
        from .case import validate
        if shell.active is None:
            raise ValueError('No case is currently open.')
        target = validate(shell.active)
        name = shell.case_label or workspace.case_label(target)
        analyst = organization = ''
        print('\n' + get_thin())
        print(palette('key', 'Add evidence to case: ' + safe(name)))
        print('Type cancel at any prompt to return to the case. Nothing is ingested before confirmation.')
    else:
        print(palette('key', WORKFLOW))
        print('Type cancel at any prompt to stop setup.\nNothing is created before final confirmation.\n')
        while True:
            name = read('Case name: ', required=True)
            try:
                target = workspace.target(name)
                break
            except (ValueError, OSError) as exc:
                print(palette('error', human_error(exc)))
        analyst = read('Analyst name (optional): ')
        organization = read('Organization (optional): ')
    plan = Plan(name, analyst, organization, target,
                metadata=dict(name=None, hostname=None, username=None, volume_root=None))
    while True:
        print('\n' + get_thin())
        print(palette('key', 'How would you like to add evidence?'))
        print('1. Scan a mounted Windows volume or folder (recommended)\n'
              '2. Select artifacts manually\n3. ' + ('Cancel' if adding else 'Skip ingestion for now'))
        mode = choice(read, 'Selection [1]: ', ('1', '2', '3'), '1')
        inventory = discovery.Inventory()
        roots = []
        try:
            if mode == '1':
                supplied = discovery.input_path(path('Mounted/extracted root or parent folder: '))
                outside_evidence(target, [supplied])
                access_guidance(read, palette)
                candidates, notes = discovery.windows_roots(supplied)
                if not candidates:
                    print(palette('warning', 'No accessible Windows root found within two directory levels; select a narrower root or use manual selection.'))
                    continue
                root = candidates[0]
                if len(candidates) > 1:
                    print('Multiple Windows roots found; select one (not combined):')
                    for n, candidate in enumerate(candidates, 1):
                        print(f'  {n}. ' + safe(candidate))
                    root = candidates[int(choice(read, 'Windows root number: ', tuple(str(i) for i in range(1, len(candidates) + 1)))) - 1]
                print('Windows root: ' + safe(root))
                inventory = discovery.scan(root)
                plan.browser_scanned = True
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
                    plan.browser_scanned = plan.browser_scanned or kind == 'browser'
                    for item in found.candidates:
                        inventory.add(item.path, item.kind, item.group)
                    inventory.notes.extend(found.notes)
                    inventory.access_notes.update(found.access_notes)
                    for label, paths in found.access_limits.items():
                        inventory.access_limits[label].update(paths)
                    for label, paths in found.redirected.items():
                        inventory.redirected[label].update(paths)
                    roots.append(source)
            else:
                if adding:
                    raise EOFError
                break
        except (OSError, ValueError) as exc:
            print(palette('error', human_error(exc)))
            continue
        plan.browser_found = sum(i.kind == 'browser' for i in inventory.candidates)
        print(inventory_text(inventory, palette=palette))
        if not inventory.candidates:
            print('No supported candidates selected. Choose another source or cancel.' if adding else
                  'No supported candidates selected. Choose another source or explicitly skip ingestion.')
            continue
        available = [k for k in discovery.CATEGORIES if any(i.kind == k for i in inventory.candidates)]
        while True:
            print(palette('key', '\nWhat would you like to do?'))
            print('1. Ingest all discovered artifacts\n2. Select artifact categories\n3. Review discovered paths\n4. Cancel')
            action = choice(read, 'Selection [1]: ', ('1', '2', '3', '4'), '1')
            if action == '4':
                raise EOFError
            if action == '3':
                print(inventory_text(inventory, details=True, palette=palette))
                continue
            if action == '1':
                categories = set(available)
            else:
                print('Available categories:\n  ' + '\n  '.join(available))
                while True:
                    try:
                        categories = select_categories(read('Enter categories separated by commas: ', required=True), available)
                        break
                    except ValueError as exc:
                        print(palette('error', human_error(exc)))
            break
        selected = [i for i in inventory.candidates if i.kind in categories]
        plan.deferred = [i for i in selected if i.access in ('requires extraction', 'unavailable')]
        plan.items, plan.browsers = browser_selection([i for i in selected if i not in plan.deferred], read, palette)
        plan.roots = roots
        plan.limited = bool(inventory.access_limits)
        if plan.items and choice(read, 'Add optional source metadata? [y/N]: ', ('y', 'yes', 'n', 'no'), 'n') in ('y', 'yes'):
            print('Optional analyst-supplied source assertions; no identities are inferred from folder names.')
            plan.metadata.update(name=read('Source display name (optional): ') or None,
                                 hostname=read('Hostname (optional): ') or None,
                                 username=read('Username (optional): ') or None,
                                 volume_root=read('Original volume root, e.g. C: (optional): ') or None)
            sources.metadata(**plan.metadata)
        break
    print('\n' + get_thin())
    if adding:
        print(palette('key', 'Add evidence to case') + '\n  ' + safe(plan.name))
    else:
        print(palette('key', 'Proposed case'))
        print('Case\n  Name: ' + safe(plan.name) + '\n  Analyst: ' + safe(analyst or 'not supplied') +
              '\n  Organization: ' + safe(organization or 'not supplied'))
        print('Workspace\n  ' + safe(target.parent))
    for root in plan.roots:
        print('Evidence source\n  ' + safe(root))
    print(palette('key', 'Selected artifacts'))
    for kind, count in Counter(i.kind for i in plan.items).items():
        print('  ' + palette('key', kind.ljust(10)) + palette('success', str(count)) +
              (' selected profiles' if kind == 'browser' else ' files'))
    for key, value in plan.metadata.items():
        if value:
            print('  ' + key + ' (analyst supplied): ' + safe(value))
    for item in plan.deferred:
        print(palette('key', 'MFT') + '\n  Found: ' + safe(item.path))
        print(palette('error', '  Direct ingestion: unavailable'))
        if item.access == 'requires extraction':
            print(palette('warning', '  Direct access is not possible on this mounted NTFS volume.\n'
                          '  Use a third-party tool to extract $MFT as a standard file, then ingest the extracted file with Locard.'))
        else:
            print(palette('warning', 'File access is unavailable; supply an accessible extracted MFT.'))
    if not plan.items:
        print('No readable evidence selected for ingestion.')
    print('You can add more evidence to this case later using the manual ingest commands.')
    confirmation = 'Add selected evidence to this case? [Y/n]: ' if adding else 'Create case and start ingestion? [Y/n]: '
    if choice(read, confirmation, ('y', 'yes', 'n', 'no'), 'y') not in ('y', 'yes'):
        raise EOFError
    return plan


class Progress:
    def __init__(self):
        self.statuses = Counter()
        self.records = self.duplicates = self.errors = 0
        self.limitations = Counter()
        self.run_ids = set()
        self.retained_partial = self.unsuccessful = 0

    def __call__(self, path, kind, result):
        self.statuses[result['status']] += 1
        if result.get('run_id') is not None:
            self.run_ids.add(result['run_id'])
        if result['status'] == 'partial' and result['inserted'] + result['duplicates']:
            self.retained_partial += 1
        elif result['status'] in ('failed', 'changed') or result['status'] == 'partial':
            self.unsuccessful += 1
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


def execute(plan, session, palette, *, totals=None, basis="guided case setup"):
    """Only selected individual files are dispatched; never rescan a whole root."""
    browser_options = {path: (product, profile) for path, product, profile in plan.browsers}
    with closing(creation.open_existing(plan.target)) as db:
        with activity.mutation('SOURCE_CREATE', basis=basis) as event, db:
            source_id = sources.create(db, **plan.metadata)
            event.update(source_id=source_id, assertion=sources.current(db, source_id))
    outcomes = {i.kind: i.access for i in plan.deferred}
    print('\n' + get_thin())
    print(palette('key', 'Ingestion is starting.'))
    print('Large evidence sets can take several minutes.')
    for kind in discovery.CATEGORIES:
        selected = [i for i in plan.items if i.kind == kind]
        if not selected:
            continue
        progress = Progress()
        def record(path, kind, result):
            progress(path, kind, result)
            if totals is not None:
                totals(path, kind, result)
        meter = setup_display.FileProgress(kind, len(selected), palette)
        meter.update(0, 0)
        try:
            for processed, item in enumerate(selected, 1):
                try:
                    outside_evidence(plan.target, plan.roots)
                    source = discovery.input_path(item.path)
                    args = SimpleNamespace(command='ingest-' + kind, path=source, source=source_id,
                                           hostname=None, user=None, volume_root=None, parser_timeout=300, record_size=None)
                    if kind == 'browser':
                        args.browser, args.profile = browser_options[item.path]
                    with closing(creation.open_existing(plan.target)) as db:
                        results = v2_cli.ingest_sources(db, args, record)
                    if not results:
                        progress.statuses['failed'] += 1
                        progress.errors += 1
                        progress.unsuccessful += 1
                        progress.limitations['Selected file produced no ingestion result'] += 1
                        if totals is not None:
                            totals.statuses['failed'] += 1
                            totals.errors += 1
                except activity.AuditError:
                    raise  # Required audit failures stop setup, as in ordinary ingestion.
                except (OSError, ValueError, sqlite3.Error) as exc:
                    # Shared pipeline already retains any committed evidence/run state.
                    progress.statuses['failed'] += 1
                    progress.errors += 1
                    progress.unsuccessful += 1
                    progress.limitations[human_error(exc)] += 1
                    if totals is not None:
                        totals.statuses['failed'] += 1
                        totals.errors += 1
                    session.record('SETUP_FILE', 'failure', path=str(item.path), **activity.error_data(exc))
                meter.update(processed, progress.records)
        finally:
            # No background reader or progress worker survives cancellation.
            meter.close()
        outcomes[kind] = progress.outcome
        print('  ' + setup_display.category_line(kind, progress, palette))
        print('    ' + setup_display.file_outcomes(progress.statuses, palette))
        if kind == 'evtx':
            print('    Files retaining partial records: ' + palette('warning', str(progress.retained_partial)) +
                  ' | Unsuccessful files (including zero-record partials): ' +
                  palette('error' if progress.unsuccessful else 'success', str(progress.unsuccessful)))
            with closing(creation.open_existing(plan.target)) as db:
                groups = setup_display.diagnostic_groups(db, progress.run_ids)
            limitations = sum(g['count'] for g in groups if g['limitation'])
            other = sum(g['count'] for g in groups if not g['limitation'])
            print('    Verification limitations: ' + palette('forensic_note', str(limitations)) +
                  ' | Other recorded errors: ' + palette('error' if other else 'success', str(other)))
        for limitation, count in progress.limitations.items():
            print('    ' + palette('forensic_note', setup_display.human_limitation(limitation, kind, count)))
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
        workspace.initialize(plan.target, on_publish=mark_published)
        session = activity.Session(plan.target)
        with activity.bind(session):
            session.record('CASE_CREATE', required=True, case_path=str(plan.target),
                           case_name=plan.name, analyst_name=plan.analyst or None, organization=plan.organization or None,
                           basis='Analyst-supplied setup labels; derived activity, not evidence',
                           selected_files=len(plan.items), metadata=plan.metadata,
                           deferred=[dict(path=str(i.path), reason=i.access) for i in plan.deferred],
                           selected_browser_profiles=len(plan.browsers))
            record_browser_selections(plan, session)
            outcomes = execute(plan, session, palette) if plan.items else {i.kind: i.access for i in plan.deferred}
            stored = 0
            if plan.items or plan.deferred:
                stored, runs, errors = creation.summarize(plan.target, palette, wizard=True)
                if not stored:
                    print('Case created, but no evidence records were stored. Review the ingestion outcomes before activation.')
                    response = read_input(shell, palette, 'Activate this empty/failed-ingestion case explicitly? [y/N]: ').casefold()
                    if response not in ('y', 'yes'):
                        print('Database retained without activation: ' + safe(plan.target))
                        return False
            session.record('CASE_SETUP', case_name=plan.name, analyst_name=plan.analyst or None, organization=plan.organization or None,
                           selected_counts=dict(Counter(i.kind for i in plan.items)), ingestion=outcomes)
        shell.activate(plan.target, activity_session=session, announce=False)
        from .shell import Mode
        shell.mode = Mode.EXPERT
        session.record('SHELL_MODE', mode='EXPERT', basis='Completed guided case setup')
        message = setup_display.completion(plan, outcomes, stored)
        print("\n████ " + setup_display.completion_line(message, palette))
        print(palette('key', 'Case') + '\n  ' + safe(plan.name))
        print(palette('key', 'Workspace') + '\n  ' + safe(plan.target.parent))
        ingestion_summary(plan, outcomes, palette)
        print(get_thin() + 'You can add more evidence at any time, or start investigating now.\n\n'
              'To investigate, stay in Expert mode and use Locard commands directly,\n'
              'or type ai to enter AI-assisted mode. In AI mode, prefix natural-language requests with !.')
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
        if plan and not published:
            print('Any case-workspace directories already created are retained.')
        if session and shell.audit is not session:
            session.end('setup not activated')


def record_browser_selections(plan, session):
    owners = {i.path: i.owner for i in plan.items if i.kind == 'browser'}
    for path, product, profile in plan.browsers:
        session.record('BROWSER_SELECTION', required=True, path=str(path), product=product,
                       profile=profile, owner_path_label=owners.get(path),
                       basis='Examiner-selected browser context; owner is a path label, not an identity assertion')


def ingestion_summary(plan, outcomes, palette):
    print(palette('key', 'Ingestion'))
    for kind in discovery.CATEGORIES:
        status = outcomes.get(kind, 'no supported history found' if kind == 'browser' and plan.browser_scanned and not plan.browser_found else 'not selected')
        print('  ' + palette('error' if status == 'requires extraction' else 'key', kind.ljust(10)) + palette(setup_display.role(status), status))
    if plan.browser_scanned and not plan.browser_found:
        print('No supported Chrome or Edge History files were found in the accessible profiles/locations scanned.')


def add_evidence(shell):
    """Append through the shared ingest path; never initialize or activate a case."""
    palette = Palette(enabled(shell))
    confirmed = False
    totals = Progress()
    try:
        if shell.active is None:
            raise ValueError('No case is currently open.')
        plan = collect(shell, adding=True)
        from .case import validate
        if validate(shell.active) != plan.target:
            raise ValueError('The active case changed during evidence selection')
        outside_evidence(plan.target, plan.roots)
        for item in plan.items:
            discovery.input_path(item.path)
        if not plan.items:
            print(palette('warning', 'No evidence was added. No ingestable files were selected.'))
            ingestion_summary(plan, {i.kind: i.access for i in plan.deferred}, palette)
            return False
        if shell.audit is None:
            raise ValueError('No active activity session; reopen the case before adding evidence')
        confirmed = True
        with activity.bind(shell.audit):
            with activity.mutation('ADD_EVIDENCE', selected_files=len(plan.items)) as event:
                record_browser_selections(plan, shell.audit)
                outcomes = execute(plan, shell.audit, palette, totals=totals, basis="guided evidence addition")
                event.update(inserted=totals.records, duplicates=totals.duplicates,
                             errors=totals.errors, ingestion=outcomes)
                if any(value != 'complete' for value in outcomes.values()):
                    event['_outcome'] = 'failure'
        print(setup_display.addition_line(plan, outcomes, totals, palette))
        print(palette('key', 'Case') + '\n  ' + safe(plan.name))
        for root in plan.roots:
            print(palette('key', 'Source') + '\n  ' + safe(root))
        print('This addition: ' + palette('success' if totals.records else 'secondary_text', f'{totals.records:,} new records') +
              ' | ' + palette('warning' if totals.duplicates else 'success', f'{totals.duplicates:,} duplicates') +
              ' | ' + palette('error' if totals.errors else 'success', f'{totals.errors:,} errors'))
        with closing(creation.open_existing(plan.target)) as db:
            setup_display.print_diagnostics(db, palette, run_ids=totals.run_ids)
        ingestion_summary(plan, outcomes, palette)
        print('You can continue investigating the case or add more evidence at any time.')
        return bool(totals.records or totals.duplicates)
    except (EOFError, KeyboardInterrupt):
        print('\nEvidence addition cancelled. The current case remains open.')
        if confirmed:
            print('Already committed evidence and provenance were retained; no rollback is implied.')
        return False
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(palette('error', 'Evidence addition failed: ' + human_error(exc)))
        if confirmed:
            print('Already committed evidence and provenance were retained; no rollback is implied.')
        return False

"""Bounded, read-only setup inventory. Candidates are not validated evidence."""
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict
import os
import stat
from forensic_assistant.ingest.observation import emit

from forensic_assistant.artifacts.ingest import discover
from forensic_assistant.artifacts.registry_logs import is_log
from forensic_assistant.reporting.transcripts import safe_path

CATEGORIES = ('mft', 'registry', 'prefetch', 'evtx', 'browser')
IMAGE_SUFFIXES = {'.e01', '.raw', '.dd', '.img', '.vhd', '.vhdx'}
IMAGE_MESSAGE = ('Locard does not currently mount disk images directly. '
                 'Mount or extract the Windows filesystem, then point the wizard at the mounted/extracted root.')
MAX_ENTRIES = 100000
MAX_ROOT_DIRECTORIES = 256
MAX_MANUAL_DEPTH = 8


@dataclass(frozen=True)
class Candidate:
    path: Path
    kind: str
    group: str = ''
    browser_product: str | None = None
    owner: str | None = None
    profile: str | None = None
    access: str = 'candidate'
    native_volume: str | None = None
    access_reason: str = ''


@dataclass
class Inventory:
    candidates: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    entries: int = 0
    _seen: set = field(default_factory=set, repr=False)
    access_limits: dict = field(default_factory=lambda: defaultdict(set))
    access_notes: set = field(default_factory=set)
    redirected: dict = field(default_factory=lambda: defaultdict(set))
    profiles_found: int = 0
    profiles_scanned: bool = False
    unsupported: list = field(default_factory=list)

    def inaccessible(self, path, category, reason):
        note = 'Directory or file could not be inspected: ' + str(path) + ' (' + reason + ')'
        self.notes.append(note)
        self.access_notes.add(note)
        emit(recoverable_errors=len(self.access_notes))
        self.access_limits[category].add(str(path))

    def redirected_path(self, path, category):
        note = 'Redirected/junction entry skipped: ' + str(path)
        self.notes.append(note)
        self.access_notes.add(note)
        self.redirected[category].add(str(path))
        emit(redirected_entries=sum(len(v) for v in self.redirected.values()))

    def children(self, directory, category='User profiles'):
        """Never follow redirected directories, including Windows junctions."""
        result = []
        emit(current_path=str(directory), phase=category)
        try:
            try:
                safe_path(directory)
            except ValueError:
                self.redirected_path(directory, category)
                return result
            if not stat.S_ISDIR(directory.stat().st_mode):
                return result
            for path in directory.iterdir():
                self.entries += 1
                emit(current_path=str(path), entries_examined=self.entries)
                if self.entries > MAX_ENTRIES:
                    raise ValueError('Discovery entry limit reached; select a narrower evidence folder')
                try:
                    safe_path(path)
                    result.append(path)
                except ValueError:
                    self.redirected_path(path, category)
                except OSError as exc:
                    self.inaccessible(path, category, type(exc).__name__)
        except FileNotFoundError:
            pass
        except OSError as exc:
            self.inaccessible(directory, category, type(exc).__name__)
        return sorted(result, key=lambda p: (p.name.casefold(), p.name))

    def add(self, path, kind, group='', *, browser_product=None, owner=None, profile=None, access='candidate'):
        try:
            safe_path(path)
            if stat.S_ISREG(path.stat().st_mode):
                candidate = Candidate(path, kind, group, browser_product, owner, profile, access)
                if candidate not in self._seen:
                    self._seen.add(candidate)
                    self.candidates.append(candidate)
                    emit(**{kind + "_candidates": sum(c.kind == kind for c in self.candidates)})
        except FileNotFoundError:
            pass
        except ValueError:
            self.redirected_path(path, kind)
        except OSError as exc:
            self.inaccessible(path, kind, type(exc).__name__)


def mounted_mft(path):
    return os.name == 'nt' and path.name.casefold() == '$mft' and path.parent == Path(path.anchor)


def mft_access(path):
    try:
        safe_path(path)
        with path.open('rb') as stream:
            stream.read(4)
        return 'readable'
    except PermissionError:
        return 'requires extraction' if mounted_mft(path) else 'unavailable'
    except OSError:
        return 'unavailable'


def input_path(value):
    from forensic_assistant.artifacts.ntfs_acquisition import mounted_volume
    volume = mounted_volume(value)
    if volume:
        value = volume + '\\'
    path = safe_path(Path(value).absolute())
    if path.suffix.casefold() in IMAGE_SUFFIXES and not path.is_dir():
        raise ValueError(IMAGE_MESSAGE)
    path = path.resolve(strict=True)
    if not path.is_dir() and not path.is_file():
        raise ValueError('Evidence must be a regular file or directory')
    return path


def candidate_path(item):
    """Native candidates validate the mounted root, not normal $MFT access."""
    if item.native_volume:
        input_path(item.native_volume + '\\')
        return item.native_volume
    return input_path(item.path)


def plausible(root):
    try:
        return all(safe_path(root / name).is_dir() for name in
                   ('Windows/System32', 'Windows/System32/config', 'Users'))
    except (OSError, ValueError):
        return False


def windows_roots(path):
    """Check the supplied root, then at most two parent-container levels."""
    root = input_path(path)
    if not root.is_dir():
        raise ValueError('Select a mounted/extracted directory, not an artifact file')
    inventory = Inventory()
    roots = []
    pending = [(root, 0)]
    checked = 0
    while pending:
        directory, depth = pending.pop(0)
        checked += 1
        if checked > MAX_ROOT_DIRECTORIES:
            raise ValueError('Windows-root search limit reached; select a narrower folder')
        if plausible(directory):
            roots.append(directory)
        elif depth < 2:
            pending.extend((p, depth + 1) for p in inventory.children(directory) if p.is_dir())
    return roots, inventory.notes


def scan(root):
    """Known Windows locations only; no full-volume recursive walk or parsing."""
    root = input_path(root)
    inventory = Inventory()
    mft = root / '$MFT'
    from forensic_assistant.artifacts.ntfs_acquisition import mounted_volume, probe, failure_reason
    volume = mounted_volume(root)
    if volume:
        try:
            probe(volume)
            inventory.candidates.append(Candidate(mft, 'mft', access='native read-only NTFS', native_volume=volume))
        except (OSError, ValueError) as exc:
            category, reason = failure_reason(exc)
            inventory.candidates.append(Candidate(mft, 'mft', access='requires extraction', access_reason=reason))
    else:
        inventory.add(mft, 'mft')
    if inventory.candidates and not volume:
        from dataclasses import replace
        inventory.candidates[0] = replace(inventory.candidates[0], access=mft_access(mft))

    def hives(directory, names, group):
        for path in inventory.children(directory, 'Registry paths'):
            if path.name.casefold() in names or (is_log(path) and path.stem.casefold() in names):
                inventory.add(path, 'registry', 'companion' if is_log(path) else group)

    hives(root / 'Windows/System32/config', {'system', 'software', 'sam', 'security'}, 'system hive')
    for directory, suffix, kind in (
        ('Windows/Prefetch', '.pf', 'prefetch'),
        ('Windows/System32/winevt/Logs', '.evtx', 'evtx'),
    ):
        for path in inventory.children(root / directory, kind):
            if path.suffix.casefold() == suffix:
                inventory.add(path, kind)
    inventory.profiles_scanned = True
    for user in inventory.children(root / 'Users'):
        if not user.is_dir():
            continue
        inventory.profiles_found += 1
        emit(user_profiles=inventory.profiles_found)
        hives(user, {'ntuser.dat'}, 'user hive')
        hives(user / 'AppData/Local/Microsoft/Windows', {'usrclass.dat'}, 'user hive')
        for product, relative in (
            ('Chrome', 'AppData/Local/Google/Chrome/User Data'),
            ('Edge', 'AppData/Local/Microsoft/Edge/User Data'),
        ):
            for profile in inventory.children(user / relative, 'Browser paths'):
                if profile.is_dir():
                    inventory.add(profile / 'History', 'browser', product + ' location',
                                  browser_product=product.casefold(), owner=user.name, profile=profile.name)
    for name in ('memory.raw', 'pagefile.sys', 'hiberfil.sys'):
        path = root / name
        try:
            if safe_path(path).is_file():
                inventory.unsupported.append(path)
                inventory.notes.append('Not currently supported by Locard: ' + str(path))
        except (OSError, ValueError):
            inventory.notes.append('Skipped redirected or inaccessible path: ' + str(path))
    return inventory


def manual(path, kind):
    """Bounded folder enumeration with existing single-file discovery semantics."""
    if kind not in CATEGORIES:
        raise ValueError('Choose mft,registry,prefetch,evtx,browser')
    root = input_path(path)
    inventory = Inventory()
    pending = [(root, 0)]
    while pending:
        current, depth = pending.pop()
        safe_path(current)
        if current.is_dir():
            if depth >= MAX_MANUAL_DEPTH:
                raise ValueError('Manual folder depth limit reached; select a narrower folder')
            pending.extend((p, depth + 1) for p in reversed(inventory.children(current)))
        elif current.is_file():
            # An explicitly selected browser file may have been renamed. Folder
            # selection targets History; the existing browser worker validates it.
            if kind == 'browser':
                if current == root or current.name.casefold() == 'history':
                    inventory.add(current, kind)
                continue
            try:
                for file, detected in discover(current, kind):
                    inventory.add(file, detected)
            except ValueError as exc:
                if current == root:
                    raise
                inventory.notes.append('Not selected: ' + str(current) + ' (' + str(exc) + ')')
    return inventory

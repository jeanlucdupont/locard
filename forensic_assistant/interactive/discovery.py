"""Bounded, read-only setup inventory. Candidates are not validated evidence."""
from dataclasses import dataclass, field
from pathlib import Path

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


@dataclass
class Inventory:
    candidates: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    entries: int = 0
    _seen: set = field(default_factory=set, repr=False)

    def children(self, directory):
        """Never follow redirected directories, including Windows junctions."""
        result = []
        try:
            safe_path(directory)
            if not directory.is_dir():
                return result
            for path in directory.iterdir():
                self.entries += 1
                if self.entries > MAX_ENTRIES:
                    raise ValueError('Discovery entry limit reached; select a narrower evidence folder')
                try:
                    safe_path(path)
                    result.append(path)
                except (ValueError, OSError):
                    self.notes.append('Skipped redirected or inaccessible path: ' + str(path))
        except OSError as exc:
            self.notes.append('Directory could not be inspected: ' + str(directory) + ' (' + type(exc).__name__ + ')')
        return sorted(result, key=lambda p: (p.name.casefold(), p.name))

    def add(self, path, kind, group=''):
        try:
            safe_path(path)
            if path.is_file():
                candidate = Candidate(path, kind, group)
                if candidate not in self._seen:
                    self._seen.add(candidate)
                    self.candidates.append(candidate)
        except (ValueError, OSError):
            self.notes.append('Skipped redirected or inaccessible path: ' + str(path))


def input_path(value):
    path = safe_path(Path(value).absolute())
    if path.suffix.casefold() in IMAGE_SUFFIXES and not path.is_dir():
        raise ValueError(IMAGE_MESSAGE)
    path = path.resolve(strict=True)
    if not path.is_dir() and not path.is_file():
        raise ValueError('Evidence must be a regular file or directory')
    return path


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
    inventory.add(root / '$MFT', 'mft')

    def hives(directory, names, group):
        for path in inventory.children(directory):
            if path.name.casefold() in names or (is_log(path) and path.stem.casefold() in names):
                inventory.add(path, 'registry', 'companion' if is_log(path) else group)

    hives(root / 'Windows/System32/config', {'system', 'software', 'sam', 'security'}, 'system hive')
    for directory, suffix, kind in (
        ('Windows/Prefetch', '.pf', 'prefetch'),
        ('Windows/System32/winevt/Logs', '.evtx', 'evtx'),
    ):
        for path in inventory.children(root / directory):
            if path.suffix.casefold() == suffix:
                inventory.add(path, kind)
    for user in inventory.children(root / 'Users'):
        if not user.is_dir():
            continue
        hives(user, {'ntuser.dat'}, 'user hive')
        hives(user / 'AppData/Local/Microsoft/Windows', {'usrclass.dat'}, 'user hive')
        for product, relative in (
            ('Chrome', 'AppData/Local/Google/Chrome/User Data'),
            ('Edge', 'AppData/Local/Microsoft/Edge/User Data'),
        ):
            for profile in inventory.children(user / relative):
                if profile.is_dir():
                    inventory.add(profile / 'History', 'browser', product + ' location')
    for name in ('memory.raw', 'pagefile.sys', 'hiberfil.sys'):
        path = root / name
        try:
            if safe_path(path).is_file():
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

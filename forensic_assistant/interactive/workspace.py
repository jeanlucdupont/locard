"""Analyst workspace naming and publication; original evidence is never copied."""
from pathlib import Path
import re
import unicodedata

from .state import state_path
from . import creation
from forensic_assistant.reporting.transcripts import safe_path


def cases_root():
    return safe_path(state_path().parent / 'cases')


def sanitize(name):
    name = unicodedata.normalize('NFC', name.strip())
    # A standalone separator is not part of an incident identifier.
    name = re.sub(r'\s+-\s+', '_', name)
    name = ''.join(c if c.isalnum() or c in '-_' else '_' for c in name)
    name = re.sub('_+', '_', name).strip('_')
    if not name or not any(c.isalnum() for c in name):
        raise ValueError('Enter a case name containing letters or numbers')
    if re.fullmatch(r'CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³]', name, re.I):
        name += '_case'
    if len(name) > 100:
        raise ValueError('Use a shorter case name (at most 100 sanitized characters)')
    return name


def target(name):
    folder = safe_path(cases_root() / sanitize(name))
    if folder.exists():
        raise ValueError(f'A case named "{name}" already exists. Choose a different case name, or open the existing case.')
    return creation.destination(folder / 'case.db')


def initialize(path, *, on_publish=None):
    """Reserve the workspace exclusively after confirmation; never reuse a rival."""
    path = creation.destination(path)
    folder = safe_path(path.parent)
    safe_path(folder.parent).mkdir(parents=True, exist_ok=True)
    safe_path(folder).mkdir()  # Atomic exclusive reservation, including empty rivals.
    for name in ('reports', 'exports', 'workspace'):
        safe_path(folder / name).mkdir()
    return creation.initialize(path, on_publish=on_publish)


def elevated():
    """Read token status only. Never elevate, relaunch, or request credentials."""
    import os
    if os.name != 'nt':
        return None
    import ctypes
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def case_label(path):
    """Read the creation label for UI only; this is not an audit-integrity verdict.

    Guided creation writes CASE_CREATE first. Bound the historical prefix lookup,
    reuse entry validation, and fall back safely for absent/damaged old sidecars.
    """
    from forensic_assistant import activity
    import io
    fallback = path.name
    try:
        if path.name.casefold() == 'case.db' and path.parent.parent == cases_root():
            fallback = path.parent.name
    except (OSError, ValueError):
        pass
    try:
        with activity.locked(activity.sidecar(path)) as raw:
            stream = io.BufferedReader(raw)
            try:
                previous = None
                for sequence in range(1, 65):
                    line = stream.readline(activity.MAX_ENTRY + 1)
                    if not line:
                        break
                    entry = activity.decode(line)
                    if entry['sequence'] != sequence or entry['previous_entry_hash'] != previous:
                        break
                    previous = entry['entry_hash']
                    name = entry.get('case_name')
                    if entry['action'] == 'CASE_CREATE' and entry['outcome'] == 'success' and isinstance(name, str) and name.strip():
                        return name[:4096]
            finally:
                stream.detach()
    except (OSError, ValueError):
        pass
    return fallback

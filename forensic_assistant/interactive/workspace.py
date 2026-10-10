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
        raise ValueError('Case workspace already exists; choose another case name')
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

"""Analyst workspace naming and publication; original evidence is never copied."""
from pathlib import Path

from . import creation
from forensic_assistant.reporting.transcripts import safe_path


def cases_root():
    from forensic_assistant.case_management import root
    return root()


def sanitize(value):
    # Names are identifiers, never silently transformed into a different name.
    from forensic_assistant.case_management import name
    return name(value)


def target(name):
    folder = safe_path(cases_root() / sanitize(name))
    if folder.exists() or (folder.parent.exists() and any(p.name.casefold() == folder.name.casefold() for p in folder.parent.iterdir())):
        raise ValueError(f'CASE_NAME_EXISTS: A case named "{name}" already exists. Choose a different case name, or open the existing case.')
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
        if path.name.casefold() == 'case.db':
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


def create_empty(shell, name=None):
    """Confirm a case workspace independently of evidence discovery/ingestion."""
    from forensic_assistant import activity, __version__
    from .console import safe
    from forensic_assistant.briefing_workflow import read_answer
    read=lambda prompt: read_answer(shell.reader.read,prompt).strip()
    name=name if name is not None else read_answer(shell.reader.read, 'Case name: ')
    path=target(name)
    analyst=read('Analyst name (optional): ')
    organization=read('Organization (optional): ')
    print('Create empty case: '+safe(name)+'\nDatabase: '+safe(path))
    if read('Create this case? [y/N]: ').casefold() not in ('y','yes'):
        return False
    from forensic_assistant.case_management import create
    path=create(name, expected_path=path)
    session=activity.Session(path)
    session.record('CASE_CREATE',required=True,case_path=str(path),case_name=name,
                   analyst=analyst,organization=organization,application_version=__version__,selected_files=0)
    shell.activate(path,activity_session=session)
    print('Use evidence ingest wizard to add evidence.')
    return True

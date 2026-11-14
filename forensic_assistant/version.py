"""Resolve the executing source release, or conventional distribution metadata."""
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import re
import tomllib


def resolve(package_file=__file__, *, metadata_version=version):
    """Only inspect the package's immediate project root, never the caller's cwd.

    Git checkout markers or Locard's launcher identify a checkout even if its
    authoritative TOML is missing/damaged. An unpacked source tree may instead
    identify itself with matching project and console-entry-point metadata.
    """
    root = Path(package_file).resolve().parent.parent
    project_file = root / 'pyproject.toml'
    checkout = (root / '.git').exists() or (root / 'locard.ps1').is_file()
    project = None
    if project_file.is_file():
        try:
            project = tomllib.loads(project_file.read_text(encoding='utf-8')).get('project', {})
        except (OSError, ValueError) as exc:
            if checkout:
                raise RuntimeError('Locard source version unavailable: cannot read valid pyproject.toml') from exc
        if isinstance(project, dict) and project.get('name') == 'locard-forensics':
            checkout = True
    source = None
    if checkout:
        if not isinstance(project, dict) or project.get('name') != 'locard-forensics':
            raise RuntimeError('Locard source version unavailable: missing or incorrect project identity in pyproject.toml')
        scripts = project.get('scripts')
        if not isinstance(scripts, dict) or scripts.get('locard') != 'forensic_assistant.cli:main':
            raise RuntimeError('Locard source version unavailable: incorrect Locard entry point in pyproject.toml')
        source = project.get('version')
        if not isinstance(source, str) or re.fullmatch(r'[0-9]+\.[0-9]+', source) is None:
            raise RuntimeError('Locard source version unavailable: pyproject.toml requires a MAJOR.RELEASE version')
    try:
        installed = metadata_version('locard-forensics')
    except PackageNotFoundError:
        installed = None
    if not checkout and installed is None:
        raise RuntimeError('Locard version unavailable: no source checkout or installed distribution metadata')
    return dict(application_version=source if checkout else installed,
                execution='source checkout' if checkout else 'installed distribution',
                source_version=source, installed_metadata_version=installed,
                metadata_mismatch=bool(source is not None and installed is not None and source != installed))

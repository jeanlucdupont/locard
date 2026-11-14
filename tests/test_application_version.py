"""Effective source version is independent of stale editable metadata."""
from importlib.metadata import PackageNotFoundError
import json
from pathlib import Path
import subprocess
import sys
import tomllib
import pytest
from forensic_assistant import __version__
from forensic_assistant.cli import main
from forensic_assistant.version import resolve

ROOT = Path(__file__).resolve().parents[1]


def layout(tmp_path, content=None):
    package = tmp_path / 'forensic_assistant'
    package.mkdir()
    path = package / '__init__.py'
    path.write_text('')
    if content is not None:
        (tmp_path / 'pyproject.toml').write_text(content)
    return path


def project(release):
    return '[project]\nname="locard-forensics"\nversion="'+release+'"\n[project.scripts]\nlocard="forensic_assistant.cli:main"\n'


def test_current_version_metadata_and_cli(capsys):
    project = tomllib.loads((Path(__file__).resolve().parents[1] / 'pyproject.toml').read_text())
    expected = project['project']['version']
    assert __version__ == expected
    with pytest.raises(SystemExit) as exc:
        main(['--version'])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == 'Locard ' + expected


@pytest.mark.parametrize('installed', ['1.1', '99.99', None])
def test_source_version_ignores_stale_or_absent_metadata(tmp_path, monkeypatch, installed):
    path = layout(tmp_path, project('7.42'))
    def metadata(name):
        assert name == 'locard-forensics'
        if installed is None: raise PackageNotFoundError(name)
        return installed
    monkeypatch.chdir(tmp_path.parent)
    value = resolve(path, metadata_version=metadata)
    assert value == dict(application_version='7.42', execution='source checkout', source_version='7.42',
                         installed_metadata_version=installed, metadata_mismatch=installed is not None)


def test_installed_fallback_does_not_read_cwd(tmp_path, monkeypatch):
    path = layout(tmp_path)
    unrelated = tmp_path / 'unrelated'
    unrelated.mkdir()
    (unrelated / 'pyproject.toml').write_text(project('99.1'))
    monkeypatch.chdir(unrelated)
    value = resolve(path, metadata_version=lambda name: '7.1')
    assert value['application_version'] == '7.1'
    assert value['execution'] == 'installed distribution' and value['source_version'] is None


@pytest.mark.parametrize('content', [None, 'not valid toml', '[project]\nname="other"',
    '[project]\nname="locard-forensics"\n[project.scripts]\nlocard="forensic_assistant.cli:main"',
    project('7.1.2'), project(''), project('7.2').replace('forensic_assistant.cli:main', 'other:main')])
def test_identified_checkout_fails_closed(tmp_path, content):
    path = layout(tmp_path, content)
    (tmp_path / '.git').write_text('gitdir: worktree')
    with pytest.raises(RuntimeError, match='Locard source version unavailable'):
        resolve(path, metadata_version=lambda name: pytest.fail('stale fallback'))


def test_version_details(capsys):
    with pytest.raises(SystemExit) as exc:
        main(['--version-details'])
    assert exc.value.code == 0
    value = json.loads(capsys.readouterr().out)
    assert value['application_version'] == value['source_version'] == __version__
    assert value['execution'] == 'source checkout'


@pytest.mark.parametrize('launcher', ['script', 'module', 'console'])
def test_launchers_from_external_directory(tmp_path, launcher):
    commands = {'script': [sys.executable, str(ROOT / 'locard.py')],
                'module': [sys.executable, '-m', 'forensic_assistant.cli'],
                'console': [str(Path(sys.executable).parent / ('locard.exe' if sys.platform == 'win32' else 'locard'))]}
    result = subprocess.run(commands[launcher] + ['--version'], cwd=tmp_path, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'Locard ' + __version__


def test_new_producer_versions():
    from forensic_assistant.investigation_ai.transcript import implementation
    from forensic_assistant.reporting import recorded, bundle
    assert implementation()['application_version'] == __version__
    assert recorded.__version__ == bundle.__version__ == __version__


def test_resolution_starts_no_process_or_network(monkeypatch):
    import socket
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **k: pytest.fail('process started'))
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('DNS'))
    monkeypatch.setattr(socket.socket, 'connect', lambda *a, **k: pytest.fail('network'))
    assert resolve()['application_version'] == __version__


def test_pull_only_version_change_in_disposable_checkout(tmp_path):
    path = layout(tmp_path, project('7.1'))
    metadata = lambda name: '7.1'
    assert resolve(path, metadata_version=metadata)['application_version'] == '7.1'
    (tmp_path / 'pyproject.toml').write_text(project('7.2'))
    value = resolve(path, metadata_version=metadata)
    assert value['application_version'] == '7.2' and value['metadata_mismatch']


def test_launcher_delegates_without_arguments(monkeypatch):
    import runpy
    calls = []
    monkeypatch.setattr('forensic_assistant.cli.main', lambda: calls.append('main') or 0)
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(ROOT/'locard.py'), run_name='__main__')
    assert exc.value.code == 0 and calls == ['main']

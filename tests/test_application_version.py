"""The installed package version is built from project metadata."""
from importlib.metadata import version
from pathlib import Path
import tomllib
from forensic_assistant import __version__
from forensic_assistant.cli import main


def test_current_version_metadata_and_cli(capsys):
    import pytest
    project = tomllib.loads((Path(__file__).resolve().parents[1] / 'pyproject.toml').read_text())
    expected = version('locard-forensics')
    assert __version__ == expected == project['project']['version']
    with pytest.raises(SystemExit) as exc:
        main(['--version'])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == 'Locard ' + expected

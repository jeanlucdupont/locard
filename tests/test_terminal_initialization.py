"""Windows capability checks are mocked; no provider or evidence access."""
import ctypes
import io
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from forensic_assistant import terminal, cli


class Stream(io.StringIO):
    def isatty(self): return True
    def fileno(self): return 1


@pytest.mark.skipif(os.name != 'nt', reason='Windows API adapter')
@pytest.mark.parametrize('initial,read_ok,write_ok,expected,writes', [
    (3, True, True, True, [7]), (7, True, True, True, []),
    (3, False, True, False, []), (3, True, False, False, [7])])
def test_windows_mode_preserves_flags(monkeypatch, initial, read_ok, write_ok, expected, writes):
    import msvcrt
    state = [initial]
    seen = []
    class Function:
        def __init__(self, fn): self.fn = fn
        def __call__(self, *a): return self.fn(*a)
    def get(handle, pointer):
        pointer._obj.value = state[0]
        return read_ok
    def put(handle, value):
        seen.append(value)
        if write_ok: state[0] = value
        return write_ok
    kernel = SimpleNamespace(GetConsoleMode=Function(get), SetConsoleMode=Function(put))
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **k: kernel)
    monkeypatch.setattr(msvcrt, 'get_osfhandle', lambda fd: 123)
    assert terminal.windows_ansi(Stream(), enable=True) == expected
    assert seen == writes
    if expected:
        assert terminal.windows_ansi(Stream(), enable=True)
        assert seen == writes  # Already enabled: no repeated mutation.


@pytest.mark.skipif(os.name != 'nt', reason='Windows initialization')
def test_each_handle_and_failed_initialization(monkeypatch):
    out, err = Stream(), Stream()
    monkeypatch.setattr(sys, 'stdout', out)
    monkeypatch.setattr(sys, 'stderr', err)
    seen = []
    def initialize(stream, **kw):
        seen.append(stream)
        if stream is out: raise OSError('unsupported')
        return True
    monkeypatch.setattr(terminal, 'windows_ansi', initialize)
    monkeypatch.delenv('TERM', raising=False)
    terminal.initialize()
    assert seen == [out, err]
    seen.clear()
    monkeypatch.setattr(sys, 'stdout', io.StringIO())
    terminal.initialize()
    assert seen == [err]


@pytest.mark.parametrize('capable,no_color', [(True, False), (False, False), (True, True)])
def test_resources_and_prompt_preserve_text(monkeypatch, capable, no_color):
    monkeypatch.setattr(terminal, 'capable', lambda stream: capable)
    monkeypatch.delenv('NO_COLOR', raising=False)
    args = SimpleNamespace(no_color=no_color)
    for name, getter in [('banner', cli.get_banner), ('liner', cli.get_liner), ('thin', cli.get_thin), ('ender', cli.get_ender)]:
        raw = (Path(cli.__file__).parent/'resources'/f'{name}.txt').read_text(encoding='utf-8')
        rendered = terminal.banner(getter(), args) if name == 'banner' else getter(args)
        assert terminal.SGR.sub('', rendered) == terminal.SGR.sub('', raw)
        assert ('\x1b' in rendered) == (capable and not no_color)
    prompt = terminal.Palette(terminal.enabled(args))('prompt', '[synthetic]> ')
    assert terminal.SGR.sub('', prompt) == '[synthetic]> '
    assert ('\x1b' in prompt) == (capable and not no_color)


def test_redirected_error_and_no_color(monkeypatch):
    monkeypatch.setattr(sys, 'stderr', io.StringIO())
    terminal.message('Example error')
    assert sys.stderr.getvalue() == 'Example error\n'
    monkeypatch.setattr(terminal, 'capable', lambda stream: True)
    monkeypatch.setenv('NO_COLOR', '')
    assert '\x1b' not in cli.get_ender()


def test_common_entry_initializes_before_dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr(terminal, 'initialize', lambda: calls.append('initialize'))
    monkeypatch.setattr(cli, '_main', lambda args: calls.append('main') or 0)
    assert cli.main(['--version']) == 0
    assert calls == ['initialize', 'main']


@pytest.mark.parametrize('supported', [True, False])
def test_interactive_entry_banner_after_initialization(monkeypatch, supported):
    out = Stream()
    state = {'ready': False}
    monkeypatch.setattr(sys, 'stdout', out)
    monkeypatch.setattr(sys, 'stdin', Stream())
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setattr(terminal, 'initialize', lambda: state.update(ready=supported))
    monkeypatch.setattr(terminal, 'capable', lambda stream: state['ready'])
    monkeypatch.setattr('forensic_assistant.interactive.shell.run', lambda **kw: 0)
    assert cli.main([]) == 0
    text = out.getvalue()
    assert terminal.SGR.sub('', text) == terminal.SGR.sub('', cli.get_banner()) + '\n'
    assert ('\x1b' in text) == supported


@pytest.mark.parametrize('launcher', ['direct', 'module', 'console', 'powershell', 'pwsh'])
def test_redirected_launchers(launcher, tmp_path):
    import shutil
    root = Path(cli.__file__).resolve().parent.parent
    commands = {'direct': [sys.executable, str(root/'locard.py')],
                'module': [sys.executable, '-m', 'forensic_assistant.cli'],
                'console': [str(Path(sys.executable).parent/'locard.exe')]}
    if launcher in ('powershell', 'pwsh'):
        executable = shutil.which(launcher)
        if not executable: pytest.skip('Shell unavailable')
        commands[launcher] = [executable, '-NoProfile', '-File', str(root/'locard.ps1')]
    result = subprocess.run(commands[launcher]+['--version'], capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert b'Locard ' in result.stdout and b'\x1b' not in result.stdout + result.stderr

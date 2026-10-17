import time
import pytest

from forensic_assistant import terminal_activity as ui
from forensic_assistant.interactive import advisory, setup, discovery
from test_terminal_activity import terminal, wait_for
from test_ai_shell import model, run_shell
from test_guided_setup import tree, prefix, managed_root
from test_interactive_shell import Input
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from test_dump import mixed, mixed_template, export


@pytest.mark.parametrize('failure', [None, advisory.AdvisoryError('AI timeout'), KeyboardInterrupt()])
def test_advisory_wait_clears_before_output(tmp_path, monkeypatch, terminal, model, capsys, failure):
    original = advisory.advise
    indicators = []
    base = ui.ActivityIndicator
    class Indicator(base):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw, delay=0)
            indicators.append(self)
    monkeypatch.setattr(ui, 'ActivityIndicator', Indicator)
    def advise(*args):
        wait_for(lambda: 'Waiting for local AI...' in terminal.getvalue())
        if failure:
            raise failure
        return original(*args)
    monkeypatch.setattr(advisory, 'advise', advise)
    from forensic_assistant.interactive import advisory_display
    render = advisory_display.render
    def checked_render(*args):
        assert indicators[-1]._thread is None
        assert terminal.getvalue().endswith('\r\x1b[K')
        return render(*args)
    monkeypatch.setattr(advisory_display, 'render', checked_render)
    run_shell(tmp_path, '! Explain how to investigate execution')
    assert indicators[-1]._thread is None
    assert terminal.getvalue().endswith('\r\x1b[K')


def test_fast_inventory_has_no_model_wait_flicker(tmp_path, monkeypatch, terminal, model):
    # A long internal delay makes this independent of filesystem timing.
    base = ui.ActivityIndicator
    monkeypatch.setattr(ui, 'ActivityIndicator', lambda *a, **kw: base(*a, **kw, delay=10))
    run_shell(tmp_path, '! ' + next(iter(advisory.INVENTORY_QUESTIONS)))
    assert not model and not terminal.getvalue()


@pytest.mark.parametrize('cancel', [False, True])
def test_discovery_activity_stops_before_next_prompt(tmp_path, monkeypatch, terminal, cancel):
    root = tree(tmp_path / 'evidence')
    target = tmp_path / 'cases/Synthetic_case/case.db'
    base = ui.ActivityIndicator
    monkeypatch.setattr(setup, 'ActivityIndicator', lambda *a, **kw: base(*a, **kw, delay=0))
    original = discovery.windows_roots
    def discover(*a):
        wait_for(lambda: 'Discovering evidence...' in terminal.getvalue())
        if cancel:
            raise KeyboardInterrupt()
        return original(*a)
    monkeypatch.setattr(discovery, 'windows_roots', discover)
    class Reader(Input):
        def read(self, *a, **kw):
            if 'Discovering evidence...' in terminal.getvalue():
                assert terminal.getvalue().endswith('\r\x1b[K')
            return super().read(*a, **kw)
    shell = Shell(State(None), Reader(*prefix(target), '1', str(root), 'cancel'))
    if cancel:
        with pytest.raises(KeyboardInterrupt):
            setup.collect(shell)
    else:
        with pytest.raises(EOFError):
            setup.collect(shell)
    assert terminal.getvalue().endswith('\r\x1b[K')


def test_real_dump_preserves_csv_and_updates_only_artifacts(mixed, monkeypatch, terminal):
    # Disable animation for the reference export, then run the real dump again.
    base = ui.ActivityIndicator
    monkeypatch.setattr(ui, 'ActivityIndicator', lambda *a, **kw: base(*a, **kw, stream=__import__('io').StringIO()))
    export(mixed)
    before = {p.name: p.read_bytes() for p in (mixed.parent / 'dump').glob('*.csv')}
    database = mixed.read_bytes()
    labels = []
    class Indicator(base):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw, delay=0)
        def update(self, text):
            labels.append(text)
            super().update(text)
    monkeypatch.setattr(ui, 'ActivityIndicator', Indicator)
    output = export(mixed, force=True)
    assert labels == ['Dumping ' + k + '...' for k in ('browser', 'evtx', 'mft', 'prefetch', 'registry')]
    assert before == {p.name: p.read_bytes() for p in (mixed.parent / 'dump').glob('*.csv')}
    assert database == mixed.read_bytes()
    assert output.count('Dump created:') == 5 and 'Total elapsed time:' in output
    assert 'Dumping ' not in output


def test_discovery_and_file_progress_never_overlap(tmp_path, monkeypatch):
    from forensic_assistant.interactive import setup_display
    root = tree(tmp_path / 'evidence')
    busy = []
    class Indicator:
        def __init__(self, text, **kw):
            assert text == 'Discovering evidence...'
        def __enter__(self):
            busy.append(True)
        def __exit__(self, *exc):
            busy.pop()
    monkeypatch.setattr(setup, 'ActivityIndicator', Indicator)
    meter = setup_display.FileProgress.update
    progress = []
    def checked(self, files, records):
        assert not busy
        progress.append((files, records))
        return meter(self, files, records)
    monkeypatch.setattr(setup_display.FileProgress, 'update', checked)
    target = tmp_path / 'cases/Synthetic_case/case.db'
    shell = Shell(State(None), Input(*prefix(target), '2', 'registry',
        str(root / 'Windows/System32/config/SYSTEM'), '', 'n', 'yes'))
    assert setup.create(shell)
    assert progress[0] == (0, 0) and progress[-1][0] == 1 and progress[-1][1] > 0


def test_investigation_json_remains_pure_with_terminal_available(tmp_path, monkeypatch, terminal, capsys):
    import json
    from forensic_assistant.cli import main
    from forensic_assistant.investigation_ai import cli
    from test_interactive_shell import case
    path = case(tmp_path)
    def run(*a, status, **kw):
        status('model')
        time.sleep(.35)
        return {'termination': 'USER_SCOPE_REACHED', 'derived_data': True}
    monkeypatch.setattr(cli, 'run', run)
    assert main(['--db', str(path), 'investigate-ai', '--json', '--dry-run', 'Inspect']) == 0
    assert json.loads(capsys.readouterr().out) == {'termination': 'USER_SCOPE_REACHED', 'derived_data': True}
    assert not terminal.getvalue()

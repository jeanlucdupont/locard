"""Activity is terminal-only, presentation-only and bounded independently of work."""
import io
import logging
import os
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from forensic_assistant import terminal_activity as ui


class Terminal(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def terminal(monkeypatch):
    stream = Terminal()
    monkeypatch.setattr(ui, 'sys', SimpleNamespace(stdin=Terminal(), stdout=stream))
    monkeypatch.setattr(ui, 'capable', lambda stream: stream.isatty())
    monkeypatch.setattr('forensic_assistant.terminal.capable', lambda stream: stream.isatty())
    return stream


def wait_for(predicate):
    deadline = time.monotonic() + 2
    while not predicate():
        assert time.monotonic() < deadline
        time.sleep(.005)


def test_delay_fast_operation_and_lifecycle(terminal):
    with ui.ActivityIndicator('Fast', delay=10) as indicator:
        assert indicator._thread.is_alive()
        assert not terminal.getvalue()
    assert not terminal.getvalue() and indicator._thread is None
    indicator.stop()
    with indicator:
        assert indicator._thread.is_alive()
    assert not any(t.name == 'Locard terminal activity' for t in threading.enumerate())


def test_frames_updates_width_clear_and_rate(terminal, monkeypatch):
    monkeypatch.setattr(ui.shutil, 'get_terminal_size', lambda **kw: os.terminal_size((20, 24)))
    with ui.ActivityIndicator('A very long phase description', args=SimpleNamespace(no_color=True),
                              delay=.01, interval=.02) as indicator:
        wait_for(lambda: ui.FRAMES[-1] in terminal.getvalue())
        indicator.update('Short')
        wait_for(lambda: 'Short' in terminal.getvalue())
        assert 'A very long phas…' in terminal.getvalue()
        assert len(terminal.getvalue().split('\r')) < 60  # timer, not a busy loop
    assert terminal.getvalue().endswith('\r\x1b[K')
    frames = terminal.getvalue().split('\r\x1b[K')[1:]
    assert ''.join(frame[0] for frame in frames[:10]) == ui.FRAMES
    assert all(len(frame) <= 19 for frame in frames)
    assert '\n' not in terminal.getvalue() and '\x1b[36m' not in terminal.getvalue()


@pytest.mark.parametrize('failure', [RuntimeError, TimeoutError, KeyboardInterrupt])
def test_exception_always_clears(terminal, failure):
    with pytest.raises(failure):
        with ui.ActivityIndicator('Work', delay=0) as indicator:
            wait_for(lambda: bool(terminal.getvalue()))
            raise failure()
    assert indicator._thread is None
    assert terminal.getvalue().endswith('\r\x1b[K')


@pytest.mark.parametrize('option', ['json', 'output_file', 'append_file', 'page'])
def test_machine_paths_disabled(terminal, option):
    with ui.ActivityIndicator('Work', args=SimpleNamespace(**{option: True}), delay=0) as indicator:
        assert not indicator.active and indicator._thread is None
    assert not terminal.getvalue()


def test_redirected_and_debug_disabled(terminal, caplog):
    redirected = io.StringIO()
    with ui.ActivityIndicator('Work', stream=redirected, delay=0) as indicator:
        assert not indicator.active
    with caplog.at_level(logging.DEBUG, logger='forensic_assistant.investigation_ai'):
        with ui.ActivityIndicator('Work', delay=0) as indicator:
            assert not indicator.active
            logging.getLogger('forensic_assistant.investigation_ai').debug('Readable diagnostic')
    assert caplog.messages == ['Readable diagnostic']
    assert not terminal.getvalue() and not redirected.getvalue()


def test_approval_stops_and_operation_resumes(terminal):
    with ui.ActivityIndicator('Preparing', delay=0) as indicator:
        wait_for(lambda: bool(terminal.getvalue()))
        indicator.phase('approval')
        before = terminal.getvalue()
        assert indicator._thread is None
        time.sleep(.03)
        assert terminal.getvalue() == before
        indicator.phase('operation')
        wait_for(lambda: 'Running read-only operation...' in terminal.getvalue())
        indicator.phase('model-controlled text')
        indicator.phase({'untrusted': 'value'})
        assert indicator.text == ui.PHASES['operation']


def test_dump_adapter_updates_per_artifact_preserves_static_summary(terminal):
    from test_dump import Output
    output = Output()
    with ui.ActivityIndicator(delay=0) as indicator:
        adapter = ui.ActivityOutput(output, indicator)
        adapter.write('Dumping registry...')
        wait_for(lambda: 'Dumping registry...' in terminal.getvalue())
        adapter.write('Dumping mft...')
        wait_for(lambda: 'Dumping mft...' in terminal.getvalue())
        adapter.write('Dump created: registry.csv — 825,888 rows')
        assert indicator._thread is None
    assert output.lines == ['Dump created: registry.csv — 825,888 rows']


def test_dump_adapter_noninteractive_exact_text():
    from test_dump import Output
    output = Output()
    with ui.ActivityIndicator(stream=io.StringIO()) as indicator:
        adapter = ui.ActivityOutput(output, indicator)
        adapter.write('Dumping registry...')
        adapter.write('Dump created: registry.csv — 1 rows')
    assert output.lines == ['Dumping registry...', 'Dump created: registry.csv — 1 rows']


def test_display_waits_for_delay(terminal):
    started = time.monotonic()
    with ui.ActivityIndicator('Work', delay=.1):
        time.sleep(.02)
        assert not terminal.getvalue()
        wait_for(lambda: bool(terminal.getvalue()))
        assert time.monotonic() - started >= .09

import io
import threading
import pytest
from forensic_assistant.interactive import setup_display as display
from forensic_assistant.terminal import Palette


class Terminal(io.StringIO):
    def __init__(self, encoding):
        super().__init__()
        self.codec = encoding

    @property
    def encoding(self):
        return self.codec

    def isatty(self):
        return True


@pytest.mark.parametrize('encoding,frames', [('utf-8', '⠋⠙'), ('ascii', '|/')])
def test_animation_continues_without_file_updates_and_stops(monkeypatch, encoding, frames):
    stream = Terminal(encoding)
    monkeypatch.setattr(display, 'capable', lambda s: True)
    monkeypatch.setattr(display.sys.stdin, 'isatty', lambda: True)
    lines = []
    advanced = threading.Event()
    def replace(text, target):
        lines.append(text)
        if len(lines) >= 2:
            advanced.set()
        return True
    monkeypatch.setattr(display, 'replace_progress_line', replace)
    meter = display.FileProgress('registry', 45, Palette(), stream=stream, clock=lambda: 1)
    try:
        meter.update(6, 427)
        assert advanced.wait(2)
        assert lines[0] == frames[0] + ' registry  6 / 45 files  13%  00:00 elapsed  427 records stored'
        assert lines[1].startswith(frames[1] + ' registry  ')
        assert all('\n' not in line for line in lines)
        assert stream.getvalue() == ''
    finally:
        meter.close()
    assert not meter.thread.is_alive()
    assert lines[-1] == ''
    before = list(lines)
    meter.update(7, 500)
    meter.close()
    assert lines == before


@pytest.mark.parametrize('tty', [False, True])
def test_noninteractive_does_not_animate(monkeypatch, tty):
    stream = Terminal('utf-8') if tty else io.StringIO()
    monkeypatch.setattr(display, 'capable', lambda s: tty)
    monkeypatch.setattr(display.sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(display, 'replace_progress_line', lambda *a: False)
    meter = display.FileProgress('prefetch', 2, Palette(), stream=stream)
    meter.update(1, 1)
    meter.close()
    assert meter.thread is None
    assert 'prefetch  1 / 2 files' in stream.getvalue()
    assert not any(c in stream.getvalue() for c in '⠋⠙')

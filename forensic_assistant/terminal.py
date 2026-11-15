"""Central semantic terminal presentation and safe plain/ANSI projections."""
import json
import os
import re
import sys
from dataclasses import dataclass

SGR = re.compile(r'\x1b\[[0-9;]*m')
RESET = '\x1b[0m'
STYLES = {
    'shell_prompt': '1;3;94',
    'heading': '97',
    'value': '96',
    'progress': '96',
    'command': '96',
    'syntax': '96',
    'question': '94',
    'label': '37',
    'unknown': '90',
    'punctuation': '90',
    'warning': '33',
    'error': '31',
    'success': '32',
    'info_bar': '3;30;107',
    'forensic_note': '37'
}


def windows_ansi(stream, *, enable=False):
    """Inspect output-console mode, optionally enabling VT without clearing flags."""
    import ctypes
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetConsoleMode.restype = wintypes.BOOL
    mode = wintypes.DWORD()
    handle = msvcrt.get_osfhandle(stream.fileno())
    if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
        return False
    if enable and not mode.value & 4:
        kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.SetConsoleMode.restype = wintypes.BOOL
        if not kernel.SetConsoleMode(handle, mode.value | 4):
            return False
        if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
    return bool(mode.value & 4)


def initialize():
    """Idempotent shared entry-point setup; never change redirected handles."""
    if os.name != 'nt' or os.environ.get('TERM') == 'dumb':
        return
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream.isatty():
                windows_ansi(stream, enable=True)
        except (OSError, ValueError, AttributeError, ImportError):
            pass  # Capability checks retain the plain-text fallback.


def capable(stream):
    try:
        if not stream.isatty() or os.environ.get('TERM') == 'dumb':
            return False
        if os.name == 'nt':
            return windows_ansi(stream)
        term = os.environ.get('TERM', '')
        return term.startswith(('xterm', 'screen', 'tmux', 'vt100', 'vt220', 'ansi', 'linux', 'rxvt'))
    except (OSError, ValueError, AttributeError, ImportError):
        return False


def enabled(args=None, stream=None, *, file_output=False):
    return (not file_output and 'NO_COLOR' not in os.environ
            and not getattr(args, 'no_color', False) and not getattr(args, 'json', False)
            and capable(sys.stdout if stream is None else stream))


class Palette:
    def __init__(self, enabled=False):
        self.enabled = enabled

    def __call__(self, role, text):
        style = STYLES[role]
        if role == 'forensic_note' and ((os.name == 'nt' and capable(sys.stdout)) or os.environ.get('WT_SESSION')
                or '256color' in os.environ.get('TERM', '')
                or os.environ.get('COLORTERM') in ('truecolor', '24bit')):
            style = '38;5;136'
        return '\x1b[' + style + 'm' + text + RESET if self.enabled and text else text


@dataclass(frozen=True)
class TextSpan:
    """Human presentation only; never insert spans into forensic JSON."""
    text: str
    role: str = 'label'


def safe_span_text(text):
    """Escape controls (including supplied ANSI), preserving Unicode and layout."""
    import unicodedata
    return ''.join(c if c in '\n\t' or unicodedata.category(c) not in ('Cc', 'Cf', 'Cs')
                   else '\\u%04x' % ord(c) for c in str(text))


def render_spans(spans, palette=None):
    """Plain and terminal projections share exactly the same safe content."""
    palette = palette or Palette()
    return ''.join(palette(span.role if span.role in STYLES else 'label',
                           safe_span_text(span.text)) for span in spans)


class LabeledField(str):
    """Human field with explicit layout metadata; never used in service results."""
    def __new__(cls, label, value, palette, role):
        obj = super().__new__(cls, render_spans((TextSpan(label + ': '), TextSpan(str(value), role)), palette))
        obj.label, obj.value, obj.palette, obj.role = label, str(value), palette, role
        return obj


def aligned_lines(lines, *, width=None):
    """Align explicit fields only, preserving other narrative/table lines."""
    import shutil
    import textwrap
    lines = list(lines)
    width = max(20, width or shutil.get_terminal_size((80, 24)).columns - 1)
    fields = [line for line in lines if isinstance(line, LabeledField)]
    column = max((len(safe_span_text(f.label).expandtabs()) + 2 for f in fields), default=0)
    result = []
    for line in lines:
        if not isinstance(line, LabeledField):
            result.append(line)
            continue
        label = safe_span_text(line.label).expandtabs() + ':'
        value = safe_span_text(line.value).expandtabs()
        stacked = column > width // 2
        indent = 2 if stacked else column
        if stacked:
            result.extend(render_spans((TextSpan(part),), line.palette)
                          for part in textwrap.wrap(label, width) or [''])
        chunks = []
        for paragraph in value.split('\n'):
            chunks.extend(textwrap.wrap(paragraph, max(1, width-indent), replace_whitespace=False) or [''])
        for index, chunk in enumerate(chunks):
            prefix = ' ' * indent if stacked or index else label.ljust(column)
            result.append(render_spans((TextSpan(prefix), TextSpan(chunk, line.role)), line.palette))
    return '\n'.join(result)


def field(label, value, palette=None, *, role='value'):
    """Explicit field meaning supplied by the human-view adapter."""
    return LabeledField(label, value, palette, role)


def question_prompt(prompt, args=None):
    return render_spans((TextSpan(prompt, 'question'),), Palette(enabled(args)))


def shell_prompt(label, palette=None):
    return render_spans((TextSpan('[' + label + ']> ', 'shell_prompt'),), palette)


def write_spans(spans, *, palette=None, stream=None):
    """Record plain content once; emit the independently styled projection."""
    from forensic_assistant.session_recording import output, suspended
    stream = sys.stdout if stream is None else stream
    spans = tuple(spans)
    output(render_spans(spans), 'stderr' if stream is sys.stderr else 'stdout')
    display = Palette(bool(palette and palette.enabled) and enabled(stream=stream))
    with suspended():
        stream.write(render_spans(spans, display))


def render_json(value, palette=None):
    """Diagnostic JSON is always machine-readable and never syntax colored."""
    return json.dumps(value, ensure_ascii=True, indent=2)


def wrap_line(line, width):
    """Wrap trusted SGR styles with zero display width, resetting each row."""
    active = ''
    row = ''
    count = 0
    pos = 0
    for match in SGR.finditer(line):
        for char in line[pos:match.start()]:
            if count == width:
                yield row + (RESET if active else '')
                row = active
                count = 0
            row += char
            count += 1
        code = match.group()
        active = '' if code in (RESET, '\x1b[m') else code
        row += code
        pos = match.end()
    for char in line[pos:]:
        if count == width:
            yield row + (RESET if active else '')
            row = active
            count = 0
        row += char
        count += 1
    yield row + (RESET if active else '')


def message(text, args=None, *, role='error'):
    print(Palette(enabled(args, sys.stderr))(role, text), file=sys.stderr)


def banner(text, args=None):
    return text if enabled(args) else SGR.sub('', text)


def clear_screen(stream=None):
    """Clear a terminal internally; color preferences do not disable cursor control."""
    stream = sys.stdout if stream is None else stream
    if not stream.isatty():
        return False
    if capable(stream):
        stream.write('\x1b[2J\x1b[H')
        stream.flush()
        return True
    if os.name == 'nt':
        return clear_windows(stream)
    return False


def replace_progress_line(text='', stream=None):
    """One-line progress control, independent of colors; no controls in files."""
    import shutil
    stream = sys.stdout if stream is None else stream
    if not capable(stream):
        return False
    width = max(1, shutil.get_terminal_size(fallback=(80, 24)).columns - 1)
    # Caller supplies application-owned progress text; bound it to one row.
    text = next(iter(wrap_line(text, width)), '')
    stream.write('\r\x1b[K' + text)
    stream.flush()
    return True


def redraw_viewport(lines, footer, stream=None):
    """Replace a terminal viewport, clearing old rows; never emit controls to a file."""
    stream = sys.stdout if stream is None else stream
    if not stream.isatty():
        return False
    frame = '\n'.join([*lines, footer])
    if capable(stream):
        # One write avoids clearing the whole screen before drawing the new frame.
        frame = '\x1b[H' + '\x1b[K\n'.join([*lines, footer]) + '\x1b[J'
    elif not clear_screen(stream):
        return False
    stream.write(frame)
    stream.flush()
    return True


def supports_unicode(text, stream=None):
    stream = sys.stdout if stream is None else stream
    try:
        text.encode(getattr(stream, 'encoding', None) or 'ascii')
        return True
    except (UnicodeError, LookupError):
        return False


def clear_windows(stream):
    """Legacy Windows console fallback, preserving attributes and console modes."""
    import ctypes
    import msvcrt
    from ctypes import wintypes as w
    class Coord(ctypes.Structure):
        _fields_ = [('x', w.SHORT), ('y', w.SHORT)]
    class Rect(ctypes.Structure):
        _fields_ = [('left', w.SHORT), ('top', w.SHORT), ('right', w.SHORT), ('bottom', w.SHORT)]
    class Info(ctypes.Structure):
        _fields_ = [
            ('size', Coord),
            ('cursor', Coord),
            ('attributes', w.WORD),
            ('window', Rect),
            ('maximum', Coord)
        ]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetConsoleScreenBufferInfo.argtypes = [w.HANDLE, ctypes.POINTER(Info)]
    kernel.FillConsoleOutputCharacterW.argtypes = [w.HANDLE, w.WCHAR, w.DWORD, Coord, ctypes.POINTER(w.DWORD)]
    kernel.FillConsoleOutputAttribute.argtypes = [w.HANDLE, w.WORD, w.DWORD, Coord, ctypes.POINTER(w.DWORD)]
    kernel.SetConsoleCursorPosition.argtypes = [w.HANDLE, Coord]
    handle = msvcrt.get_osfhandle(stream.fileno())
    info = Info()
    written = w.DWORD()
    if not kernel.GetConsoleScreenBufferInfo(handle, ctypes.byref(info)):
        return False
    width = info.window.right - info.window.left + 1
    for row in range(info.window.top, info.window.bottom + 1):
        pos = Coord(info.window.left, row)
        if not kernel.FillConsoleOutputCharacterW(handle, ' ', width, pos, ctypes.byref(written)):
            return False
        if not kernel.FillConsoleOutputAttribute(handle, info.attributes, width, pos, ctypes.byref(written)):
            return False
    return bool(kernel.SetConsoleCursorPosition(handle, Coord(info.window.left, info.window.top)))

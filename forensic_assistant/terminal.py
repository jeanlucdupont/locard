"""Terminal presentation only. Styles describe types, never forensic judgments."""
import json
import os
import re
import sys

SGR = re.compile(r'\x1b\[[0-9;]*m')
RESET = '\x1b[0m'
STYLES = {
    'prompt': '1;3;94',
    'key': '36',
    'string_value': '32',
    'number_value': '35',
    'boolean_value': '34',
    'evidence_id': '1;36',
    'heading': '1',
    'secondary_text': '0',
    'warning': '33',
    'error': '31',
    'success': '32',
    'info_bar': '3;30;107'
}
EVIDENCE_PREFIXES = ('EVTX:', 'PREFETCH:', 'MFT:', 'REGISTRY:')


def windows_ansi(stream):
    """Only trust the actual console mode; do not mutate console settings."""
    import ctypes
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetConsoleMode.restype = wintypes.BOOL
    mode = wintypes.DWORD()
    return bool(kernel.GetConsoleMode(msvcrt.get_osfhandle(stream.fileno()), ctypes.byref(mode)) and mode.value & 4)


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
        return '\x1b[' + STYLES[role] + 'm' + text + RESET if self.enabled and text else text


def value_role(value):
    if isinstance(value, str):
        return 'evidence_id' if value.startswith(EVIDENCE_PREFIXES) else 'string_value'
    if value is None or isinstance(value, bool):
        return 'boolean_value'
    if isinstance(value, (int, float)):
        return 'number_value'
    return 'secondary_text'


def render_json(value, palette):
    if not palette.enabled:
        return json.dumps(value, ensure_ascii=True, indent=2)
    active = set()
    def walk(item, depth):
        if not isinstance(item, (dict, list, tuple)):
            yield palette(value_role(item), json.dumps(item, ensure_ascii=True))
            return
        if id(item) in active:
            raise ValueError('Circular reference detected')
        active.add(id(item))
        try:
            mapping = isinstance(item, dict)
            left, right = ('{', '}') if mapping else ('[', ']')
            yield left
            for i, entry in enumerate(item.items() if mapping else item):
                yield (',' if i else '') + '\n' + '  ' * (depth + 1)
                if mapping:
                    key, child = entry
                    if not isinstance(key, str):
                        if key is None or isinstance(key, (bool, int, float)):
                            key = json.dumps(key)
                        else:
                            raise TypeError('JSON keys must be str, int, float, bool or None')
                    yield palette('key', json.dumps(key, ensure_ascii=True)) + ': '
                else:
                    child = entry
                yield from walk(child, depth + 1)
            if item:
                yield '\n' + '  ' * depth
            yield right
        finally:
            active.remove(id(item))
    return ''.join(walk(value, 0))


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

"""Standard-library console input. No background stdin readers or disk history."""
import os
import sys
import time
import unicodedata
from contextlib import contextmanager


class WindowsKeys:
    """Read explicit key events, avoiding getwch's U+00E0 prefix ambiguity."""
    def __init__(self):
        import ctypes
        from ctypes import wintypes as w
        import msvcrt
        class Character(ctypes.Union):
            _fields_=[('unicode',w.WCHAR),('ascii',ctypes.c_char)]
        class Key(ctypes.Structure):
            _fields_=[('down',w.BOOL),('repeat',w.WORD),('virtual',w.WORD),
                      ('scan',w.WORD),('char',Character),('control',w.DWORD)]
        class Event(ctypes.Union):
            _fields_=[('key',Key),('padding',ctypes.c_byte*16)]
        class Record(ctypes.Structure):
            _fields_=[('kind',w.WORD),('event',Event)]
        if ctypes.sizeof(Record)!=20:raise RuntimeError('Unsupported console event layout')
        self.ctypes=ctypes;self.w=w;self.Record=Record
        self.handle=msvcrt.get_osfhandle(sys.stdin.fileno())
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.kernel.GetNumberOfConsoleInputEvents.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)]
        self.kernel.ReadConsoleInputW.argtypes=[w.HANDLE,ctypes.POINTER(Record),w.DWORD,ctypes.POINTER(w.DWORD)]
        self.kernel.FlushConsoleInputBuffer.argtypes=[w.HANDLE]
        self.remaining=0;self.last=None

    def poll(self):
        if self.remaining:
            self.remaining-=1;return self.last
        count=self.w.DWORD()
        if not self.kernel.GetNumberOfConsoleInputEvents(self.handle,self.ctypes.byref(count)):
            raise RuntimeError('Cannot poll console input')
        if not count.value:return None
        record=self.Record()
        if not self.kernel.ReadConsoleInputW(self.handle,self.ctypes.byref(record),1,self.ctypes.byref(count)):
            raise RuntimeError('Cannot read console input')
        key=record.event.key
        if record.kind!=1 or not key.down:return None
        value={38:'UP',40:'DOWN',37:'LEFT',39:'RIGHT',36:'HOME',35:'END',46:'DELETE'}.get(key.virtual)
        value=value or key.char.unicode
        if not value or value=='\x00':return None
        self.last=value;self.remaining=max(0,key.repeat-1)
        return value

    def flush(self):
        self.remaining=0
        if not self.kernel.FlushConsoleInputBuffer(self.handle):
            raise RuntimeError('Cannot clear cancelled console input')


@contextmanager
def windows_input():
    # Receive Ctrl+C as a key while editing, then restore normal Ctrl+C signal
    # delivery for command execution. ConPTY may otherwise discard this key.
    import ctypes
    from ctypes import wintypes as w
    import msvcrt
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetConsoleMode.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)]
    kernel.SetConsoleMode.argtypes=[w.HANDLE,w.DWORD]
    handle=msvcrt.get_osfhandle(sys.stdin.fileno());mode=w.DWORD()
    if not kernel.GetConsoleMode(handle,ctypes.byref(mode)) or not kernel.SetConsoleMode(handle,mode.value & ~7):
        raise RuntimeError('Cannot establish interactive console input mode')
    try:yield
    finally:
        if not kernel.SetConsoleMode(handle,mode.value):
            raise RuntimeError('Cannot restore console input mode')


def safe(value):
    return ''.join(c if c.isprintable() and not unicodedata.category(c).startswith('C')
                   else ascii(c)[1:-1] for c in str(value))


def edit(keys, *, history=(), output=None, prompt='', limit=65536):
    """Small console editor; key source owns timeout and terminal restoration."""
    output = output or sys.stdout
    buffer = []
    cursor = 0
    position = len(history)
    draft = ''
    previous = 0
    overflow = False
    for key in keys:
        if key in ('\r', '\n'):
            output.write('\n'); output.flush()
            if overflow:raise ValueError('Input line exceeds size limit; command discarded')
            return ''.join(buffer)
        if key == '\x03': raise KeyboardInterrupt
        if key in ('\x04','\x1a'):
            if not buffer: raise EOFError
            continue
        if key == 'UP' and position:
            if position == len(history): draft = ''.join(buffer)
            position -= 1; buffer = list(history[position]); cursor = len(buffer)
        elif key == 'DOWN' and position < len(history):
            position += 1; buffer = list(history[position] if position < len(history) else draft); cursor = len(buffer)
        elif key == 'LEFT': cursor = max(0,cursor-1)
        elif key == 'RIGHT': cursor = min(len(buffer),cursor+1)
        elif key == 'HOME': cursor = 0
        elif key == 'END': cursor = len(buffer)
        elif key == 'DELETE' and cursor < len(buffer): del buffer[cursor]
        elif key in ('\b','\x7f') and cursor:
            cursor -= 1; del buffer[cursor]
        elif len(key) == 1 and key.isprintable():
            if len(buffer)>=limit:overflow=True
            else:buffer.insert(cursor,key); cursor += 1
        # Keep redraw within one terminal row. Wide-character rendering remains
        # terminal-dependent; the returned Unicode text is never truncated.
        import shutil
        width = max(10,shutil.get_terminal_size().columns-1)
        prefix = safe(prompt)
        left = safe(''.join(buffer[:cursor])); right = safe(''.join(buffer[cursor:]))
        frame = (prefix+left)[-width:]
        shown = frame+right[:max(0,width-len(frame))]
        output.write('\r'+shown+' '*max(0,previous-len(shown))+'\r'+frame)
        output.flush(); previous = len(shown)
    raise TimeoutError('Input timed out')


def timed_line(prompt, seconds, *, history=()):
    if not sys.stdin.isatty(): raise ValueError('Interactive input requires a terminal')
    deadline = time.monotonic()+seconds if seconds is not None else float('inf')
    print(prompt,end='',flush=True)
    if os.name == 'nt':
        source=WindowsKeys()
        def keys():
            high = None
            while time.monotonic() < deadline:
                key=source.poll()
                if key is None:time.sleep(.02);continue
                if high is not None:
                    if len(key)==1 and 0xdc00<=ord(key)<=0xdfff:
                        key=(high+key).encode('utf-16-le','surrogatepass').decode('utf-16-le')
                    high=None
                elif len(key)==1 and 0xd800<=ord(key)<=0xdbff:
                    high=key;continue
                yield key
        with windows_input():
            try:
                return edit(keys(),history=history,prompt=prompt)
            except (TimeoutError,KeyboardInterrupt,EOFError):
                source.flush()
                print()
                raise
    import select
    import termios
    import tty
    fd = sys.stdin.fileno()
    original = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        def keys():
            while time.monotonic() < deadline:
                if select.select([fd],[],[],min(.05,max(0,deadline-time.monotonic())))[0]:
                    key = os.read(fd,1)
                    if not key: raise EOFError
                    yield key.decode('utf-8',errors='replace')
        return edit(keys(),history=history,prompt=prompt)
    finally:
        termios.tcsetattr(fd,termios.TCSAFLUSH,original)


class Reader:
    def __init__(self): self.history = []
    def clear(self): self.history.clear()
    def read(self,prompt,*,remember=False):
        if os.name == 'nt':
            value = timed_line(prompt,None,history=self.history if remember else ())
        else:
            # Native cooked Unicode input; no readline import or disk history.
            value = input(prompt)
        if remember and value.strip(): self.history = (self.history+[value])[-100:]
        return value

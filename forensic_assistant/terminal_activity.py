"""Presentation-only activity owned by the terminal, never by a forensic worker."""
import logging
import shutil
import sys
import threading

from .terminal import Palette, capable, enabled, replace_progress_line

_OWNER = threading.Lock()

FRAMES = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
PHASES = {
    'preparing': 'Preparing investigation...',
    'supervisor_start': 'Starting supervised investigation...',
    'authorization_validation': 'Checking investigation authorization...',
    'handoff_validation': 'Revalidating approved assessment and briefing...',
    'provider_init': 'Initializing approved AI provider...',
    'audit_init': 'Initializing investigation activity record...',
    'transcript_init': 'Creating derived investigation journal...',
    'worker_start': 'Starting read-only forensic worker...',
    'semantic_fingerprint': 'Verifying semantic index against retained evidence...',
    'view_validation': 'Checking investigation read view...',
    'read_transaction': 'Establishing consistent investigation view...',
    'snapshot_creation': 'Preparing private investigation snapshot...',
    'fingerprint': 'Calculating evidence fingerprint...',
    'initial_retrieval': 'Retrieving initial evidence...',
    'exposure': 'Preparing evidence context...',
    'model': 'Waiting for AI...',
    'validation': 'Validating proposed operation...',
    'operation': 'Running read-only operation...',
    'finalizing': 'Finalizing investigation...',
}


class ActivityIndicator:
    def __init__(self, text='', *, args=None, stream=None, delay=.3, interval=.1):
        self.stream = sys.stdout if stream is None else stream
        self.active = (capable(self.stream) and sys.stdin.isatty()
                       and not any(getattr(args, k, False) for k in
                                   ('json', 'output_file', 'append_file', 'page'))
                       and not any(logging.getLogger(name).isEnabledFor(logging.DEBUG)
                                   for name in ('forensic_assistant',
                                                'forensic_assistant.investigation_ai',
                                                'forensic_assistant.dump_cli')))
        self.palette = Palette(enabled(args, self.stream))
        self.delay, self.interval = max(0, delay), max(.01, interval)
        self.text = text
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._visible = False
        self._owns_line = False

    def start(self, text=None):
        if text is not None:
            self.update(text)
        if self.active and self._thread is None and _OWNER.acquire(blocking=False):
            self._owns_line = True
            self._stop.clear()
            self._thread = threading.Thread(target=self._animate, daemon=True,
                                            name='Locard terminal activity')
            try:
                self._thread.start()
            except RuntimeError:
                self._thread = None
                self._owns_line = False
                _OWNER.release()
        return self

    def update(self, text):
        # Callers supply application-owned labels, never paths/model/evidence text.
        with self._lock:
            self.text = text

    def phase(self, name):
        if type(name) is not str:
            return
        if name == 'approval' or name in PHASES:
            from .session_recording import record
            record('execution_phase', dict(phase=name))
        if name == 'approval':
            self.stop()
        elif name in PHASES:
            self.start(PHASES[name])

    def _animate(self):
        if self._stop.wait(self.delay):
            return
        index = 0
        try:
            while not self._stop.is_set():
                with self._lock:
                    text = self.text
                width = max(1, shutil.get_terminal_size(fallback=(80, 24)).columns - 1)
                room = max(0, width - 2)
                text = text if len(text) <= room else (text[:max(0, room-1)] + '…' if room else '')
                from .terminal import supports_unicode
                frames = FRAMES if supports_unicode(FRAMES, self.stream) else '|/-\\'
                line = self.palette('progress', frames[index % len(frames)])
                if room:
                    line += ' ' + self.palette('label', text)
                from .session_recording import suspended
                with suspended():
                    self._visible = replace_progress_line(line, self.stream)
                index += 1
                if self._stop.wait(self.interval):
                    break
        except (OSError, ValueError, UnicodeError):
            # Rendering failure must not affect the represented operation.
            pass

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
            self._thread = None
        if self._visible:
            try:
                from .session_recording import suspended
                with suspended():
                    replace_progress_line('', self.stream)
            except (OSError, ValueError, UnicodeError):
                pass
            self._visible = False

        if self._owns_line:
            self._owns_line = False
            _OWNER.release()

    def __enter__(self):
        return self.start() if self.text else self

    def __exit__(self, *exc):
        self.stop()


class ActivityOutput:
    """Dump's existing per-artifact messages drive activity, never its row loop."""
    def __init__(self, output, indicator):
        self.output, self.indicator = output, indicator

    def write(self, text):
        if self.indicator.active and text.startswith('Dumping '):
            self.indicator.start(text)
        else:
            self.indicator.stop()
            self.output.write(text)


def operation(text, args=None):
    """Present silent synchronous work; leave before output or questions.

    Reuse the delayed activity thread, which waits without drawing for fast work.
    """
    return ActivityIndicator(text, args=args, delay=.5, interval=.1)

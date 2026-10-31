"""Deterministic narrative units, never forensic evidence identifiers."""
import hashlib
import re
import time

UNIT_CHARS = 256
MAX_UNITS = 256


def inventory(inputs):
    started = time.perf_counter()
    units = []
    total = 0
    for source, text in inputs.items():
        # Keep paragraph separators in the preceding unit. No trimming, decoding,
        # newline normalization or linguistic sentence guessing occurs here.
        newline = r'(?:\r\n|\r(?!\n)|(?<!\r)\n)'
        boundaries = [m.end() for m in re.finditer(newline+r'[ \t]*'+newline, text)]
        boundaries.append(len(text))
        start = 0
        digest = hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]
        prefix = ('O' if source == 'original' else 'C'+source.split(':')[1]
                  if source.startswith('correction:') else 'F'+hashlib.sha256(source.encode()).hexdigest()[:8])
        ordinal = 0
        for end in boundaries:
            while start < end:
                stop = min(start+UNIT_CHARS, end)
                ordinal += 1
                total += 1
                if len(units) < MAX_UNITS:
                    units.append(dict(id=f'S-{prefix}-{digest}-{ordinal:03d}', source=source,
                                      start=start, end=stop, text=text[start:stop], order=len(units)))
                start = stop
    return units, dict(total_units=total, retained_units=len(units), complete=len(units)==total,
                       segmentation_seconds=time.perf_counter()-started)


def supports(lead, units):
    """An occurrence must be fully covered by contiguous cited units in its input."""
    for occurrence in lead['occurrences']:
        cursor = occurrence['start']
        for unit in sorted((u for u in units if u['source']==occurrence['source']), key=lambda u:u['start']):
            if unit['start'] <= cursor < unit['end']:
                cursor = unit['end']
            if cursor >= occurrence['end']:
                return True
    return False

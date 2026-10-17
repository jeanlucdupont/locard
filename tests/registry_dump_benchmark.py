"""Development only: synthetic CSV pipeline and full Registry dump measurements.

Run with the repository's editable install. --case must be an expendable synthetic
case: the normal dump command replaces its derived registry.csv and writes audit.
No benchmark knobs are exposed through the product CLI.
"""
import argparse
import csv
import hashlib
import json
import logging
from pathlib import Path
import time

from forensic_assistant import dump_cli as dump


def legacy_encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
def legacy_cell(value):
    if value is None: return ''
    text = legacy_encoded(value) if isinstance(value, (list, dict)) else str(value)
    if len(text.encode('utf-8')) > dump.MAX_CELL: raise ValueError('oversized cell')
    if text.startswith(("'", '\t', '\r', '\n')) or text.lstrip().startswith(('=', '+', '-', '@')):
        text = "'" + text
    return text


def legacy_values(row, fields):
    """Frozen pre-optimization conversion, including its JSON encoder allocation."""
    return [legacy_cell(legacy_encoded(row[f]) if f.endswith('_json') and row.get(f) is not None
                 else row.get(f)) for f in fields]


def representative_rows():
    """Rich synthetic fields, including repeated provenance and nontrivial values."""
    fields = dump.COMMON + dump.FIELDS['registry']
    assertions = [dict(source_id='source-1', display_name='Synthetic', hostname='host',
                       username='analyst', volume_root='C:', creation_basis='analyst')]
    contexts = [dict(hostname='host', username='analyst', volume_root='C:')]
    for index, value in enumerate((None, {'text': '雪,"quoted"\nvalue', 'items': [None, 1, True, 'x' * 256]},
                                    ['a', 'b', '\t=1'], -123, 'long' * 1024)):
        row = dump.RegistryRow.fromkeys(fields)
        row.update(evidence_id='REGISTRY:synthetic:' + str(index), file_sha256='a' * 64,
                   source_file='synthetic.hive', source_assertions_json=assertions,
                   legacy_contexts_json=contexts, warnings_json=[], timestamps_json=[],
                   artifact_type='registry_value', hive='NTUSER', hive_dirty=0,
                   hive_warnings_json=['synthetic warning'],
                   key_path='ROOT\\Software\\' + ('long-key\\' * 20),
                   key_time=[dict(timestamp_utc='2020-01-01T00:00:00Z', source='Registry key time', status='valid')],
                   kind='registry_value', value_name='=SUM(1,2)', value_type=1, value_data_json=value)
        row.update({f: [a[k] for a in assertions] for f, k in dump.SOURCE_COLUMNS})
        yield row


def micro():
    rows = list(representative_rows())
    fields = dump.COMMON + dump.FIELDS['registry']
    convert = dump.CsvValues(fields)
    class Sink:
        def __init__(self): self.hash = hashlib.sha256()
        def write(self, text):
            self.hash.update(text.encode('utf-8'))
            return len(text)
    for count in (10000, 100000):
        results = []
        for label in ('baseline', 'candidate'):
            sink = Sink(); writer = csv.writer(sink, lineterminator='\r\n')
            start = time.perf_counter()
            for index in range(count):
                row = rows[index % len(rows)]
                if label == 'candidate' and index % 128 == 0:
                    cache = dump.source_csv_cells(['a' * 64], {'a' * 64: row['source_assertions_json']},
                                                 {'a' * 64: row['legacy_contexts_json']})
                    for r in rows: r.csv_cells = cache.get('a' * 64, {})
                writer.writerow(legacy_values(row, fields) if label == 'baseline' else convert(row))
            results.append(dict(pipeline=label, rows=count, seconds=time.perf_counter() - start,
                                csv_sha=sink.hash.hexdigest()))
        assert results[0]['csv_sha'] == results[1]['csv_sha']
        print(json.dumps(results), flush=True)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def peak_memory():
    import os
    if os.name != 'nt': return None
    import ctypes
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize',
            'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
            'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage', 'PrivateUsage')]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    counters = Counters(); counters.cb = ctypes.sizeof(counters)
    if not kernel.K32GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    return counters.PeakWorkingSetSize


def full(args):
    from forensic_assistant.cli import main
    dump.PAGE = args.page
    if args.buffer is not None:
        original = dump.tempfile.NamedTemporaryFile
        def buffered(*pos, **kw):
            kw['buffering'] = args.buffer
            return original(*pos, **kw)
        dump.tempfile.NamedTemporaryFile = buffered
    captured = {}
    class Handler(logging.Handler):
        def emit(self, record): captured[record.msg] = record.args
    logger = logging.getLogger('forensic_assistant.dump_cli')
    logger.setLevel(logging.DEBUG if args.debug else logging.WARNING)
    logger.addHandler(Handler())
    case = Path(args.case).resolve()
    target = case.parent / 'dump' / 'registry.csv'
    before = digest(case)
    old_csv = digest(target) if target.exists() else None
    start = time.perf_counter()
    result = main(['--db', str(case), 'dump', 'registry', '--force'])
    elapsed = time.perf_counter() - start
    print(json.dumps(dict(exit_code=result, command_seconds=elapsed,
                         page_size=args.page, buffer=args.buffer,
                         peak_working_set=peak_memory(), database_sha=digest(case),
                         database_unchanged=before == digest(case), csv_sha=digest(target),
                         csv_unchanged=old_csv == digest(target), diagnostics=captured)), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case')
    parser.add_argument('--micro', action='store_true')
    parser.add_argument('--page', type=int, default=128)
    parser.add_argument('--buffer', type=int)
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    if args.micro: micro()
    elif args.case: full(args)
    else: parser.error('Specify --micro or an expendable synthetic --case')

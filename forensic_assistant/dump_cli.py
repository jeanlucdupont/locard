"""Fixed-destination, read-only CSV projection of retained records.

One row per evidence ID. Collections retain their slots as deterministic JSON;
source assertions are not collapsed into a guessed identity.
"""
import csv
import json
import logging
import os
from collections import defaultdict
from contextlib import closing, contextmanager, ExitStack
from pathlib import Path
import tempfile

from forensic_assistant.dump_timing import Timings
from forensic_assistant.registry_dump_profile import RegistryProfile, measure
from forensic_assistant import activity
from forensic_assistant.command_catalog import COMMANDS
from forensic_assistant.investigation_ai.case import open_readonly, read_transaction
from forensic_assistant.interactive.case import normalize, check_structure
from forensic_assistant.output import validate_destination, file_state, file_hash
from forensic_assistant.reporting.transcripts import safe_path

TYPES = ('browser', 'evtx', 'mft', 'prefetch', 'registry')
HELP = '''Usage:
  dump <type> [--force]

Types: browser, evtx, mft, prefetch, registry, all

Examples: dump browser; dump evtx; dump mft; dump prefetch; dump registry; dump all
Fixed destination: <case database directory>/dump/<type>.csv
Existing files require --force. Empty categories are skipped.
CSV files are derived analyst output, not evidence.'''
COMMON = ('evidence_id', 'source_id', 'source_display_name', 'hostname', 'username',
          'volume_root', 'source_assertions_json', 'legacy_contexts_json',
          'artifact_hostname', 'artifact_username', 'source_file', 'file_sha256',
          'artifact_type', 'warnings_json', 'timestamps_json')
FIELDS = {
    'mft': ('record_number', 'sequence_number', 'allocated', 'directory', 'file_size',
            'names_json', 'si_timestamps_json', 'fn_timestamps_json'),
    'prefetch': ('executable', 'run_count', 'candidate_paths_json', 'last_run_time', 'run_times_json'),
    'registry': ('hive', 'hive_dirty', 'hive_warnings_json', 'key_path', 'key_time',
                 'kind', 'value_name', 'value_type', 'value_data_json'),
    'evtx': ('timestamp', 'event_id', 'provider', 'channel', 'computer', 'record_id',
             'level', 'event_data_json', 'normalization_warnings_json'),
    'browser': ('browser', 'profile', 'record_kind', 'timestamp', 'url', 'title',
                'visit_count', 'download_path', 'referrer', 'url_chain_json',
                'browser_context_id', 'occurrences_json'),
}
PAGE = 128
MAX_CELL = 2 * 1024 * 1024
MAX_PAGE_BYTES = 32 * 1024 * 1024


class DumpExistsError(ValueError):
    def __init__(self, target):
        self.target = target
        super().__init__('Dump already exists: ' + str(target) + '\nUse --force to replace it.')


def configure(commands):
    parser = commands.add_parser('dump', help=COMMANDS['dump'], description=HELP)
    parser.add_argument('dump_type', nargs='?', choices=(*TYPES, 'all'))
    parser.add_argument('--force', action='store_true', help='Replace requested derived CSV files')
    parser.add_argument('--no-color', action='store_true', help='Disable terminal styling')


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def cell(value):
    """Reversible spreadsheet protection; null is empty, collections are JSON."""
    if value is None:
        return ''
    text = encoded(value) if isinstance(value, (list, dict)) else str(value)
    if len(text.encode('utf-8')) > MAX_CELL:
        raise ValueError('Dump cell exceeds 2 MiB safety bound; no data was truncated')
    # Escape existing apostrophes too, so stripping one prefix restores the text.
    if text.startswith(("'", '\t', '\r', '\n')) or text.lstrip().startswith(('=', '+', '-', '@')):
        text = "'" + text
    return text


@contextmanager
def pin_directory(path):
    """On Windows, deny directory rename/deletion for the publication lifetime."""
    safe_path(path)
    if os.name != 'nt':
        yield
        return
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    # Attributes only; share read/write, deliberately not FILE_SHARE_DELETE.
    handle = kernel.CreateFileW(str(path), 0x80, 3, None, 3, 0x02200000, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        safe_path(path)  # Reject reparse points opened without following them.
        yield
    finally:
        kernel.CloseHandle(handle)


def groups(db, sql, params, key='evidence_id'):
    result = defaultdict(list)
    size = count = 0
    for row in db.execute(sql, params):
        data = dict(row)
        size += len(encoded(data).encode('utf-8'))
        count += 1
        if size > MAX_PAGE_BYTES or count > 100000:
            raise ValueError('Dump related-record page exceeds safety bound; no data was truncated')
        result[data[key]].append(data)
    return result


def rows(db, kind):
    """Keyset pages and indexed bulk joins: never fetch the entire dataset."""
    profile = getattr(db, 'registry_profile', None) if kind == 'registry' else None
    version = db.execute('PRAGMA user_version').fetchone()[0]
    last = ''
    while True:
        records = []
        size = 0
        # evidence_type begins with (source_type, artifact_type), not evidence_id.
        # Letting SQLite choose it sorts the whole category again for every page.
        # The schema-defined primary-key index gives a forward keyset scan without
        # changing case indexes or accumulating all IDs in application memory.
        for record in db.execute('SELECT * FROM evidence_records INDEXED BY sqlite_autoindex_evidence_records_1 '
                                 'WHERE source_type=? AND evidence_id>? '
                                 'ORDER BY evidence_id LIMIT ?', (kind, last, PAGE)):
            data = dict(record)
            size += len(encoded(data).encode('utf-8'))
            if size > MAX_PAGE_BYTES:
                raise ValueError('Dump record page exceeds safety bound; no data was truncated')
            records.append(data)
        if not records:
            return
        if profile is not None:
            profile.page(len(records))
        ids = [r['evidence_id'] for r in records]
        hashes = sorted({r['file_sha256'] for r in records})
        marks = ','.join('?' for _ in ids)
        hashmarks = ','.join('?' for _ in hashes)
        stamps = groups(db, f'SELECT * FROM evidence_timestamps WHERE evidence_id IN ({marks}) ORDER BY evidence_id,slot', ids)
        contexts = groups(db, f'SELECT * FROM source_contexts WHERE file_sha256 IN ({hashmarks}) ORDER BY context_id', hashes, 'file_sha256') if kind != 'browser' else {}
        members = {}
        occurrences = {}
        if version >= 4:
            if kind == 'browser':
                if version != 5:
                    raise ValueError('Browser records require explicit schema-5 occurrence provenance')
                occurrences = groups(db, f'''SELECT o.evidence_id,o.context_id,o.run_id,r.batch_id,
                    b.source_id,r.source_file,r.status,c.browser_product,c.profile,c.snapshot_sha256
                    FROM browser_record_occurrences o JOIN browser_contexts c USING(context_id)
                    JOIN ingestion_runs r ON r.id=o.run_id JOIN ingestion_batches b USING(batch_id)
                    WHERE o.evidence_id IN ({marks}) ORDER BY o.evidence_id,o.run_id''', ids)
                membership = f'''SELECT DISTINCT o.evidence_id,b.source_id FROM browser_record_occurrences o
                    JOIN ingestion_runs r ON r.id=o.run_id JOIN ingestion_batches b USING(batch_id)
                    WHERE o.evidence_id IN ({marks})'''
                params, key = ids, 'evidence_id'
            else:
                membership = f'''SELECT r.file_sha256,b.source_id FROM ingestion_runs r JOIN ingestion_batches b USING(batch_id)
                    WHERE r.file_sha256 IN ({hashmarks}) UNION SELECT f.file_sha256,a.source_id
                    FROM source_assignment_files f JOIN source_assignments a USING(assignment_id)
                    WHERE f.file_sha256 IN ({hashmarks})'''
                params, key = hashes + hashes, 'file_sha256'
            members = groups(db, f'''SELECT m.{key},s.creation_basis,a.* FROM ({membership}) m
                JOIN sources s USING(source_id) JOIN source_assertions a USING(source_id)
                WHERE NOT EXISTS (SELECT 1 FROM source_assertions n WHERE n.supersedes=a.assertion_id)
                ORDER BY m.{key},a.source_id''', params, key)
        details, extra = {}, {}
        if kind == 'mft':
            details = groups(db, f'SELECT evidence_id,record_number,sequence_number,allocated,directory,file_size FROM mft_records WHERE evidence_id IN ({marks})', ids)
            extra = groups(db, f'SELECT * FROM mft_names WHERE evidence_id IN ({marks}) ORDER BY evidence_id,slot', ids)
        elif kind == 'prefetch':
            details = groups(db, f'SELECT evidence_id,executable,run_count FROM prefetch_records WHERE evidence_id IN ({marks})', ids)
            extra = groups(db, f"SELECT slot,original,evidence_id FROM evidence_objects WHERE evidence_id IN ({marks}) AND role='executable_path_candidate' ORDER BY evidence_id,slot", ids)
        elif kind == 'evtx':
            fields = 'id AS evidence_id,timestamp_utc AS timestamp,event_id,provider,channel,computer,record_id,level,event_data_json,normalization_warnings_json'
            details = groups(db, f'SELECT {fields} FROM events WHERE id IN ({marks})', ids)
        elif kind == 'registry':
            with measure(profile, 'primary_registry_query'):
                details = groups(db, f'''SELECT e.evidence_id,h.hive_type AS hive,h.dirty AS hive_dirty,h.warnings_json AS hive_warnings_json,
                    coalesce(k.key_path,parent.key_path) AS key_path,v.value_name,v.value_type,v.decoded_json AS value_data_json,
                    v.key_id FROM evidence_records e JOIN registry_hives h USING(file_sha256)
                    LEFT JOIN registry_keys k USING(evidence_id) LEFT JOIN registry_values v ON v.evidence_id=e.evidence_id
                    LEFT JOIN registry_keys parent ON parent.evidence_id=v.key_id WHERE e.evidence_id IN ({marks})''', ids)
            if profile is not None:
                profile.counts['primary_rows'] += sum(map(len, details.values()))
            with measure(profile, 'parent_id_collection'):
                parents = sorted({r[0]['key_id'] for r in details.values() if r[0]['key_id']})
            if profile is not None:
                profile.counts['parent_ids'] += len(parents)
            if parents:
                with measure(profile, 'parent_timestamp_query'):
                    extra = groups(db, 'SELECT * FROM evidence_timestamps WHERE evidence_id IN (' + ','.join('?' for _ in parents) + ') ORDER BY evidence_id,slot', parents)
                if profile is not None:
                    profile.counts['timestamp_rows'] += sum(map(len, extra.values()))
        for record in records:
            with measure(profile, 'row_normalization'):
                eid = record['evidence_id']
                assertions = members.get(eid if kind == 'browser' else record['file_sha256'], [])
                ts = stamps.get(eid, [])
                result = dict(evidence_id=eid, source_assertions_json=assertions,
                              legacy_contexts_json=contexts.get(record['file_sha256'], []),
                              artifact_hostname=record['hostname'], artifact_username=record['username'],
                              source_file=record['source_file'], file_sha256=record['file_sha256'],
                              artifact_type=record['artifact_type'], warnings_json=json.loads(record['warnings_json']), timestamps_json=ts)
                for field, source in (('source_id', 'source_id'), ('source_display_name', 'display_name'),
                                      ('hostname', 'hostname'), ('username', 'username'), ('volume_root', 'volume_root')):
                    result[field] = [a[source] for a in assertions]
                if kind != 'browser':
                    if len(details.get(eid, [])) != 1:
                        raise ValueError('Missing or ambiguous normalized artifact record: ' + eid)
                    result.update(details[eid][0])
                if kind == 'mft':
                    result.update(names_json=extra.get(eid, []),
                                  si_timestamps_json=[t for t in ts if t['source'].startswith('MFT SI ')],
                                  fn_timestamps_json=[t for t in ts if t['source'].startswith('MFT FN ')])
                elif kind == 'prefetch':
                    runs = [t for t in ts if t['slot'].startswith('run:')]
                    result.update(candidate_paths_json=extra.get(eid, []), run_times_json=runs,
                                  last_run_time=next((t['timestamp_utc'] for t in runs if t['slot'] == 'run:0'), None))
                elif kind == 'registry':
                    if (record['artifact_type'] not in ('registry_key', 'registry_value') or
                            result['key_path'] is None):
                        raise ValueError('Missing or unsupported normalized Registry key/value record')
                    keyts = extra.get(result['key_id'], []) if result['key_id'] else ts
                    result.update(kind=record['artifact_type'], key_time=[t for t in keyts if t['source'].startswith('Registry')])
                    for field in ('value_data_json', 'hive_warnings_json'):
                        if result[field] is not None:
                            result[field] = json.loads(result[field])
                elif kind == 'evtx':
                    for field in ('event_data_json', 'normalization_warnings_json'):
                        result[field] = json.loads(result[field])
                elif kind == 'browser':
                    if record['artifact_type'] not in ('browser_visit', 'browser_download'):
                        raise ValueError('Unsupported retained browser record kind')
                    d = json.loads(record['original_json'])
                    if (not isinstance(d, dict) or d.get('browser_product') not in ('chrome', 'edge') or
                            not isinstance(d.get('profile'), str) or not isinstance(d.get('context_id'), str)):
                        raise ValueError('Invalid normalized browser context')
                    occ = occurrences.get(eid, [])
                    if not occ or any((o['context_id'], o['browser_product'], o['profile']) !=
                                      (d['context_id'], d['browser_product'], d['profile']) for o in occ):
                        raise ValueError('Browser occurrence provenance is missing or inconsistent')
                    result.update(browser=d['browser_product'], profile=d['profile'],
                                  record_kind='history' if record['artifact_type'] == 'browser_visit' else 'download',
                                  timestamp=next((t['timestamp_utc'] for t in ts if t['slot'] in ('Browser.VisitTime', 'Browser.DownloadStart')), None),
                                  url=d.get('url'), title=d.get('title'), visit_count=d.get('url_visit_count'),
                                  download_path=d.get('target_path'), referrer=d.get('referrer'),
                                  url_chain_json=d.get('url_chain', []), browser_context_id=d['context_id'], occurrences_json=occ)
            yield result
        last = ids[-1]


def run(args, output, *, timings=None):
    kind = args.dump_type
    if kind not in (*TYPES, 'all') or any(getattr(args, n, None) for n in ('output_file', 'append_file', 'page')):
        raise ValueError('Dump requires a supported type and fixed case-local destination')
    timing = timings if timings is not None else Timings()
    logger = logging.getLogger(__name__)
    timing.registry_profile = RegistryProfile(PAGE) if kind == 'registry' and logger.isEnabledFor(logging.DEBUG) else None
    completed = False
    start = timing.clock()
    try:
        with ExitStack() as locks:
            with timing.measure('path_setup'):
                case = normalize(args.db)
                for parent in reversed(case.parents):
                    locks.enter_context(pin_directory(parent))
            completed = _run(args, output, case, locks, timing)
        if completed:
            label = 'Total elapsed time' if kind == 'all' else 'Elapsed time'
            output.write(f'{label}: {timing.clock() - start:.2f} sec')
    finally:
        timing.total = timing.clock() - start
        logger.debug('Dump timings (seconds): %s', timing.summary())
        if timing.registry_profile is not None:
            logger.debug('Registry dump performance: %s', timing.registry_profile.summary(bool(completed)))


def _run(args, output, case, locks, timing):
    kind = args.dump_type
    profile = timing.registry_profile
    root = safe_path(case.parent / 'dump')
    if root.exists() and not root.is_dir():
        raise ValueError('Dump destination must be a directory')
    staged, published = [], []
    try:
        with closing(timing.call('database_open', 'shared', open_readonly, case)) as db, read_transaction(db):
            with timing.measure('schema_and_counts'):
                check_structure(db)
                counts = dict(db.execute('SELECT source_type,count(*) FROM evidence_records GROUP BY source_type'))
            requested = TYPES if kind == 'all' else (kind,)
            selected = [t for t in requested if counts.get(t, 0)]
            if not selected:
                output.write('No retained ' + (kind if kind != 'all' else 'supported') + ' records to dump.')
                return
            # Check every existing target before creating even the staging directory.
            before = {}
            for t in selected:
                with timing.measure('preflight', t):
                    target = safe_path(root / (t + '.csv'))
                    # A recorded evidence pathname remains protected even when absent.
                    for row in db.execute('SELECT source_file FROM source_locations UNION SELECT source_file FROM ingestion_runs'):
                        if target.resolve() == Path(row[0]).absolute().resolve():
                            raise ValueError('Dump destination is recorded source evidence')
                    if target.exists():
                        validate_destination(target, args)
                        if target.stat().st_nlink != 1:
                            raise ValueError('Hard-linked dump destination rejected')
                        if not args.force:
                            raise DumpExistsError(target)
                        with target.open(encoding='utf-8', newline='') as existing:
                            header = existing.readline(16385)
                        if len(header) > 16384 or next(csv.reader([header]), []) != list(COMMON + FIELDS[t]):
                            raise ValueError('Existing file is not a recognized Locard dump; refusing replacement')
                    before[t] = file_state(target)
            safe_path(root).mkdir(exist_ok=True)
            locks.enter_context(pin_directory(root))
            for t in selected:
                target = root / (t + '.csv')
                timing.call('destination_validation', t, validate_destination, target, args)
                output.write('Dumping ' + t + '...')
                with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='',
                        dir=safe_path(root), prefix='.locard-dump-', delete=False) as stream:
                    temporary = Path(stream.name)
                    staged.append((t, temporary, target))
                    writer = csv.writer(stream, lineterminator='\r\n')
                    fields = COMMON + FIELDS[t]
                    with measure(profile, 'csv_write'):
                        timing.call('csv_write', t, writer.writerow, fields)
                    total = 0
                    for row in timing.records(db, t, rows):
                        with measure(profile, 'csv_write'), timing.measure('csv_write', t):
                            writer.writerow([cell(encoded(row[f]) if f.endswith('_json') and row.get(f) is not None
                                                  else row.get(f)) for f in fields])
                        total += 1
                        if profile is not None:
                            profile.counts['csv_rows'] += 1
                    if total != counts[t]:
                        raise ValueError('Dump count differs from snapshot count')
                    publication_start = profile.clock() if profile is not None else None
                    with timing.measure('csv_write', t):
                        stream.flush()
                        os.fsync(stream.fileno())
                if profile is not None:
                    profile.add('publication', profile.clock() - publication_start)
        # Release the snapshot before filesystem publication / audit writes.
        for t, temporary, target in staged:
            with timing.measure('publication_validation', t):
                safe_path(target)
                validate_destination(target, args)
                if file_state(target) != before[t]:
                    raise ValueError('Dump destination changed during export; review it and retry')
        for t, temporary, target in staged:
            with timing.measure('publication_validation', t):
                safe_path(target)
                if file_state(target) != before[t]:
                    raise ValueError('Dump destination changed before publication')
            action = 'OUTPUT_OVERWRITE' if before[t] else 'OUTPUT_WRITE'
            audit_start = timing.clock()
            measured = timing.elapsed(t)
            try:
                with activity.mutation(action, command='dump', path='dump/' + target.name,
                                       artifact_type=t, row_count=counts[t]) as audit:
                    with measure(profile, 'publication'):
                        if before[t] is None:
                            timing.call('publication', t, os.link, temporary, target)
                        else:
                            timing.call('publication', t, os.replace, temporary, target)
                    published.append(target.name)
                    audit['new_sha256'] = timing.call('checksum', t, file_hash, target)
            finally:
                timing.phases[t]['audit'] += max(0.0, timing.clock() - audit_start - (timing.elapsed(t) - measured))
            suffix = f' — {timing.elapsed(t):.2f} sec' if kind == 'all' else ''
            output.write(f'Dump created: {target.name} — {counts[t]:,} rows' + suffix)
        for t in requested:
            if t not in selected:
                output.write('Skipped ' + t + ': no retained records')
        return True
    except BaseException:
        if published:
            output.write('Dump interrupted; already published files remain: ' + ', '.join(published))
        raise
    finally:
        for _, temporary, _ in staged:
            safe_path(temporary).unlink(missing_ok=True)

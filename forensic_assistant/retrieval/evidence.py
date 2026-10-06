"""Unified bounded retrieval. Timeline rows are observations, not synthetic EVTX."""
import base64
import json
import ntpath
from forensic_assistant.artifacts.context import effective_context
from forensic_assistant.artifacts.paths import normalize_path
from forensic_assistant.correlation.models import get_event
from forensic_assistant.retrieval.queries import QueryResult, Queries, required_time, escape_like


def get_evidence(db, eid, raw=False):
    row = db.execute('SELECT * FROM evidence_records WHERE evidence_id=?', (eid,)).fetchone()
    if not row:
        raise ValueError('Evidence ID not found')
    record = dict(row)
    kind = record['source_type']
    ctx = effective_context(db, record)
    result = get_event(db, eid) if kind == 'evtx' else {
        'id': eid,
        'kind': record['artifact_type'],
        'timestamp_utc': None
    }
    result.update(
        evidence_id=eid,
        source_type=kind,
        source=dict(
            sha256=record['file_sha256'],
            source_file=record['source_file'],
            locator=json.loads(record['locator_json']),
            parser=record['parser_name'],
            parser_version=record['parser_version'],
            extractor_version=record['extractor_version']
        ),
        source_file=record['source_file'],
        file_sha256=record['file_sha256'],
        artifact_type=result.get('artifact_type') if kind == 'evtx' else record['artifact_type'],
        context=ctx,
        warnings=json.loads(record['warnings_json'])
    )
    result['source_locations'] = [r[0] for r in db.execute(
        'SELECT source_file FROM source_locations WHERE file_sha256=? ORDER BY source_file',
        (record['file_sha256'],)
    )]
    result['timestamps'] = [dict(r) for r in db.execute(
        'SELECT * FROM evidence_timestamps WHERE evidence_id=? ORDER BY slot',
        (eid,)
    )]
    result['objects'] = [dict(r) for r in db.execute(
        'SELECT * FROM evidence_objects WHERE evidence_id=? ORDER BY slot LIMIT 101',
        (eid,)
    )]
    result['objects_truncated'] = len(result['objects']) > 100
    result['objects'] = result['objects'][:100]
    result['host_key'] = ctx['hostname']
    result['hostname'] = result.get('hostname') or record['hostname'] or ctx['hostname']
    result['username'] = record['username'] or ctx['username']
    if kind == 'mft':
        cols = '*' if raw else 'evidence_id,record_number,sequence_number,allocated,directory,file_size,base_record,base_sequence,record_size,attributes_json'
        detail = dict(db.execute('SELECT ' + cols + ' FROM mft_records WHERE evidence_id=?', (eid,)).fetchone())
        detail['names'] = [dict(r) for r in db.execute(
            'SELECT * FROM mft_names WHERE evidence_id=? ORDER BY slot',
            (eid,)
        )]
        result['observation'] = 'Filesystem metadata; timestamps do not establish a download or user action'
    elif kind == 'prefetch':
        cols = '*' if raw else 'evidence_id,executable,prefetch_identifier,run_count,format_version'
        detail = dict(db.execute('SELECT ' + cols + ' FROM prefetch_records WHERE evidence_id=?', (eid,)).fetchone())
        detail['references'] = [r[0] for r in db.execute(
            'SELECT path FROM prefetch_references WHERE evidence_id=? ORDER BY ordinal LIMIT 101',
            (eid,)
        )]
        detail['references_truncated'] = len(detail['references']) > 100
        detail['references'] = detail['references'][:100]
        detail['reference_count'] = db.execute(
            'SELECT count(*) FROM prefetch_references WHERE evidence_id=?',
            (eid,)
        ).fetchone()[0]
        detail['volumes'] = [dict(r) for r in db.execute(
            'SELECT * FROM prefetch_volumes WHERE evidence_id=? ORDER BY ordinal',
            (eid,)
        )]
        result['process_name'] = detail['executable']
        result['observation'] = 'Prefetch records execution timestamps; retained runs are incomplete'
    elif kind == 'registry':
        hive = dict(db.execute('SELECT * FROM registry_hives WHERE file_sha256=?', (record['file_sha256'],)).fetchone())
        if record['artifact_type'] == 'registry_key':
            detail = dict(db.execute('SELECT * FROM registry_keys WHERE evidence_id=?', (eid,)).fetchone())
            detail['value_ids'] = [r[0] for r in db.execute(
                'SELECT evidence_id FROM registry_values WHERE key_id=? ORDER BY evidence_id LIMIT 101',
                (eid,)
            )]
            detail['values_truncated'] = len(detail['value_ids']) > 100
            detail['value_ids'] = detail['value_ids'][:100]
            result['observation'] = 'Registry key last-write; not individual value creation'
        else:
            cols = '*' if raw else 'evidence_id,key_id,value_name,value_type,decoded_json,cell_offset'
            detail = dict(db.execute('SELECT ' + cols + ' FROM registry_values WHERE evidence_id=?', (eid,)).fetchone())
            detail['value_data'] = json.loads(detail.pop('decoded_json'))
            detail['key_path'] = db.execute(
                'SELECT key_path FROM registry_keys WHERE evidence_id=?',
                (detail['key_id'],)
            ).fetchone()[0]
            result['timestamps'] = [{**dict(r), 'inherited_from_key': True} for r in db.execute(
                'SELECT * FROM evidence_timestamps WHERE evidence_id=?',
                (detail['key_id'],)
            )]
            result['supporting_evidence_ids'] = [detail['key_id']]
            result['observation'] = 'Registry value in snapshot; associated timestamp belongs to containing key'
        detail['hive'] = hive
        detail['views'] = [dict(r) for r in db.execute(
            'SELECT * FROM registry_views WHERE evidence_id=? ORDER BY extractor',
            (eid,)
        )]
    else:
        detail = None
    if detail:
        for k, v in list(detail.items()):
            if isinstance(v, bytes):
                detail[k] = {'encoding': 'base64', 'data': base64.b64encode(v).decode()}
        result['detail'] = detail
    if not raw:
        result.pop('raw_xml', None)
    times = [t['timestamp_utc'] for t in result['timestamps'] if t['timestamp_utc']]
    if kind != 'evtx':
        result['timestamp_utc'] = min(times) if times else None
    return result


class EvidenceQueries:
    def __init__(self, db):
        self.db = db

    def _where(
        self,
        *,
        artifact=None,
        evidence_kind=None,
        path=None,
        username=None,
        hostname=None,
        strict_host=False,
        process=None,
        process_exact=None,
        process_contains=None,
        event_id=None,
        ip=None,
        artifact_types=None,
        powershell=False,
        source_id=None,
        source_scope=None
    ):
        clauses = []
        params = []
        schema4 = self.db.execute('PRAGMA user_version').fetchone()[0] == 4
        if source_id or (schema4 and source_scope is not None):
            from forensic_assistant.database.sources import MEMBERSHIP, current, require4
            require4(self.db)
            if source_id:
                current(self.db, source_id)
                clauses.append('e.file_sha256 IN (SELECT file_sha256 FROM (' + MEMBERSHIP + ') WHERE source_id=?)')
                params.append(source_id)
            if source_scope is not None:
                if source_scope:
                    clauses.append('(SELECT count(*) FROM (' + MEMBERSHIP + ') WHERE file_sha256=e.file_sha256)=1 AND e.file_sha256 IN (SELECT file_sha256 FROM (' + MEMBERSHIP + ') WHERE source_id=?)')
                    params.append(source_scope)
                else:
                    clauses.append('NOT EXISTS (SELECT 1 FROM (' + MEMBERSHIP + ') WHERE file_sha256=e.file_sha256)')
        if schema4:
            # Parameterized SQL calls a read-only resolver shared with hydration.
            def context_value(sha, host, user, key):
                return effective_context(self.db, dict(file_sha256=sha, hostname=host, username=user)).get(key)
            self.db.create_function('locard_context', 4, context_value)
        # Explicit CLI search policy; existing process callers retain their contract.
        if sum(v is not None for v in (process, process_exact, process_contains)) > 1:
            raise ValueError('Exact and partial process filters are mutually exclusive')
        if process_exact is not None or process_contains is not None:
            from forensic_assistant.retrieval.process_names import predicate
            value = process_exact if process_exact is not None else process_contains
            if not value.strip():
                raise ValueError('Process search must not be empty')
            if process_exact is not None and ntpath.dirname(value):
                process = value  # Preserve existing full-path/volume assertion matching.
            else:
                clause, values = predicate(value, contains=process_contains is not None)
                clauses.append(clause)
                params.extend(values)
        if artifact:
            if artifact not in ('evtx', 'mft', 'prefetch', 'registry'):
                raise ValueError('Unknown artifact source')
            clauses.append('e.source_type=?')
            params.append(artifact)
        if evidence_kind:
            clauses.append('e.artifact_type=?')
            params.append(evidence_kind)
        if hostname:
            from forensic_assistant.database.context import host_key
            if schema4:
                if strict_host:
                    clauses.append("locard_context(e.file_sha256,e.hostname,e.username,'hostname')=?")
                    params.append(host_key(hostname))
                else:
                    from forensic_assistant.database.sources import MEMBERSHIP
                    clauses.append('''(e.hostname=? OR e.file_sha256 IN (SELECT file_sha256 FROM source_contexts WHERE hostname=?) OR
                        e.file_sha256 IN (SELECT m.file_sha256 FROM (''' + MEMBERSHIP + ''') m JOIN source_assertions a USING(source_id)
                        WHERE a.hostname=? AND NOT EXISTS (SELECT 1 FROM source_assertions n WHERE n.supersedes=a.assertion_id)))''')
                    params.extend([host_key(hostname)] * 3)
            else:
                clauses.append('(e.hostname=? OR e.file_sha256 IN (SELECT file_sha256 FROM source_contexts WHERE hostname=?))')
                params.extend([host_key(hostname)] * 2)
            if strict_host and not schema4:
                clauses.append('(e.hostname IS NULL OR e.hostname=?) AND NOT EXISTS (SELECT 1 FROM source_contexts c WHERE c.file_sha256=e.file_sha256 AND c.hostname IS NOT NULL AND c.hostname<>?)')
                params.extend([host_key(hostname)] * 2)
        if username:
            suffix = '%\\' + escape_like(username) if '\\' not in username and '@' not in username else escape_like(username)
            extra = " OR locard_context(e.file_sha256,e.hostname,e.username,'username')=? COLLATE NOCASE OR locard_context(e.file_sha256,e.hostname,e.username,'username') LIKE ? ESCAPE '!' COLLATE NOCASE" if schema4 else ''
            clauses.append('(e.username=? COLLATE NOCASE OR e.username LIKE ? ESCAPE \'!\' COLLATE NOCASE OR e.file_sha256 IN (SELECT file_sha256 FROM source_contexts WHERE username=? COLLATE NOCASE OR username LIKE ? ESCAPE \'!\' COLLATE NOCASE)' + extra + ')')
            params.extend([username, suffix, username, suffix])
            if schema4:
                params.extend([username, suffix])
        for value, is_process in ((path, False), (process, True)):
            if not value:
                continue
            p = normalize_path(value)
            role = " AND o.role IN ('process_image','executable_name','executable_path_candidate','file_path','filename','persistence_target')" if is_process else ''
            if is_process and process_exact is not None:
                # A Prefetch candidate path must identify its represented executable.
                role += " AND (e.source_type<>'prefetch' OR (o.role='executable_path_candidate' AND o.basename IN (SELECT i.basename FROM evidence_objects i WHERE i.evidence_id=e.evidence_id AND i.role='executable_name')))"
            if ntpath.dirname(value):
                volume = "lower(locard_context(e.file_sha256,e.hostname,e.username,'volume_root'))||o.normalized=?" if schema4 else "EXISTS (SELECT 1 FROM source_contexts c WHERE c.file_sha256=e.file_sha256 AND lower(c.volume_root)||o.normalized=? AND NOT EXISTS (SELECT 1 FROM source_contexts x WHERE x.file_sha256=e.file_sha256 AND x.volume_root<>c.volume_root))"
                clauses.append("EXISTS (SELECT 1 FROM evidence_objects o WHERE o.evidence_id=e.evidence_id AND (o.normalized=? OR (o.path_kind='volume_relative' AND " + volume + "))" + role + ')')
                params.extend([p['normalized']] * 2)
            else:
                clauses.append('EXISTS (SELECT 1 FROM evidence_objects o WHERE o.evidence_id=e.evidence_id AND o.basename=?' + role + ')')
                params.append(p['basename'])
        if any((event_id is not None, ip, artifact_types is not None, powershell)):
            # Keep original EVTX filtering semantics and fixed parameterized predicates.
            sub = []
            values = []
            if event_id is not None:
                sub.append('v.event_id=?')
                values.append(event_id)
            if ip:
                import ipaddress
                from forensic_assistant.retrieval.queries import _ip_equal
                ipaddress.ip_address(ip)
                self.db.create_function('ip_equal', 2, _ip_equal, deterministic=True)
                sub.append('(ip_equal(v.source_ip,?) OR ip_equal(v.destination_ip,?))')
                values.extend([ip, ip])
            if artifact_types is not None:
                sub.append('v.id IN (SELECT evidence_id FROM event_context WHERE kind IN (' + ','.join('?' for _ in artifact_types) + '))' if artifact_types else '0')
                values.extend(artifact_types)
            if powershell:
                sub.append("(v.artifact_type='powershell' OR lower(v.process_name) IN ('powershell.exe','pwsh.exe') OR lower(v.process_name) LIKE '%\\powershell.exe' OR lower(v.process_name) LIKE '%\\pwsh.exe')")
            clauses.append('EXISTS (SELECT 1 FROM events v WHERE v.id=e.evidence_id AND ' + ' AND '.join(sub) + ')')
            params.extend(values)
        return clauses, params

    def search(
        self,
        *,
        start=None,
        end=None,
        exclude_time=None,
        nearest_to=None,
        limit=100,
        offset=0,
        timeline=False,
        raw=False,
        require_complete=False,
        **filters
    ):
        if not 1 <= limit <= 10000 or offset < 0:
            raise ValueError('Invalid pagination bounds')
        start = required_time(start) if start else None
        end = required_time(end) if end else None
        if start and end and start > end:
            raise ValueError('Start must not follow end')
        clauses, params = self._where(**filters)
        timeclauses = []
        tp = []
        if start:
            timeclauses.append('t.timestamp_utc>=?')
            tp.append(start)
        if end:
            timeclauses.append('t.timestamp_utc<=?')
            tp.append(end)
        if exclude_time:
            timeclauses.append('t.timestamp_utc<>?')
            tp.append(exclude_time)
        if timeline:
            source = 'evidence_timestamps t JOIN evidence_records e USING(evidence_id)'
            clauses += ['t.timestamp_utc IS NOT NULL', *timeclauses]
            params += tp
            fields = 'e.evidence_id,t.slot,t.timestamp_utc'
            order = 't.timestamp_utc,e.evidence_id,t.slot'
        else:
            source = 'evidence_records e'
            fields = 'e.evidence_id'
            if timeclauses:
                # Registry values borrow key context for filtering, never value timestamps.
                clauses.append('EXISTS (SELECT 1 FROM evidence_timestamps t WHERE (t.evidence_id=e.evidence_id OR t.evidence_id=(SELECT key_id FROM registry_values WHERE evidence_id=e.evidence_id)) AND ' + ' AND '.join(timeclauses) + ')')
                params += tp
            order = "(SELECT min(timestamp_utc) FROM evidence_timestamps WHERE evidence_id=e.evidence_id) IS NULL,(SELECT min(timestamp_utc) FROM evidence_timestamps WHERE evidence_id=e.evidence_id),e.evidence_id"
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        total = self.db.execute('SELECT count(*) FROM ' + source + where, params).fetchone()[0]
        if require_complete and (offset or total > limit):
            raise ValueError('Grouped text exceeds the 10,000 timestamp-observation safety bound; '
                             'narrow the time window/filters or use JSON/raw observation pagination')
        order_params = []
        if nearest_to and timeline:
            from forensic_assistant.correlation.models import time_ns
            self.db.create_function(
                'locard_distance',
                2,
                lambda a,
                b: str(abs(time_ns(a) - time_ns(b))).zfill(30),
                deterministic=True
            )
            order = 'locard_distance(t.timestamp_utc,?),' + order
            order_params = [nearest_to]
        rows = self.db.execute(
            'SELECT ' + fields + ' FROM ' + source + where + ' ORDER BY ' + order + ' LIMIT ? OFFSET ?',
            [*params, *order_params, limit, offset]
        ).fetchall()
        records = []
        text_evidence = {}
        for row in rows:
            if require_complete:
                # Text windows may include many slots from one MFT record.
                # Hydrate once and share unchanged detail/timestamp structures.
                eid = row['evidence_id']
                if eid not in text_evidence:
                    text_evidence[eid] = get_evidence(self.db, eid, raw)
                e = dict(text_evidence[eid])
            else:
                e = get_evidence(self.db, row['evidence_id'], raw)
            if timeline:
                stamp = next(t for t in e['timestamps'] if t['slot'] == row['slot'])
                e.update(
                    timestamp_utc=row['timestamp_utc'],
                    timestamp=stamp,
                    timeline_id=e['id'] + ':Timestamp:' + row['slot']
                )
            records.append(e)
        return QueryResult(records, total, limit, offset)

    def complete_timeline(self, *, around=None, minutes=5, **filters):
        """Bounded complete text window; count and hydration share a read snapshot.

        No per-group queries or changes to ordinary observation pagination.
        A savepoint also preserves an existing caller-owned transaction.
        """
        self.db.execute('SAVEPOINT locard_mft_text_window')
        try:
            options = dict(filters, limit=10000, offset=0, require_complete=True)
            if around:
                return self.timeline_around(around, minutes, **options)
            return self.search(timeline=True, **options)
        finally:
            self.db.execute('RELEASE locard_mft_text_window')

    def timeline_around(self, stamp, minutes=5, **kwargs):
        from forensic_assistant.correlation.temporal import shift
        if not 0 <= minutes <= 525600:
            raise ValueError('Invalid timeline minutes')
        stamp = required_time(stamp)
        return self.search(start=shift(stamp, -minutes * 60), end=shift(stamp, minutes * 60), timeline=True, **kwargs)

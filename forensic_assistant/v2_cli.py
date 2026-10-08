"""Additive V2 CLI. Existing EVTX ingestion and process/session commands remain."""
from forensic_assistant.command_catalog import COMMANDS
from forensic_assistant.artifacts.ingest import ingest_artifact, discover
from forensic_assistant.artifacts.context import bind_context
from forensic_assistant.database.db import now
from forensic_assistant.ingest.evtx import ingest_file, digest
from forensic_assistant.retrieval.evidence import EvidenceQueries, get_evidence
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.retrieval.presentation import safe


def configure(commands):
    for name in ('ingest-mft', 'ingest-prefetch', 'ingest-registry', 'ingest-all', 'ingest-evtx'):
        p = commands.add_parser(name, help=COMMANDS[name])
        p.add_argument('path')
        p.add_argument('--hostname')
        p.add_argument('--user')
        p.add_argument('--volume-root')
        p.add_argument('--parser-timeout', type=int, default=300)
        p.add_argument('--record-size', type=int)
        p.add_argument('--json', action='store_true')
    for name in ('search', 'timeline'):
        p = commands.choices[name]
        p.add_argument('--artifact', choices=['evtx', 'mft', 'prefetch', 'registry'])
        p.add_argument('--path')
    for name in ('search', 'show', 'status'):
        commands.choices[name].add_argument('--json', action='store_true')
    keys = commands.choices['search'].add_mutually_exclusive_group()
    keys.add_argument('--key', help='Registry key path: exact literal match (SQLite NOCASE); includes its values; no filesystem normalization')
    keys.add_argument('--key-contains', help='Registry key path: literal substring (SQLite NOCASE); no wildcards; includes matching keys and their values')
    values = commands.choices['search'].add_mutually_exclusive_group()
    values.add_argument('--value-name', help='Registry value name: exact raw or decoded UserAssist name (SQLite NOCASE)')
    values.add_argument('--value-name-contains', help='Registry value name: literal substring of raw or decoded UserAssist name (SQLite NOCASE); no wildcards')
    commands.choices['around'].add_argument('--timestamp-slot')
    commands.choices['investigate'].add_argument('--timestamp-slot')



def ingest_sources(db, args, progress=None):
    from forensic_assistant.database import sources
    from forensic_assistant.ingest.evtx import discover as evtx_discover
    sources.require4(db)
    requested = args.command.removeprefix('ingest-')
    results = []
    source_id = getattr(args, 'source', None)
    supplied = {k: getattr(args, k, None) for k in ('hostname', 'user', 'volume_root')}
    # Existing-source metadata is changed only by an explicit source update action.
    if source_id and any(v is not None for v in supplied.values()):
        raise ValueError('Use source update to change metadata on an existing --source')
    batch_id = sources.identifier('batch')
    with db:
        if source_id:
            sources.current(db, source_id)
        else:
            source_id = sources.create(
                db,
                name=getattr(args, 'source_name', None),
                hostname=supplied['hostname'],
                username=supplied['user'],
                volume_root=supplied['volume_root'],
                automatic=not getattr(args, 'source_explicit', False)
            )
        db.execute(
            'INSERT INTO ingestion_batches VALUES (?,?,?,?,?,?,?)',
            (batch_id, source_id, now(), None, str(args.path), args.command, 'running')
        )
    status = 'failed'
    try:
        files = ((p, 'evtx') for p in evtx_discover(args.path)) if args.command == 'ingest' else discover(
            args.path,
            None if requested == 'all' else requested
        )
        for path, kind in files:
            if kind == 'evtx':
                result = ingest_file(db, path, batch_id=batch_id)
            else:
                result = ingest_artifact(
                    db,
                    path,
                    kind,
                    timeout=args.parser_timeout,
                    record_size=args.record_size,
                    batch_id=batch_id
                )
            results.append(result)
            if progress is not None:
                progress(path, kind, result)
        status = 'empty' if not results else 'complete' if all(r['status'] == 'complete' for r in results) else 'unsupported' if all(r['status'] == 'unsupported' for r in results) else 'partial' if any(r['inserted'] or r['duplicates'] for r in results) else 'failed'
        return results
    except (KeyboardInterrupt, EOFError):
        status = 'cancelled'
        raise
    except BaseException:
        from forensic_assistant.investigation_ai.lifecycle import CleanupError
        import sys
        if isinstance(sys.exception(), CleanupError):
            status = 'cleanup_unconfirmed'
            raise
        status = 'partial' if db.execute(
            'SELECT 1 FROM ingestion_runs WHERE batch_id=? AND file_sha256 IS NOT NULL',
            (batch_id,)
        ).fetchone() else 'failed'
        raise
    finally:
        db.rollback()
        with db:
            db.execute(
                'UPDATE ingestion_batches SET status=?,finished_utc=? WHERE batch_id=?',
                (status, now(), batch_id)
            )

def dispatch(db, args, *, presentation=None):
    command = args.command
    q = EvidenceQueries(db)
    if command.startswith('ingest-'):
        results = ingest_sources(db, args)
        return {
            'results': results,
            'status': 'complete' if results and all(r['status'] == 'complete' for r in results) else 'incomplete'
        }, 0 if results and all(r['status'] == 'complete' for r in results) else 1
    if command == 'show':
        result = get_evidence(db, args.evidence_id, args.raw)
        if presentation is not None and not args.raw and not args.json and result['artifact_type'] == 'registry_key':
            from forensic_assistant.retrieval.registry_display import projected_values
            presentation['registry_values'] = projected_values(db, result['id'])
        return result, 0
    if command == 'status':
        from forensic_assistant.database.sources import coverage
        from forensic_assistant.artifacts.userassist import timeline_cte
        result = Queries(db).coverage()
        result.update(
            schema_version=db.execute('PRAGMA user_version').fetchone()[0],
            source_coverage=coverage(db),
            artifact_counts={r[0]: r[1] for r in db.execute('SELECT source_type,count(*) FROM evidence_records GROUP BY source_type')},
            timeline_observations=db.execute(timeline_cte(db) + 'SELECT count(*) FROM locard_times WHERE timestamp_utc IS NOT NULL').fetchone()[0]
        )
        if presentation is not None and not getattr(args, 'raw', False) and not args.json:
            from forensic_assistant.retrieval.status_display import context
            presentation['status'] = context(db)
        return result, 0
    if command in ('search', 'timeline'):
        filters = {k: getattr(args, k, None) for k in ('artifact', 'path', 'process', 'hostname', 'ip', 'event_id')}
        filters.update(username=args.user, limit=args.limit, offset=args.offset, raw=args.raw)
        if command == 'search':
            filters.update(registry_key=getattr(args, 'key', None), registry_key_contains=getattr(args, 'key_contains', None))
            filters.update(value_name=getattr(args, 'value_name', None), value_name_contains=getattr(args, 'value_name_contains', None))
            filters['process_exact'] = filters.pop('process')
            filters['process_contains'] = args.process_contains
            filters['source_id'] = getattr(args, 'source', None)
            kinds = {
                'logons': ['logon', 'explicit_credentials', 'privileged_logon'],
                'failed-logons': ['failed_logon'],
                'processes': ['process'],
                'scheduled-tasks': ['scheduled_task'],
                'services': ['service'],
                'account-changes': ['account_creation', 'group_membership']
            }
            if args.kind == 'powershell':
                filters['powershell'] = True
            elif args.kind:
                filters['artifact_types'] = kinds[args.kind]
            result = q.search(start=args.start, end=args.end, **filters)
        else:
            if args.timestamp and args.around:
                raise ValueError('Specify either positional timestamp or --around')
            anchor = args.timestamp or args.around
            if args.artifact_type:
                filters['artifact_types'] = [args.artifact_type]
            grouped_text = getattr(args, 'text', False) and not args.raw and not getattr(args, 'json', False) and args.artifact in (None, 'mft', 'evtx')
            if not 1 <= args.limit <= 10000 or args.offset < 0:
                raise ValueError('Invalid pagination bounds')
            if anchor:
                if args.start or args.end:
                    raise ValueError('Do not combine --around with --start/--end')
                if grouped_text and args.artifact is None:
                    kinds = {kind for kind in ('mft', 'evtx', 'prefetch', 'registry')
                             if q.timeline_around(anchor, args.minutes, **dict(
                                 filters, artifact=kind, limit=1, offset=0)).total}
                    grouped_text = len(kinds) > 1 or bool(kinds & {'mft', 'evtx'})
                result = q.complete_timeline(around=anchor, minutes=args.minutes, **{
                    k: v for k, v in filters.items() if k not in ('limit', 'offset')
                }) if grouped_text else q.timeline_around(anchor, args.minutes, **filters)
            else:
                if not args.start or not args.end:
                    raise ValueError('Timeline requires --start and --end, or --around')
                if grouped_text and args.artifact is None:
                    kinds = {kind for kind in ('mft', 'evtx', 'prefetch', 'registry')
                             if q.search(start=args.start, end=args.end, timeline=True, **dict(
                                 filters, artifact=kind, limit=1, offset=0)).total}
                    grouped_text = len(kinds) > 1 or bool(kinds & {'mft', 'evtx'})
                result = q.complete_timeline(start=args.start, end=args.end, **{
                    k: v for k, v in filters.items() if k not in ('limit', 'offset')
                }) if grouped_text else q.search(start=args.start, end=args.end, timeline=True, **filters)
        # Keep shared, read-only hydration in text windows; as_dict deep-copies
        # every observation's full evidence detail and is reserved for serialization.
        output = {**vars(result), 'truncated': result.truncated} if command == 'timeline' and grouped_text else result.as_dict()
        if command == 'timeline' and grouped_text:
            from forensic_assistant.retrieval import mft_display, evtx_display, mixed_display
            mixed = mixed_display.is_mixed(output)
            display = evtx_display if mixed or args.artifact == 'evtx' or any(r['source_type'] == 'evtx' for r in output['records']) else mft_display
            output = display.page(output, args.limit, args.offset)
            if mixed:
                output['_mixed_text'] = True
        output['count_unit'] = 'timestamp_observations' if command == 'timeline' else 'evidence_records'
        output['caution'] = 'Timestamp semantics differ by artifact. Correlation is not causation.'
        return output, 0
    if command == 'around':
        from forensic_assistant.correlation.temporal import shift
        anchor = get_evidence(db, args.evidence_id)
        stamp = anchor_time(anchor, args.timestamp_slot, require_slot=anchor['source_type'] == 'mft')
        if presentation is not None:
            presentation.update(anchor=anchor, stamp=stamp)
        source_ids = anchor['context'].get('source_ids', [])
        if len(source_ids) > 1:
            raise ValueError('Multiple source occurrences; cannot select an unambiguous source')
        if not anchor['host_key']:
            raise ValueError('Host context missing or conflicting; cannot select same-host temporal neighbors')
        if not 0 <= args.seconds <= 604800:
            raise ValueError('Seconds must be 0..604800')
        grouped_text = getattr(args, 'text', False) and not args.raw and not getattr(args, 'json', False)
        if not 1 <= args.limit <= 10000 or args.offset < 0:
            raise ValueError('Invalid pagination bounds')
        # Same-host temporal context may cross source memberships; the shared
        # strict resolver still excludes unknown, ambiguous and conflicting hosts.
        window = dict(
            start=shift(stamp, -args.seconds) if args.direction != 'after' else stamp,
            end=shift(stamp, args.seconds) if args.direction != 'before' else stamp,
            exclude_time=stamp if args.direction != 'around' else None,
            hostname=anchor['host_key'],
            strict_host=True,
            raw=args.raw
        )
        if grouped_text:
            from forensic_assistant.retrieval import mft_display, evtx_display, mixed_display
            result = q.complete_timeline(**window)
            output = {**vars(result), 'truncated': result.truncated}
            mixed = mixed_display.is_mixed(output, anchor)
            display = evtx_display if mixed or anchor['source_type'] == 'evtx' else mft_display
            output = display.page(output, args.limit, args.offset,
                                  anchor=anchor, stamp=stamp, selected_slot=args.timestamp_slot)
            if mixed:
                output['_mixed_text'] = True
            return output, 0
        result = q.search(timeline=True, limit=args.limit, offset=args.offset, **window)
        return result.as_dict(), 0
    return None


def anchor_time(anchor, slot=None, *, require_slot=False):
    require_slot = require_slot or bool(anchor.get('detail', {}).get('userassist'))
    candidates = [t for t in anchor['timestamps'] if t['timestamp_utc'] and (slot is None or t['slot'] == slot)]
    times = {t['timestamp_utc'] for t in candidates}
    if len(times) != 1 or (require_slot and len(candidates) != 1):
        raise ValueError('Anchor has missing or multiple timestamps; select --timestamp-slot from show output')
    return next(iter(times))


def render(result, *, methodology=True, palette=None):
    if 'records' not in result:
        return safe(result)
    from forensic_assistant.retrieval import mixed_display
    if not methodology and mixed_display.is_mixed(result):
        return mixed_display.render(result, palette=palette)
    if not methodology and result['records'] and all(r['source_type'] == 'prefetch' for r in result['records']):
        from forensic_assistant.retrieval.prefetch_display import render_timeline
        return render_timeline(result, palette=palette)
    if not methodology and ('_evtx_page' in result or any(r['source_type'] == 'evtx' for r in result['records'])):
        from forensic_assistant.retrieval.evtx_display import render_timeline
        return render_timeline(result, palette=palette)
    if not methodology and ('_mft_page' in result or any(r['source_type'] == 'mft' for r in result['records'])):
        from forensic_assistant.retrieval.mft_display import render_timeline
        return render_timeline(result)
    lines = ['UTC | EVIDENCE ID | SOURCE | ARTIFACT TYPE | TIMESTAMP MEANING | OBJECT / OBSERVATION']
    for r in result['records']:
        obj = next((o['original'] for o in r.get('objects', []) if o['role'] not in ('parent_image',)), None)
        from forensic_assistant.retrieval.presentation import detail
        observation = detail(r) if r['source_type'] == 'evtx' else obj or r.get('observation')
        values = (
            r.get('timestamp_utc'),
            r['id'],
            r['source_type'],
            r.get('artifact_type'),
            r.get('timestamp', {}).get('source'),
            observation
        )
        if not methodology and r.get('detail', {}).get('userassist'):
            from forensic_assistant.retrieval.presentation import safe_path
            lines.append(' | '.join(safe(v) for v in values[:-1]) + ' | ' + safe_path(values[-1]))
        else:
            lines.append(' | '.join(safe(v) for v in values))
    lines.append(f"Displayed {len(result['records'])} / {result['total']}; truncated={result['truncated']}")
    if methodology:
        lines.append('CORRELATION != CAUSATION. Timestamp semantics differ by artifact.')
    return '\n'.join(lines)

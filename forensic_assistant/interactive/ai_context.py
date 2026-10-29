"""Bounded advisory metadata, read afresh in one short read-only snapshot."""
from contextlib import closing
import time
import json
import logging
import sqlite3

from forensic_assistant import __version__
from forensic_assistant.command_catalog import investigation_capabilities
from forensic_assistant.database.sources import current
from forensic_assistant.investigation_ai.case import open_readonly, read_transaction
from .case import check_structure

SOURCE_LIMIT = 8
TEXT_LIMIT = 160
BUILD_SECONDS = 3
MAX_CONTEXT_BYTES = 65536
_LOG = logging.getLogger(__name__)


class ContextBuildError(ValueError):
    """Safe diagnostic fields only; never stores raw exceptions or case contents."""
    def __init__(self, reason, stage, code=None, retryable=False):
        label = {
            'database_busy': 'database busy',
            'read_deadline': 'context timeout',
            'database_read': 'database access failure',
            'filesystem_read': 'database access failure',
            'case_validation': 'context validation failure',
            'source_metadata': 'source metadata validation failure',
            'context_size': 'context size limit',
            'query_failure': 'database query failure',
        }.get(reason, 'controlled internal failure')
        super().__init__(f'AI case context unavailable ({label}). No action was taken.')
        self.reason, self.stage = reason, stage
        self.sqlite_code, self.retryable = code, retryable


def _failure(exc, stage, deadline):
    code = getattr(exc, 'sqlite_errorcode', None)
    code = code if type(code) is int else None
    primary = code & 255 if code is not None else None
    read_stage = stage in ('open', 'validation', 'inventory', 'sources')
    transient = read_stage and primary in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
    if transient:
        reason = 'database_busy'
    elif read_stage and primary == sqlite3.SQLITE_INTERRUPT and time.monotonic() >= deadline:
        reason, transient = 'read_deadline', True
    elif isinstance(exc, sqlite3.ProgrammingError):
        reason = 'connection_or_programming'
    elif isinstance(exc, sqlite3.Error):
        reason = 'database_read' if stage == 'open' else 'query_failure'
    elif isinstance(exc, OSError):
        reason = 'filesystem_read'
    elif stage == 'catalog':
        reason = 'command_catalog'
    elif stage == 'size_limit':
        reason = 'context_size'
    elif isinstance(exc, (TypeError, ValueError)):
        reason = {'sources': 'source_metadata', 'validation': 'case_validation',
                  'open': 'case_validation'}.get(stage, 'context_build')
    else:
        reason = 'unexpected_exception'
    return ContextBuildError(reason, stage, code, transient)


def build_ai_case_context(path, case_name):
    """At most two independent snapshots; only recognized transient reads retry."""
    for attempt in (1, 2):
        _LOG.debug('AI context attempt=%s budget_seconds=%s', attempt, BUILD_SECONDS)
        try:
            context = _build_ai_case_context(path, case_name, time.monotonic() + BUILD_SECONDS)
        except ContextBuildError as exc:
            retry = attempt == 1 and exc.retryable
            # No exception text, traceback, paths, labels, queries or prompt content.
            _LOG.debug('AI context failure stage=%s reason=%s sqlite_code=%s attempt=%s retry=%s',
                       exc.stage, exc.reason, exc.sqlite_code, attempt, retry)
            if not retry:
                raise
        else:
            if attempt == 2:
                _LOG.debug('AI context retry succeeded')
            return context


def _build_ai_case_context(path, case_name, deadline):
    stage = 'catalog'
    started = phase_started = time.perf_counter()
    cpu_started = time.process_time()

    def phase(next_stage):
        nonlocal stage, phase_started
        now = time.perf_counter()
        _LOG.debug('AI context timing stage=%s seconds=%.6f', stage, now - phase_started)
        stage, phase_started = next_stage, now
        remaining = deadline - time.monotonic()
        _LOG.debug('AI context phase_start stage=%s remaining_seconds=%.6f deadline_exceeded=%s',
                   stage, max(0.0, remaining), remaining <= 0)

    try:
        # Use the actual search parser's supported categories, including absent ones.
        from forensic_assistant.cli import build_parser
        parser = build_parser()
        search = next(a for a in parser._actions if hasattr(a, 'choices') and
                      isinstance(a.choices, dict)).choices['search']
        categories = next(a.choices for a in search._actions if a.dest == 'artifact')
        truncated_fields = []

        def bounded(value, field):
            if value is None:
                return None
            if not isinstance(value, str):
                raise ValueError('Invalid context metadata type')
            if len(value) > TEXT_LIMIT:
                truncated_fields.append(field)
            return value[:TEXT_LIMIT]

        capabilities = investigation_capabilities()
        phase('metadata')
        context = {
            'case_name': bounded(case_name, 'case_name'),
            'locard_version': __version__,
            'case_context_available': True, 'individual_records_inspected': False,
            'forensic_conclusions_reached': False,
            'artifact_inventory': {kind: 0 for kind in categories},
            'count_basis': 'Retained normalized evidence records, not files or ingestion attempts',
            'manual_commands': capabilities,
        }
        phase('open')
        with closing(open_readonly(path, deadline=deadline)) as db:
            with read_transaction(db):
                phase('validation')
                check_structure(db)
                phase('inventory')
                for kind in categories:
                    context['artifact_inventory'][kind] = db.execute(
                        'SELECT count(*) FROM evidence_records WHERE source_type=?', (kind,)
                    ).fetchone()[0]
                counts = context['artifact_inventory']
                context['artifact_availability'] = {
                    'available': [kind for kind, count in counts.items() if count > 0],
                    'unavailable': [kind for kind, count in counts.items() if count == 0],
                }
                phase('sources')
                sources = {'total': None, 'shown': 0, 'truncated': False, 'items': [],
                           'basis': 'Analyst-supplied assertions, not verified findings'}
                if db.execute('PRAGMA user_version').fetchone()[0] >= 4:
                    sources['total'] = db.execute('SELECT count(*) FROM sources').fetchone()[0]
                    ids = [r[0] for r in db.execute(
                        'SELECT source_id FROM sources ORDER BY created_utc,source_id LIMIT ?',
                        (SOURCE_LIMIT,))]
                    for index, sid in enumerate(ids):
                        row = current(db, sid)
                        sources['items'].append({field: bounded(row[field], f'sources[{index}].{field}')
                                                 for field in ('display_name', 'hostname', 'username', 'volume_root')})
                    sources['shown'] = len(ids)
                    sources['truncated'] = sources['total'] > len(ids)
                else:
                    sources['unavailable_reason'] = 'Schema has no source assertion registry'
                context['sources'] = sources
        context['truncated_fields'] = truncated_fields
        phase('serialization')
        if len(json.dumps(context, ensure_ascii=True).encode('utf-8')) > MAX_CONTEXT_BYTES:
            phase('size_limit')
            raise ValueError('Context exceeds size bound')
        return context
    except Exception as exc:
        raise _failure(exc, stage, deadline) from None
    finally:
        finished = time.perf_counter()
        _LOG.debug('AI context timing stage=%s seconds=%.6f', stage, finished - phase_started)
        _LOG.debug('AI context timing stage=total seconds=%.6f', finished - started)
        _LOG.debug('AI context completion cpu_seconds=%.6f deadline_exceeded=%s',
                   time.process_time() - cpu_started, time.monotonic() >= deadline)

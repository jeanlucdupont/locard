"""Bounded advisory metadata, read afresh in one short read-only snapshot."""
from contextlib import closing
import time

from forensic_assistant import __version__
from forensic_assistant.command_catalog import investigation_capabilities
from forensic_assistant.database.sources import current
from forensic_assistant.investigation_ai.case import open_readonly, read_transaction
from .case import check_structure

SOURCE_LIMIT = 8
TEXT_LIMIT = 160


def build_ai_case_context(path, case_name):
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
        if len(value) > TEXT_LIMIT:
            truncated_fields.append(field)
        return value[:TEXT_LIMIT]

    context = {
        'case_name': bounded(case_name, 'case_name'),
        'locard_version': __version__, 'mode': 'AI',
        'case_context_available': True, 'individual_records_inspected': False,
        'forensic_conclusions_reached': False,
        'artifact_inventory': {kind: 0 for kind in categories},
        'count_basis': 'Retained normalized evidence records, not files or ingestion attempts',
        'manual_commands': investigation_capabilities(),
    }
    with closing(open_readonly(path, deadline=time.monotonic() + 3)) as db:
        with read_transaction(db):
            check_structure(db)
            for kind in categories:
                context['artifact_inventory'][kind] = db.execute(
                    'SELECT count(*) FROM evidence_records WHERE source_type=?', (kind,)
                ).fetchone()[0]
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
    return context

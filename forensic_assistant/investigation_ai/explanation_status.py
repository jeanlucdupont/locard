"""Diagnostic projections only; never part of checkpoint state or evidence authority."""

CONTRACT = 'explanation-diagnostics-v1'
MAX_ATTEMPTS = 9


def validate(value):
    """Telemetry is bounded and non-authoritative; never used to replay operations."""
    import json
    outcomes = {'admission_rejected', 'committed_prefix', 'committed_complete', 'publication_uncertain'}
    reasons = {None, 'event_byte_limit', 'local_journal_allocation_limit', 'global_journal_reservation',
               'journal_event_slot_limit', 'operation_limit', 'dependency_visit_limit', 'processing_time_limit',
               'preparation_failed', 'memory_limit', 'checkpoint_limit', 'pending_dependency',
               'admission_limit', 'index_edge_limit', 'checkpoint_append', 'commit_after_publication'}
    numbers = {'event_bytes', 'event_limit', 'local_bytes', 'local_remaining_bytes', 'global_bytes',
               'global_limit', 'future_reserved_bytes', 'remaining_event_slots', 'future_reserved_slots'}
    def integer(n):
        return type(n) is int and 0 <= n <= 2**63 - 1
    if (type(value) is not dict or set(value) != {'contract', 'attempts', 'omitted_attempts', 'time_limit_exceeded'} or
            value['contract'] != CONTRACT or type(value['attempts']) is not list or
            type(value['time_limit_exceeded']) is not bool or
            len(value['attempts']) > MAX_ATTEMPTS or not integer(value['omitted_attempts']) or
            value['omitted_attempts'] > 256 or len(json.dumps(value).encode()) > 8192):
        raise ValueError('Invalid explanation diagnostics')
    for row in value['attempts']:
        if (type(row) is not dict or set(row) != {'c1_revision', 'outcome', 'reason', 'event_size_basis',
                'candidate_operations_considered', 'prepared_operations', 'committed_operations', 'details'} or
                not integer(row['c1_revision']) or not 1 <= row['c1_revision'] <= 9 or
                type(row['outcome']) is not str or
                (row['reason'] is not None and type(row['reason']) is not str) or
                row['outcome'] not in outcomes or row['reason'] not in reasons or
                row['event_size_basis'] not in ('measured', 'unavailable') or
                not integer(row['committed_operations']) or
                any(v is not None and not integer(v) for v in
                    (row['candidate_operations_considered'], row['prepared_operations']))):
            raise ValueError('Invalid explanation attempt diagnostic')
        details = row['details']
        if ((details is None) != (row['event_size_basis'] == 'unavailable') or
                details is not None and (type(details) is not dict or set(details) != numbers or
                                         any(not integer(n) for n in details.values()))):
            raise ValueError('Invalid explanation size diagnostic')


def reason(code):
    return {'dependency_limit': 'dependency_visit_limit',
            'time_limit': 'processing_time_limit',
            'local_time_overrun': 'processing_time_limit'}.get(code, code)


def admission(details):
    """Same admission predicates and order as the original combined gate."""
    if details['event_bytes'] > details['event_limit']:
        return 'event_byte_limit'
    if details['event_bytes'] > details['local_remaining_bytes']:
        return 'local_journal_allocation_limit'
    if details['global_bytes'] + details['event_bytes'] + details['future_reserved_bytes'] > details['global_limit']:
        return 'global_journal_reservation'
    if 1 + details['future_reserved_slots'] > details['remaining_event_slots']:
        return 'journal_event_slot_limit'
    return None


def currentness(committed, latest):
    if committed is None or latest is None:
        return 'unavailable'
    fields = ('run_id', 'read_view', 'revision', 'digest', 'event', 'source_frontier')
    return 'current' if all(committed[k] == latest[k] for k in fields) else 'stale'


def project(state, latest, upstream, *, finalized):
    committed = state['frontier']['receipt'] if state['frontier'] else None
    current = currentness(committed, latest)
    pending, omitted = len(state['pending']), len(state['omitted'])
    if pending or omitted:
        processing = ('pending' if state['stop'] == 'pending_dependency' else
                      'resource_limited' if state['stop'] else 'partial')
    elif committed is None or current != 'current':
        processing = 'pending'
    elif not finalized:
        processing = 'partial'
    else:
        processing = 'complete'
    return dict(currentness=current, processing=processing,
                upstream='unavailable' if upstream is None else 'complete' if upstream else 'partial',
                c1_revision=committed['revision'] if committed else None,
                accepted=len(state['items']), pending=pending, omitted=omitted,
                final_assessment_available=state['coverage'].get('final_assessment_available', False),
                final_assessment_represented=state['coverage'].get('final_assessment_represented', False),
                forensic_completeness='not_established')


def from_summary(summary):
    if 'status' in summary:
        return summary['status']
    # Legacy display fallback only. Historical replay computes exact frontier status.
    coverage = summary.get('coverage', {})
    current = ('unavailable' if not summary.get('checkpoint') else
               'stale' if summary.get('stale') else 'current')
    return dict(currentness=current,
                processing='partial' if coverage.get('pending') or coverage.get('omitted') else
                           'complete' if current == 'current' else 'pending',
                upstream='unavailable' if 'upstream_partial' not in summary else
                         'partial' if summary['upstream_partial'] else 'complete',
                c1_revision=summary.get('c1_revision'), accepted=coverage.get('accepted', 0),
                pending=coverage.get('pending', 0), omitted=coverage.get('omitted', 0),
                final_assessment_available=coverage.get('final_assessment_available', False),
                final_assessment_represented=coverage.get('final_assessment_represented', False))


def lines(status):
    current = status['currentness']
    if current == 'current':
        current = 'current at C1 revision ' + str(status['c1_revision'])
    elif current == 'stale':
        current = 'stale; represents C1 revision ' + str(status['c1_revision'])
    assessment = 'available' if status['final_assessment_available'] else 'unavailable'
    if status['final_assessment_available'] and not status['final_assessment_represented']:
        assessment += ' (not represented in this revision)'
    return ['Explanation: ' + current + '.',
            'Explanation components: ' + str(status['accepted']) + ' accepted; ' +
            str(status['pending']) + ' pending; ' + str(status['omitted']) + ' omitted.',
            'Explanation processing: ' + ('complete within admitted component scope' if status['processing'] == 'complete'
                                           else status['processing'].replace('_', '-')) + '.',
            'Upstream organization: ' + status['upstream'] + '.',
            'Final assessment: ' + assessment + '.',
            'Forensic completeness: not established.']

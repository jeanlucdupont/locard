"""Human projection of controller-validated data; never a model summary."""
import re
from forensic_assistant.interactive.console import safe
from forensic_assistant.terminal import Palette

LABELS = {
    'ANSWER_SUPPORTED': 'Supported findings from disclosed evidence',
    'USER_REJECTED': 'Analyst rejected proposed lookup',
    'TOO_MANY_REJECTIONS': 'Rejection limit reached',
    'BUDGET_EXHAUSTED': 'Investigation budget exhausted',
    'WORKER_FAILURE': 'Investigation worker failed',
    'TRANSCRIPT_FAILURE': 'Investigation record could not be saved',
    'TOOL_LOOP': 'Repeated lookup proposal stopped the investigation',
    'TIMEOUT': 'Investigation time limit reached',
    'INTEGRITY_FAILURE': 'Case integrity verification failed',
    'INTEGRITY_UNCONFIRMED': 'Case integrity could not be confirmed',
    'FINGERPRINT_FAILURE': 'Evidence integrity calculation failed',
    'INITIAL_RETRIEVAL_FAILURE': 'Initial evidence lookup failed',
    'WORKER_START_FAILURE': 'Investigation could not start',
    'MODEL_FAILURE': 'AI model failure',
    'MAX_SECONDS': 'Investigation time limit reached',
    'STARTUP_TIMEOUT': 'Investigation startup timed out',
    'EVIDENCE_STATE_CHANGED': 'The live case changed during investigation; final acceptance stopped',
    'SEMANTIC_STATE_CHANGED': 'Semantic index changed during investigation',
    'USER_SCOPE_REACHED': 'Requested scope reached or analyst interrupted',
    'INSUFFICIENT_EVIDENCE': 'Insufficient disclosed evidence',
    'NO_NEW_EVIDENCE': 'No new evidence from repeated operations',
    'TOOL_FAILURE': 'Forensic lookup failed',
    'AUDIT_FAILURE': 'Required audit recording failed',
    'CLEANUP_LIMITATION': 'Worker or temporary snapshot cleanup could not be confirmed',
}


# Match known generic messages only; unknown caveats remain visible.
GENERIC = {
    'Bounded investigation; absence of findings does not prove absence of activity',
    'Findings refer only to the recorded original evidence fingerprint; later case states are not covered',
    'ANSWER_SUPPORTED means validated disclosed structure, not scientific proof or model accuracy',
    'Hypotheses and model-proposed unknowns are unverified',
    'Reported field; not proof of execution, attribution, intent or causation',
    'Reported field; not proof of execution or causation',
}
SOURCE = {
    'Source metadata includes analyst assertions; these are not independently verified artifact facts',
    'Source metadata includes analyst assertions, not independently verified facts',
    'Source metadata includes analyst assertions; it is not independently verified evidence',
    'Source metadata includes analyst assertions',
}
TRUNCATION = {
    'Some evidence fields are truncated; inspect the original records',
    'Some exposed fields are truncated; absence is not established',
    'Some evidence fields were truncated; omitted values are unavailable',
}


def limitations(values, *, source_material=False):
    result = []
    for value in values:
        if not value:
            continue
        value = str(value)
        key = value.rstrip('.')
        source_key = key.replace('Source metadata contains', 'Source metadata includes')
        if key in GENERIC:
            continue
        if source_key in SOURCE:
            if not source_material:
                continue
            value = 'Source context relies on analyst-supplied metadata; it is not independently verified.'
        elif key in TRUNCATION:
            value = 'Some evidence fields were truncated.'
        elif key in ('Dirty hive: transaction logs were not replayed; snapshot may be inconsistent',
                     'Registry hive was dirty; transaction logs were not replayed'):
            value = 'Registry hive was dirty; transaction logs were not replayed.'
        # Unknown case-specific warnings retain their original qualification.
        if value not in result:
            result.append(value)
    return result


def source_dependency(row):
    field = str(row.get('field', ''))
    if field.startswith('/source_context/assertions/'):
        return True
    attribution = field in ('/hostname', '/username', '/volume_root', '/host_context_basis')
    relation = bool(row.get('relationship'))
    basis = row.get('host_context_basis') or (row.get('source_context') or {}).get('basis')
    # Unknown bases do not become analyst assertions just because context exists.
    analyst_basis = isinstance(basis, str) and ('analyst' in basis.casefold() or 'source_assertion' in basis.casefold())
    return (attribution or relation) and analyst_basis


def termination_label(result):
    code = result.get('termination')
    if code == 'BUDGET_EXHAUSTED':
        # This code covers several budgets. Only call it a step limit when the
        # deterministic path has no competing limit/error reason.
        limits = (result.get('state') or {}).get('limitations') or []
        if 'Tool-call budget exhausted' in limits:
            return 'Forensic lookup limit reached'
        return 'Investigation limit reached'
    return LABELS.get(code, 'Investigation ended; see diagnostic details for the termination reason')


def field_label(row):
    path = str(row.get('field', ''))
    match = re.fullmatch(r'/timestamps/(\d+)/utc', path)
    semantics = row.get('timestamp_semantics')
    if match and isinstance(semantics, list):
        index = int(match[1])
        if index < len(semantics) and isinstance(semantics[index], dict):
            stamp = semantics[index]
            if stamp.get('utc') == row.get('reported_value') and stamp.get('type'):
                return safe(stamp['type']), True
    if path in ('/timestamp', '/timestamp_utc') and isinstance(semantics, str) and semantics:
        return safe(semantics), True
    return safe(path.strip('/').replace('/', ' / ').replace('_', ' ')), False


def timestamp_text(value):
    # Preserve precision and timezone; only simplify an explicit UTC representation.
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d+)?Z', str(value))
    if not match:
        return safe(value)
    fraction = (match[3] or '').rstrip('0').rstrip('.')
    return match[1] + ' ' + match[2] + fraction + ' UTC'


def proposal_text(proposal, palette=None, *, introduction=False):
    palette = palette or Palette()
    lines = ([palette('secondary_text', 'More evidence is needed to answer the question.'), ''] if introduction else []) + [
             palette('heading', 'Proposed forensic lookup'),
             '  Tool: ' + palette('key', safe(proposal.get('tool', '')))]
    for key, value in proposal.get('arguments', {}).items():
        label = 'Evidence ID' if key == 'evidence_id' else key.replace('_', ' ').capitalize()
        role = 'evidence_id' if key == 'evidence_id' else 'string_value'
        lines.append('  ' + label + ': ' + palette(role, safe(value)))
    if proposal.get('reason'):
        lines.append('  Reason: ' + safe(proposal['reason']))
    return '\n'.join(lines)


def render(result, palette=None, *, dry_run=False):
    palette = palette or Palette()
    supported = result.get('termination') == 'ANSWER_SUPPORTED'
    dry_run = dry_run or bool(result.get('dry_run_proposal'))
    lines = [palette('success' if supported else 'warning',
                     'Investigation result' if supported else 'Investigation incomplete')]
    findings = result.get('findings') or {}
    caveats = list(result.get('limitations') or [])
    state = result.get('state') or {}
    caveats.extend(state.get('limitations') or [])
    source_material = False
    for title, key in [('Observed evidence', 'observed'),
                       ('Deterministic relationships', 'deterministically_correlated'),
                       ('Corroborated evidence', 'corroborated'),
                       ('Unresolved relationships', 'unresolved_relationships'),
                       ('Detections (not proof of compromise)', 'detections')]:
        rows = findings.get(key) or []
        if not rows:
            continue
        lines.extend(['', palette('heading', title)])
        for row in rows:
            if key == 'observed':
                label, timestamp = field_label(row)
                value = timestamp_text(row.get('reported_value')) if timestamp else safe(row.get('reported_value'))
                lines.append('  ' + palette('key', label) + ': ' + palette('string_value', value))
                caveats.append(row.get('qualifier'))
            else:
                source_material |= source_dependency(row)
                lines.append('  ' + safe(row.get('relationship') or row.get('rule_name') or row.get('rule_id', 'Relationship'))
                             + ' — ' + safe(row.get('status') or row.get('correlation_status', '')))
                if row.get('reason'):
                    lines.append('    ' + safe(row['reason']))
            for eid in row.get('evidence_ids', []):
                lines.append('    Evidence: ' + palette('evidence_id', safe(eid)))
            context = row.get('source_context') or {}
            source_material |= source_dependency(row)
            if context:
                caveats.append('Source metadata includes analyst assertions; it is not independently verified evidence.')
            if row.get('truncated_fields'):
                caveats.append('Some evidence fields were truncated; omitted values are unavailable.')
            caveats.extend(row.get('warnings') or [])
            caveats.extend(row.get('limitations') or [])
    completed = sum(p.get('operation') != 'initial' for p in state.get('investigation_path', []) if isinstance(p, dict))
    if completed and not dry_run:
        lines.extend(['', palette('heading', 'Forensic lookups'), '  Completed: ' + palette('number_value', str(completed))])
    count = state.get('final_grounding_rejections', 0)
    if not supported and type(count) is int and 1 <= count <= 16:
        noun, verb = ('conclusion', 'was') if count == 1 else ('conclusions', 'were')
        message = f'Locard rejected {count} AI {noun} that {verb} not supported by the evidence available to the model.'
        lines.extend(['', palette('heading', 'AI validation'), palette('warning', '  ' + message)])
    elif state.get('rejected_requests'):
        lines.extend(['', palette('heading', 'AI validation'), palette('warning', '  Rejected proposals: ' + str(state['rejected_requests']))])
    if result.get('dry_run_proposal'):
        lines.extend(['', palette('heading', 'Dry-run proposal'), '', proposal_text(result['dry_run_proposal'], palette, introduction=True),
                      '', palette('secondary_text', 'No operation was executed.')])
    termination = result.get('termination')
    integrity = (result.get('metrics') or {}).get('integrity') or {}
    integrity_warning = (integrity.get('strategy') == 'private_sqlite_snapshot'
                         and integrity.get('live_case_matches') is not True)
    integrity_termination = termination in ('EVIDENCE_STATE_CHANGED', 'INTEGRITY_FAILURE', 'INTEGRITY_UNCONFIRMED')
    if not supported:
        if not (integrity_warning and integrity_termination):
            label = 'Dry-run completed' if dry_run and termination == 'USER_SCOPE_REACHED' else termination_label(result)
            role = 'error' if termination in ('TOOL_FAILURE', 'MODEL_FAILURE', 'AUDIT_FAILURE', 'CLEANUP_LIMITATION') else 'warning'
            lines.extend(['', palette('heading', 'Termination'), '  ' + palette('success' if label == 'Dry-run completed' else role, label)])
        lines.append(palette('warning', '  No supported conclusion was produced.'))
    # Render one integrity warning; suppress only duplicate controller check details.
    if integrity_warning:
        text = ('The live case changed during the investigation. Findings were not accepted against the changed case state.'
                if integrity.get('live_case_matches') is False else
                'Locard could not confirm that the live case still matched the investigation snapshot.')
        lines.extend(['', palette('warning', 'Warning'), '  ' + palette('warning', text)])
        caveats = [v for v in caveats if not str(v).startswith('Final state check failed: ')
                   and v != 'Live-case equality was not confirmed at completion; findings cover only the original private snapshot.'
                   and v != 'EVIDENCE_STATE_CHANGED']
    caveats = [v for v in caveats if str(v).rstrip('.') != 'No supported conclusion was produced']
    unique = limitations(caveats, source_material=source_material)
    if unique:
        lines.extend(['', palette('heading', 'Limitations'), *(palette('warning', '  - ' + safe(value)) for value in unique)])
    return '\n'.join(lines)

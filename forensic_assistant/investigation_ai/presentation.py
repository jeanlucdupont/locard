"""Human projection of controller-validated data; never a model summary."""
from forensic_assistant.interactive.console import safe

LABELS = {
    'ANSWER_SUPPORTED': 'Supported findings from disclosed evidence',
    'USER_REJECTED': 'Analyst rejected proposed operation',
    'TOO_MANY_REJECTIONS': 'Rejection limit reached',
    'BUDGET_EXHAUSTED': 'Investigation budget exhausted',
    'MODEL_FAILURE': 'Local AI model failure',
    'MAX_SECONDS': 'Investigation time limit reached',
    'STARTUP_TIMEOUT': 'Investigation startup timed out',
    'EVIDENCE_STATE_CHANGED': 'The live case changed during investigation; final acceptance stopped',
    'SEMANTIC_STATE_CHANGED': 'Semantic index changed during investigation',
    'USER_SCOPE_REACHED': 'Requested scope reached or analyst interrupted',
    'INSUFFICIENT_EVIDENCE': 'Insufficient disclosed evidence',
    'NO_NEW_EVIDENCE': 'No new evidence from repeated operations',
    'TOOL_FAILURE': 'Read-only operation failed',
    'AUDIT_FAILURE': 'Required audit recording failed',
    'CLEANUP_LIMITATION': 'Worker or temporary snapshot cleanup could not be confirmed',
}


def proposal_text(proposal):
    lines = ['More evidence is needed.', '', 'Proposed read-only operation',
             '  Tool: ' + safe(proposal.get('tool', ''))]
    for key, value in proposal.get('arguments', {}).items():
        label = 'Evidence ID' if key == 'evidence_id' else key.replace('_', ' ').capitalize()
        lines.append('  ' + label + ': ' + safe(value))
    if proposal.get('reason'):
        lines.append('  Model-proposed reason: ' + safe(proposal['reason']))
    return '\n'.join(lines)


def render(result):
    from .cli import rejection_notice
    supported = result.get('termination') == 'ANSWER_SUPPORTED'
    lines = ['Investigation result' if supported else 'Investigation incomplete']
    findings = result.get('findings') or {}
    caveats = list(result.get('limitations') or [])
    state = result.get('state') or {}
    caveats.extend(state.get('limitations') or [])
    for title, key in [('Observed evidence', 'observed'),
                       ('Deterministic relationships', 'deterministically_correlated'),
                       ('Corroborated evidence', 'corroborated'),
                       ('Unresolved relationships', 'unresolved_relationships'),
                       ('Detections (not proof of compromise)', 'detections')]:
        rows = findings.get(key) or []
        if not rows:
            continue
        lines.extend(['', title])
        for row in rows:
            if key == 'observed':
                label = str(row.get('field', '')).strip('/').replace('/', ' / ').replace('_', ' ')
                lines.append('  ' + safe(label) + ': ' + safe(row.get('reported_value')))
                caveats.append(row.get('qualifier', 'Reported field; not proof of execution or causation.'))
            else:
                lines.append('  ' + safe(row.get('relationship') or row.get('rule_name') or row.get('rule_id', 'Relationship'))
                             + ' — ' + safe(row.get('status') or row.get('correlation_status', '')))
                if row.get('reason'):
                    lines.append('    ' + safe(row['reason']))
            for eid in row.get('evidence_ids', []):
                lines.append('    Evidence: ' + safe(eid))
            if row.get('source_context'):
                caveats.append('Source metadata includes analyst assertions; it is not independently verified evidence.')
            if row.get('truncated_fields'):
                caveats.append('Some evidence fields were truncated; omitted values are unavailable.')
            caveats.extend(row.get('warnings') or [])
            caveats.extend(row.get('limitations') or [])
    # Unverified model narrative cannot populate factual or safety sections.
    if findings.get('hypotheses') or findings.get('model_proposed_unknowns'):
        caveats.append('Unverified model hypotheses/unknowns are available in --json; they are not findings of fact.')
    completed = sum(p.get('operation') != 'initial' for p in state.get('investigation_path', []) if isinstance(p, dict))
    lines.extend(['', 'Read-only operations', '  Completed: ' + str(completed)])
    notice = rejection_notice(result)
    if notice:
        lines.extend(['', 'AI validation', '  ' + notice.splitlines()[1],
                      '  Unsupported AI conclusions are rejected rather than presented as findings.'])
    elif state.get('rejected_requests'):
        lines.extend(['', 'AI validation', '  Rejected proposals: ' + str(state['rejected_requests'])])
    if result.get('dry_run_proposal'):
        lines.extend(['', 'Dry-run: proposal only; no proposed tool was executed.', proposal_text(result['dry_run_proposal'])])
    lines.extend(['', 'Termination', '  ' + LABELS.get(result.get('termination'), 'Investigation stopped')])
    integrity = (result.get('metrics') or {}).get('integrity') or {}
    if integrity.get('strategy') == 'private_sqlite_snapshot':
        match = integrity.get('live_case_matches')
        lines.extend(['', 'Case integrity', '  ' + ('Live case matched the original snapshot at completion.' if match is True else
                      'Live case changed; findings cover only the original snapshot.' if match is False else
                      'Live-case equality was not confirmed; findings cover only the original snapshot.')])
    if not supported:
        caveats.append('No supported conclusion was produced.')
    unique = []
    for value in caveats:
        if not value:
            continue
        # Only normalize the known wording variant; retain distinct forensic caveats.
        value = str(value).replace('Source metadata contains analyst assertions', 'Source metadata includes analyst assertions')
        if value not in unique:
            unique.append(value)
    if unique:
        lines.extend(['', 'Limitations', *('  - ' + safe(value) for value in unique)])
    return '\n'.join(lines)

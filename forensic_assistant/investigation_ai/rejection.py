"""Bounded diagnostic metadata; never a validation or authorization decision."""
import re
from .contracts import TOOLS
from .diagnostics import LOG
from .transcript import digest

REASONS = {
    'Tool is unknown or not applicable': ('UNKNOWN_TOOL', 'allowlist_validation'),
    'Anchor was not exposed to the model': ('UNEXPOSED_EVIDENCE_ID', 'anchor_validation'),
    'Multiple source occurrences; cannot select an unambiguous source': ('SOURCE_AMBIGUITY', 'worker_execution'),
    'Host context missing or conflicting; cannot select same-host temporal neighbors': ('HOST_AMBIGUITY', 'worker_execution'),
    'Repeated normalized tool call': ('REPEATED_TOOL_CALL', 'loop_validation'),
    'Tool-call budget exhausted': ('LIMIT_REJECTION', 'budget_validation'),
    'Analyst rejected or approval timed out': ('POLICY_REJECTION', 'analyst_approval'),
    'Browser evidence is unavailable in this case': ('RESULT_SCOPE_VIOLATION', 'case_scope_validation'),
    'Rule not in frozen registry': ('POLICY_REJECTION', 'anchor_validation'),
    'Process anchor required': ('INVALID_ARGUMENT', 'anchor_validation'),
    'Successful logon anchor required': ('INVALID_ARGUMENT', 'anchor_validation'),
}
FIXED = frozenset((
    'Malformed structured response', 'Duplicate JSON key', 'Nonfinite JSON value',
    'Model response exceeds content limit', 'Response must be an object',
    'Malformed evidence ID', 'Time window exceeds 24 hours or is reversed',
    'Search needs at least one scope filter', 'Rule not in frozen registry',
    'Use a full ISO timestamp with Z or an explicit UTC offset',
    'Process anchor required', 'Successful logon anchor required',
    'Observed finding references an unexposed evidence field',
    'Supporting evidence was not exposed', 'Relationship was not exposed',
    'Relationship lacks disclosed support', 'Detection was not exposed',
    'Detection lacks disclosed support', 'Hypothesis cites undisclosed evidence',
    'Hypothesis requires an alternative explanation',
))
SCHEMA_ERRORS = frozenset(('wrong type', 'missing parameter', 'unknown parameter',
    'invalid item count', 'duplicate items', 'invalid string length/content',
    'value outside bounds', 'unsupported value'))


def _keys(schema):
    result = set(schema.get('properties', {}))
    for child in schema.get('properties', {}).values():
        result.update(_keys(child))
    if 'items' in schema:
        result.update(_keys(schema['items']))
    return result


def diagnostic(identity, step, number, decoded, stage, error):
    value = decoded if type(decoded) is dict else {}
    tool = value.get('tool')
    tool = tool if type(tool) is str and tool in TOOLS else 'unknown'
    action = value.get('action')
    action = action if type(action) is str and action in ('tool', 'final') else 'unknown'
    reason = str(error)
    category = ('MALFORMED_PROPOSAL' if stage == 'proposal_parsing' else
                'GROUNDING_VIOLATION' if stage == 'final_grounding' else
                'INVALID_ARGUMENT' if stage == 'proposal_validation' else
                'OTHER_VALIDATION_FAILURE')
    if reason in REASONS:
        category, stage = REASONS[reason]
    elif reason in FIXED:
        if reason == 'Response must be an object':
            category = 'MALFORMED_PROPOSAL'
        elif stage == 'proposal_validation' and action == 'tool':
            stage = 'argument_validation'
    elif reason.endswith(' does not appear to be an IPv4 or IPv6 address'):
        category, stage, reason = 'INVALID_ARGUMENT', 'argument_validation', 'Invalid IP address'
    else:
        # Validation paths consist only of schema-owned names; never echo an
        # arbitrary exception (e.g. ipaddress includes the submitted value).
        path, separator, detail = reason.partition(': ')
        from .contracts import FINAL
        allowed = {'request', 'action', 'answer', 'tool', 'arguments', 'reason'} | _keys(FINAL)
        for _, schema in TOOLS.values():
            allowed.update(_keys(schema))
        parts = re.sub(r'\[\]', '', path).split('.')
        if separator and detail in SCHEMA_ERRORS and all(p in allowed for p in parts):
            reason = path + ': ' + detail
            if 'arguments' in parts or (action == 'tool' and len(parts) > 1 and parts[1] not in ('action', 'tool', 'reason')):
                stage = 'argument_validation'
                category = 'UNKNOWN_ARGUMENT' if detail == 'unknown parameter' else 'INVALID_ARGUMENT'
            else:
                category = 'MALFORMED_PROPOSAL'
        else:
            reason = 'Validation rejected the submitted value; raw content omitted'
            if stage == 'proposal_validation' and action == 'tool':
                stage = 'argument_validation'
    result = dict(investigation_id=identity, step=step, proposal_sequence=step,
                  tool_call_number=number, action=action, tool=tool,
                  arguments_sha256=digest(value.get('arguments')),
                  category=category, stage=stage, reason=reason[:300])
    LOG.debug('investigate-ai proposal diagnostic %s', result)
    return result

"""Small deterministic corrections, never raw exception stacks or model prose."""
from .contracts import TOOLS


def correction(proposal, diagnostic):
    tool = proposal.get('tool') if isinstance(proposal, dict) else None
    reason = diagnostic['reason'][:200]
    if reason == 'Time window exceeds 24 hours or is reversed':
        reason = 'Time window must be <= 24 hours and start must precede or equal end.'
        action = 'Choose a valid bounded window or another allowed tool.'
    else:
        action = 'Use the allowed contract; retrieve missing disclosed fields or leave the question unresolved.'
    return {'status': 'Previous proposal rejected', 'tool': tool if isinstance(tool, str) and tool in TOOLS else None,
            'category': diagnostic['category'], 'reason': reason, 'correction': action}

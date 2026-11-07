"""Terminal adapter for the reusable assessment handoff service."""
import sys
from functools import partial
from . import assessment_handoff as service
from .briefing_workflow import read_answer
from .interactive.console import safe


def run(args):
    if any((args.ai,args.allow_cloud,args.save,args.deterministic,args.discover,args.approve,args.artifact,
            args.revision,args.briefing_correction,args.discovery_after)):
        raise ValueError('Assessment investigation cannot combine with briefing analysis/discovery options')
    read = getattr(args, '_confirm', None) or (input if sys.stdin.isatty() else None)
    if read is None:
        raise ValueError('Assessment investigation requires interactive scope and tool approvals')
    selected = service.select(args.db, args.investigate)
    stream = sys.stderr if args.json else sys.stdout
    print('Using saved assessment ' + selected['id'], file=stream)
    question = args.question or read_answer(read, 'What would you like to investigate? ')
    handoff = service.prepare(args.db, selected['id'], question, args.start, args.end)
    def confirm(plan):
        print('Proposed investigation window: ' + plan['scope']['start'] + ' to ' + plan['scope']['end'], file=stream)
        print('Initial read-only verification of these historical references:', file=stream)
        for hint in plan['hints']:print('  ' + hint['ref'] + ': ' + hint['id'], file=stream)
        for limitation in plan['limitations']:print('  ' + safe(limitation), file=stream)
        print('Initial verification exposes identities only; each additional forensic lookup requires approval.', file=stream)
        return read_answer(read, 'Confirm scope and initial verification; start AI investigation? [y/N] ').strip().casefold() in ('y','yes')
    approved = service.authorize(handoff, confirm)
    if approved is None:return {'kind':'assessment_investigation','message':'Investigation cancelled; no evidence retrieved or model called.'}
    from .investigation_ai.cli import approve
    from .ai.backend import backend, status_callback, waiting_label, restart_confirmation
    from .terminal_activity import ActivityIndicator
    with ActivityIndicator('Preparing investigation...', args=args) as indicator, status_callback(indicator.update), restart_confirmation(read, indicator):
        result = service.investigate(approved, client=backend(), approval=partial(approve,args=args),
                                    status=lambda phase: indicator.start(waiting_label()) if phase=='model' else indicator.phase(phase))
    return {'kind':'assessment_investigation', 'result':result}

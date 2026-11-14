"""Terminal adapter for the reusable assessment handoff service."""
import sys
from functools import partial
from . import assessment_handoff as service
from .briefing_workflow import read_answer
from .interactive.console import safe


def execute(case, identity, question=None, *, read, start=None, end=None, autonomous=False,
            decompose=False, synthesize=False, live_explanation=False, details=False,
            json_output=False, presentation=None):
    """Shared terminal orchestration over the existing authorized handoff service."""
    if not callable(read):raise ValueError('Explicit interactive authorization required')
    if live_explanation and not synthesize:raise ValueError('Live explanation requires synthesis')
    if synthesize and not (autonomous and decompose):raise ValueError('Synthesis requires autonomous decomposition')
    if decompose and not autonomous:raise ValueError('Decomposition requires autonomous execution')
    selected = service.select(case, identity)
    stream = sys.stderr if json_output else sys.stdout
    print('Using saved assessment ' + selected['id'], file=stream)
    question = question or read_answer(read, 'What would you like to investigate? ')
    handoff = service.prepare(case, selected['id'], question, start, end)
    if autonomous:
        from .investigation_ai.autonomous import start
        from .ai.backend import backend
        from .terminal_activity import ActivityIndicator
        def authorize_envelope(grant):
            indicator.stop()  # Never animate concurrently with approval input.
            s4 = grant.get('contract') == 'investigation-s4-authorization-v1'
            b2 = grant.get('contract') == 'investigation-s4-b2-authorization-v1'
            print('Autonomous S4-B2 authorization' if b2 else 'Autonomous S4-A authorization' if s4 else 'Autonomous Stage A authorization',file=stream)
            print('  Case: '+safe(grant['case']),file=stream)
            print('  Question: '+safe(grant['objective']),file=stream)
            print('  Window: '+grant['start']+' to '+grant['end'],file=stream)
            print('  Sources: '+', '.join(grant['source_ids']),file=stream)
            print('  Families: '+', '.join(grant['families']),file=stream)
            print('  OpenAI model: '+safe(grant['model'])+'; authorized evidence will be sent to OpenAI.',file=stream)
            print('  Inspect only '+str(len(grant['evidence_ids']))+' listed assessment references; show_evidence only, no search.',file=stream)
            print('  Eligibility: any of the first 32 recorded timestamps in the window. Bounded full-record context, including other timestamps, is permitted.',file=stream)
            if b2:
                print('  Limits: 6 analysis + 1 decomposition + 2 synthesis; 9 model attempts; 6 lookups; 0 refill; 10 steps.',file=stream)
                print('  300 seconds total: model work ends by 280; 15 seconds finalization + 5 seconds containment.',file=stream)
                print('  Synthesis at most 30 seconds/request; 5600 content bytes; 1024 output tokens. No retries or transfers.',file=stream)
                print('  Original evidence may be disclosed repeatedly. Exploratory organization is permitted for unresolved objectives.',file=stream)
                print('  Model proposals remain unverified. Budget exhaustion may skip synthesis; completion is not forensic completeness.',file=stream)
            elif s4:
                print('  Limits: 6 analysis + 1 question-only decomposition, 0 organization; 7 AI requests total.',file=stream)
                print('  6 lookups, 8 steps, 5 minutes; 15 seconds reserved for finalization; decomposition at most 30 seconds.',file=stream)
                print('  5600 prompt bytes and 1024 output tokens per request. No retries or allocation transfers.',file=stream)
                print('  Proposed meaning remains unverified; scoped answers do not certify the original question answered.',file=stream)
            else:
                print('  Limits: 6 AI requests, 6 lookups, 8 steps, 5 minutes; 5600 prompt bytes and 1024 output tokens per request.',file=stream)
            print('  View established after approval; expires after 5 minutes. No restart continuation or automatic scope expansion.',file=stream)
            if live_explanation:
                print('  Local explanation persistence enabled; no additional model requests or evidence lookups.',file=stream)
            if details:
                import json
                print(json.dumps(grant,ensure_ascii=True,indent=2),file=stream)
            return read_answer(read,'Authorize this bounded autonomous investigation? [y/N] ').strip().casefold() in ('y','yes')
        with ActivityIndicator('Preparing investigation...',args=presentation) as indicator:
            extra = {'decompose':True} if decompose else {}
            if synthesize:extra['synthesize']=True
            if live_explanation:extra['live_explanation']=True
            result=start(handoff,selected,backend(),authorize_envelope,status=indicator.phase,**extra)
        return {'kind':'assessment_investigation',**({'result':result} if result is not None else {'message':'Investigation cancelled; no evidence retrieved or model called.'})}
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
    with ActivityIndicator('Preparing investigation...', args=presentation) as indicator, status_callback(indicator.update), restart_confirmation(read, indicator):
        result = service.investigate(approved, client=backend(), approval=partial(approve,args=presentation),
                                    status=lambda phase: indicator.start(waiting_label()) if phase=='model' else indicator.phase(phase))
    return {'kind':'assessment_investigation', 'result':result}

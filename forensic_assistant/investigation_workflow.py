"""Guided orchestration over existing briefing, assessment and handoff services.

No parser namespaces, subprocess dispatch, persisted formats or new engine.
"""
from .briefing_store import Store, content, FIELDS
from . import briefing_workflow, assessment_cli, assessment_handoff_cli


def start(case, *, read, display=print, presentation=None):
    if not callable(read):
        raise ValueError('Guided investigation requires interactive review and approvals')
    answer = lambda prompt: briefing_workflow.read_answer(read, prompt).strip()
    display('Investigation — briefing, explicit scope, assessment, authorization, review')
    from .interactive.console import safe
    display('Case: '+safe(str(case)))
    store = Store(case)
    state = store.load()
    revision = state['revisions'][-1] if state else None
    current = revision['content'] if revision else content(dict.fromkeys(FIELDS, ''), '')
    choice = answer('Briefing: existing, edit, or interview [existing]: ') or 'existing'
    if choice not in ('existing', 'edit', 'interview'):
        raise ValueError('Choose existing, edit or interview')
    if choice == 'existing' and revision is None:
        raise ValueError('No saved briefing; choose edit or interview')
    if choice == 'interview':
        if answer('Start the AI-assisted interview? Analyst text may be sent to the configured provider. [y/N]: ').lower() not in ('y','yes'):
            return {'status':'cancelled', 'stage':'briefing'}
        from .briefing_interview import interview
        value = interview(current, read)
    elif choice == 'edit':
        value = briefing_workflow.edit(store, current, read)
    else:
        value = None
    if choice != 'existing':
        if value is None:
            return {'status':'cancelled', 'stage':'briefing'}
        state = store.save(value, revision['digest'] if revision else None)
    display(briefing_workflow.render(briefing_workflow.view(state)))
    if answer('Proceed to explicit local evidence scope and assessment? [y/N]: ').lower() not in ('y','yes'):
        return {'status':'cancelled', 'stage':'assessment'}
    from contextlib import closing
    from .interactive.case import open_existing
    from .database.sources import listing
    with closing(open_existing(case)) as db:
        available=listing(db)
    display('Recorded sources (analyst-supplied identity is not independently verified):')
    for source in available['sources']:
        display('  '+safe(source['source_id'])+' '+safe(source['display_name']))
    if available['truncated']:display('Source listing truncated; exact grant restrictions are displayed before execution.')
    assessment = assessment_cli.assess(case, read=read)
    if 'id' not in assessment:
        return assessment
    from .assessment_display import render
    display(render(assessment))
    question = answer('Investigation question (or cancel): ')
    return run(case, assessment['id'], question, read=read, display=display, presentation=presentation)


def run(case, identity='latest', question=None, *, read, display=print, presentation=None):
    """Stage choices precede, and never replace, the engine's exact grant approval."""
    from .assessment_handoff import prepare
    from .ai.settings import load
    from .interactive.console import safe
    answer = lambda prompt: briefing_workflow.read_answer(read, prompt).strip()
    question = question or answer('Investigation question: ')
    handoff = prepare(case, identity, question)
    display('Selected case: '+safe(str(case)))
    display('Assessment: '+safe(handoff['assessment_id']))
    display('Question: '+safe(question))
    if handoff.get('scope'):display('Requested window: '+safe(str(handoff['scope'])))
    display('Scope and source restrictions will be displayed in the exact engine grant; no continuation or scope expansion.')
    for limitation in handoff['limitations']:
        display(safe(limitation))
    config = load()
    if config['provider'] != 'openai':
        raise ValueError('The autonomous workflow currently supports OpenAI only; use ! for other configured-provider routing')
    if answer('Permit bounded evidence disclosure to OpenAI for this investigation? [y/N]: ').lower() not in ('y','yes'):
        return {'status':'cancelled', 'stage':'cloud_disclosure'}
    decompose = answer('Authorize a separate question-decomposition request within the displayed grant? [y/N]: ').lower() in ('y','yes')
    synthesize = False
    if decompose:
        synthesize = answer('Authorize up to two additional bounded evidence-synthesis requests? [y/N]: ').lower() in ('y','yes')
    result = assessment_handoff_cli.execute(case, identity, question, read=read, autonomous=True,
        decompose=decompose, synthesize=synthesize, live_explanation=synthesize, presentation=presentation)
    display('Review recorded output with investigation history. Findings and reports are separate explicit operations; nothing is automatically captured or published.')
    return result

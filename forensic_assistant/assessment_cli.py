"""Explicit assessment plan approval and historical review CLI."""
import copy
import sys
from . import assessment as a
from .briefing_store import Store
from .assessment_store import AssessmentStore
from .briefing_workflow import read_answer


def run(args, *, worker_factory=None):
    store=AssessmentStore(args.db)
    briefing=Store(args.db);state=briefing.load();revision=state['revisions'][-1] if state else None
    if args.workflow == 'list':
        return dict(kind='assessment_history',assessments=[dict(id=r['id'],created=r['created'],status=r['status'],revision=r['plan']['revision']) for r in store.history()])
    previous=None
    selected=getattr(args,'assessment',None)
    if selected:
        if selected=='latest':
            history=store.history()
            if not history:return {'kind':'case_assessment','message':'No saved assessments.'}
            previous=store.load(history[-1]['id'])
        else:previous=store.load(selected)
    if args.workflow == 'show':
        previous['briefing_stale']=not revision or revision['digest']!=previous['plan']['digest']
        if not args.json and 'editorial_summary' not in previous['plan'] and state:
            original=next((r for r in state['revisions'] if r['digest']==previous['plan']['digest']),None)
            if original and original['content'].get('canonical'):
                summary=original['content']['canonical']['document']['summary']
                if summary['status']=='accepted':
                    previous['briefing_report_context']={'editorial_summary':summary['text']}
        return previous
    return assess(args.db, read=getattr(args,'_confirm',None) or (input if sys.stdin.isatty() else None),
                  start=getattr(args,'start',None), end=getattr(args,'end',None), previous=previous, details=getattr(args,'details',False),
                  json_output=args.json, worker_factory=worker_factory)


def assess(case, *, read, start=None, end=None, previous=None, details=False,
           json_output=False, worker_factory=None):
    """Reusable assessment orchestration with explicit input/approval callback."""
    if not callable(read): raise ValueError('Assessment requires explicit plan approval')
    worker_factory=worker_factory or a.ForensicWorker
    store=AssessmentStore(case)
    briefing=Store(case);state=briefing.load();revision=state['revisions'][-1] if state else None
    if not revision or not revision['content'].get('canonical'):
        raise ValueError('Accept a structured briefing before assessment')
    stream=sys.stderr if json_output else sys.stdout
    def display(text):print(text,file=stream,flush=True)
    from .interactive.console import safe
    display('Reported time remains analyst input; an unknown timezone is not converted to UTC.')
    from .assessment_display import reported_time,Progress
    for line in reported_time(revision['content']['canonical']['document']['categories']['when']):display(line)
    if previous:
        if previous['plan']['digest']!=revision['digest']:raise ValueError('Briefing changed; start a new investigation assess plan')
        if start or end:raise ValueError('Reauthorization retains the previously approved time scope')
        start,end=previous['plan']['start'],previous['plan']['end']
        display('Reauthorization starts a new read view and restarts approved searches. Prior results and cursors remain separate.')
    else:
        start=start or read_answer(read,'Authorized start (ISO timestamp with timezone): ').strip()
        end=end or read_answer(read,'Authorized end (ISO timestamp with timezone; at most 24 hours): ').strip()
    a.briefing.window(start,end,source='explicit assessment authorization')
    available=a.inventory(case,worker_factory)
    p=a.plan(revision,store.identity,available,start,end)
    if previous:
        old=previous['plan']
        if any(lead not in p['leads'] for lead in old['leads']):raise ValueError('Approved leads changed; start a new assessment')
        routes={(r['lead_id'],r['artifact']):r['query'] for r in p['rows']}
        if old['policy']!=p['policy'] or any(routes.get((r['lead_id'],r['artifact']))!=r['query'] for r in old['rows']):
            raise ValueError('Saved plan no longer matches validated routes; start a new assessment')
        # Never extend resumption to newly available families or excluded leads.
        p=copy.deepcopy(old)
    display(a.plan_text(p))
    excluded=read_answer(read,'Exclude lead IDs (comma-separated), or Enter to keep the displayed plan: ').strip()
    if excluded:
        ids={v.strip() for v in excluded.split(',')}
        if not ids<={lead['id'] for lead in p['leads']}:raise ValueError('Unknown exclusion ID; no searches executed')
        p['leads']=[r for r in p['leads'] if r['id'] not in ids]
        p['rows']=[r for r in p['rows'] if r['lead_id'] not in ids]
        p['excluded'].extend(dict(field=i,value='',reason='Excluded by analyst before authorization') for i in sorted(ids))
        display(a.plan_text(p))
    if not any(r['status']=='not_searched' for r in p['rows']):
        display('No eligible available searches; approval will save a coverage-only assessment.')
    if read_answer(read,'Approve this bounded assessment plan? [y/N]: ').strip().lower() not in ('y','yes'):
        return {'kind':'case_assessment','message':'Assessment cancelled; no evidence searches executed.'}
    current=briefing.load()
    if not current or current['revisions'][-1]['digest']!=revision['digest']:
        raise ValueError('Briefing changed during approval; no searches executed')
    store.check_case()
    progress=Progress(stream,details=details)
    try:return a.execute(p,store,worker_factory=worker_factory,progress=progress,parent=previous['id'] if previous else None)
    finally:progress.finish()

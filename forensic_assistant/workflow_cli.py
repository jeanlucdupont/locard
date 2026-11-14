"""Canonical workflow navigation; calls existing application services directly."""
import json
import sys


def configure(operations, *, interactive=False):
    def add(group, name, operation, help):
        p = operations.group(group).add_parser(name, help=help, description=help)
        p.set_defaults(command='workflow', workflow=operation, json=False)
        return p
    for name in ('open','new'):
        p = add(('case',), name, 'case-'+name, 'Interactive case '+name+'; no evidence ingestion is implied')
        if name == 'open': p.add_argument('path', nargs='?')
    add(('evidence','ingest'), 'wizard', 'ingest-wizard', 'Guided evidence selection; confirmation required')
    for name, help in [('start','Guided briefing, assessment and separately authorized AI investigation'),
                       ('assess','Plan and approve a new deterministic assessment'),
                       ('list','List saved assessments'),('show','Review a saved assessment'),
                       ('reauthorize','Reauthorize an assessment in a NEW read view; not continuation'),
                       ('run','Review a saved assessment scope and authorize investigation stages')]:
        p=add(('investigation',), name, name, help)
        p.add_argument('--json',action='store_true', help='Structured result; prompts remain explicit')
        if name in ('show','reauthorize','run'):p.add_argument('assessment',nargs='?',default='latest')
        if name == 'run':p.add_argument('--question',help='Investigation question; otherwise prompted')
        if name == 'assess':
            p.add_argument('--start');p.add_argument('--end')
    p=add(('audit',),'verify','audit-verify','Verify the existing analyst activity chain; read-only')
    p.add_argument('--json',action='store_true')
    p=add(('settings',),'color','color','Inspect or set terminal styling')
    p.add_argument('setting',nargs='?',choices=('on','off'))
    p=add(('settings',),'version','version','Show effective version; optional source/installed diagnostics')
    p.add_argument('--details',action='store_true')
    p=add(('investigation','advanced'),'assessment','assessment-advanced','Historical assessment handoff with per-tool approval; distinct from autonomous run')
    p.add_argument('assessment',nargs='?',default='latest')
    p.add_argument('--question')
    p.add_argument('--start');p.add_argument('--end')
    p.add_argument('--details',action='store_true');p.add_argument('--json',action='store_true')
    findings=operations.group(('investigation','findings'))
    from .investigation_ai.findings import KINDS
    for name in ('create','select','list','show','register','accept','reject','supersede','history'):
        p=findings.add_parser(name, help='Explicit findings workspace: '+name)
        p.set_defaults(command='workflow',workflow='findings',finding_operation=name)
        p.add_argument('--workspace',required=True,help='Explicit .findings directory; never silently selected')
        p.add_argument('--json',action='store_true')
        if name=='create':
            p.add_argument('--transcripts',required=True);p.add_argument('--run',required=True)
        if name in ('create','register','accept','reject','supersede'):
            p.add_argument('--actor',required=True,help='Locally asserted analyst identity')
        if name in ('register','accept','reject','supersede'):
            p.add_argument('--workspace-id',required=True,help='UUID from explicit workspace review')
            p.add_argument('--revision',required=True,type=int,help='Expected current workspace revision')
        if name in ('show','accept','reject','supersede'):p.add_argument('finding_id')
        if name in ('accept','reject','supersede'):p.add_argument('--rationale',required=True)
        if name in ('register','supersede'):
            p.add_argument('--statement',required=True);p.add_argument('--support',action='append',required=True)
            p.add_argument('--contrary',action='append',default=[])
        if name=='register':p.add_argument('--kind',default='analyst_hypothesis',choices=KINDS[:3]+('analyst_hypothesis',))
    from .investigation_ai import d2_reasoning
    p=add(('investigation',),'reason','reason','Advanced recorded D2 preview / explicitly authorized execution and optional capture')
    d2_reasoning.configure(p)


def findings(args):
    from .investigation_ai.findings import Workspace, create
    op=args.finding_operation
    if op=='create':return create(args.workspace,args.transcripts,args.run,actor=args.actor).export()
    w=Workspace(args.workspace)
    state=w.export()
    if op in ('select','list'):return state
    if op=='history':return {'decisions':w.decisions()}
    if op=='show':return w.get(args.finding_id)
    if args.workspace_id != state['metadata']['id']:
        raise ValueError('FINDINGS_WORKSPACE_CHANGED')
    common=dict(actor=args.actor,expected_revision=args.revision)
    if op=='register':
        identity=w.register(kind=args.kind,statement=args.statement,supporting_ids=args.support,contrary_ids=args.contrary,**common)
    elif op=='supersede':
        identity=w.supersede(args.finding_id,rationale=args.rationale,statement=args.statement,supporting_ids=args.support,contrary_ids=args.contrary,**common)
    else:identity=w.review(args.finding_id,op,rationale=args.rationale,**common)
    return dict(changed_finding_id=identity,**w.export())


def run(args):
    read=getattr(args,'_confirm',None) or (input if sys.stdin.isatty() else None)
    op=args.workflow
    if op=='findings':return findings(args)
    if op=='reason':
        from .investigation_ai.d2_reasoning import run
        return run(args, read=read)
    if op=='version':
        from . import __version__
        from .version import resolve
        return resolve() if args.details else {'application_version':__version__}
    if op in ('color','case-open','case-new','ingest-wizard'):
        raise ValueError('This navigation operation requires the interactive shell')
    if op=='audit-verify':
        from . import activity
        return activity.inspect(activity.sidecar(args.db), limit=1)
    from . import assessment_cli
    if op in ('list','show','assess','reauthorize'):
        return assessment_cli.run(args)
    if not callable(read):raise ValueError('Investigation workflow requires explicit interactive approvals')
    from . import investigation_workflow, assessment_cli
    if op in ('start','run'):
        from contextlib import nullcontext,redirect_stdout
        with redirect_stdout(sys.stderr) if args.json else nullcontext():
            if op=='start':return investigation_workflow.start(args.db,read=read,presentation=args)
            return investigation_workflow.run(args.db,args.assessment,args.question,read=read,presentation=args)
    if op=='assessment-advanced':
        from .assessment_handoff_cli import execute
        return execute(args.db,args.assessment,args.question,read=read,start=args.start,end=args.end,
                       details=args.details,json_output=args.json,presentation=args)
    raise ValueError('Unknown workflow operation')


def render(value):
    if value is None:return ''
    from .briefing_cli import render as briefing_render
    from .retrieval.presentation import safe_text
    if isinstance(value,dict) and value.get('kind')=='assessment_investigation':return briefing_render(value)
    if isinstance(value,dict) and value.get('kind')=='assessment_history':return briefing_render(value)
    if isinstance(value,dict) and 'valid' in value and 'entries' in value:
        from .activity import render
        return render(value,verify=True)
    if isinstance(value,dict) and 'rows' in value and 'records' in value:
        from .assessment_display import render
        return render(value)
    if isinstance(value,dict) and 'findings' in value:
        lines=['Findings — analyst decisions, not forensic verification',
               'Workspace: '+str(value.get('metadata',{}).get('id',value.get('workspace_id',''))),
               'Revision: '+str(value['revision'])]
        for row in value['findings']:
            candidate=row.get('candidate',{})
            lines.append('  '+safe_text(row.get('id',''))+' | '+safe_text(row.get('state',''))+' | '+safe_text(candidate.get('origin','')))
            lines.append('    '+safe_text(candidate.get('statement','')))
        if not value['findings']:lines.append('  No findings registered.')
        lines.append('Use --json for complete support, rationale and source-binding details.')
        return '\n'.join(lines)
    if isinstance(value,dict) and set(value)=={'application_version'}:
        return 'Locard '+value['application_version']
    return '\n'.join(safe_text(line) for line in json.dumps(value,ensure_ascii=True,indent=2).splitlines())

"""Reporting dispatch precedes all database creation/migration paths."""
from pathlib import Path
from .bundle import generate,inspect,validate
from .model import Limits

def configure(commands):
    report=commands.add_parser('report',help='Derived, bounded forensic reporting')
    sub=report.add_subparsers(dest='report_command',required=True)
    create=sub.add_parser('generate')
    inputs=create.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--evidence',action='append',dest='evidence_ids',help='Explicit evidence ID (repeatable); not a complete investigation')
    inputs.add_argument('--investigation',action='append',dest='investigation_ids',help='Same-state V4 investigation ID (repeatable)')
    create.add_argument('--transcript-root')
    create.add_argument('--output',required=True,help='New report directory under an existing parent')
    create.add_argument('--profile',choices=('technical','executive'),default='technical')
    create.add_argument('--redact',choices=('none','identifiers'),default='none')
    create.add_argument('--include-source-locations',action='store_true')
    for name in ('case-name','case-identifier','analyst-name','organization','title','scope-note'):
        create.add_argument('--'+name)
    create.add_argument('--max-claims',type=int,default=100)
    create.add_argument('--max-timeline',type=int,default=500)
    create.add_argument('--seconds',type=int,default=300)
    create.add_argument('--llm-narrative',action='store_true',help='Optional constrained claim ordering through local MiniCPM')
    create.add_argument('--endpoint',default='http://127.0.0.1:8080')
    view=sub.add_parser('show');view.add_argument('directory')
    check=sub.add_parser('validate');check.add_argument('directory')
    check.add_argument('--case',help='Optional existing schema-3 case for fingerprint and grounding checks')
    check.add_argument('--transcript-root',help='Original transcripts for investigation-report grounding')

def dispatch(args):
    if args.report_command=='show':
        report,_=inspect(args.directory)
        return dict(report_id=report['report_id'],status=report['data']['status'],input_mode=report['data']['input_mode'],
                    scope=report['data']['scope'],profile=report['profile'],redaction=report['redaction'],
                    claim_count=len(report['data']['claims']),caution=report['data']['caution'])
    if args.report_command=='validate':return validate(args.directory,case=args.case,transcript_root=args.transcript_root)
    if args.investigation_ids and not args.transcript_root: raise ValueError('--transcript-root is required for investigation reports')
    client=None
    if args.llm_narrative:
        from forensic_assistant.llm.client import LocalClient
        client=LocalClient(args.endpoint,timeout=min(45,args.seconds))
    metadata={name:getattr(args,name) for name in ('case_name','case_identifier','analyst_name','organization','title','scope_note') if getattr(args,name) is not None}
    return generate(args.db,args.output,profile=args.profile,redaction=args.redact,narrative_client=client,
        evidence_ids=args.evidence_ids or (),investigation_ids=args.investigation_ids or (),transcript_root=args.transcript_root,
        limits=Limits(args.max_claims,args.max_timeline,args.seconds),include_source_locations=args.include_source_locations,metadata=metadata)

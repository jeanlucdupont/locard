"""Reporting dispatch precedes database creation paths."""
from forensic_assistant.command_catalog import COMMANDS
from pathlib import Path
from .bundle import generate, inspect, validate
from .model import Limits

def configure(commands, *, interactive=False):
    report = commands.add_parser('report', help=COMMANDS['report'])
    sub = report.add_subparsers(dest='report_command', required=True)
    recorded = sub.add_parser('from-history', help='Create a report from validated investigation history')
    recorded.set_defaults(report_command='recorded')
    recorded.add_argument('--transcript-root', required=True, help='Original investigation transcript directory')
    recorded.add_argument('--run', required=True, help='Saved investigation ID')
    recorded.add_argument('--workspace', help='Optional matching .findings directory')
    recorded.add_argument('--profile', choices=('executive', 'technical', 'handover'), default='technical', help='Report detail level')
    recorded.add_argument('--output', required=True, help='New local report directory')
    recorded.add_argument('--protect-root', action='append', default=[], help='Additional evidence directory to exclude from destinations (repeatable)')
    recorded_check = sub.add_parser('verify-history', help='Verify a report; optionally check recorded sources')
    recorded_check.set_defaults(report_command='inspect-recorded')
    recorded_check.add_argument('directory', help='Report directory')
    recorded_check.add_argument('--transcript-root', help='Original investigation transcript directory')
    recorded_check.add_argument('--run', help='Saved investigation ID')
    recorded_check.add_argument('--workspace', help='Matching findings workspace directory')
    for parser in (recorded, recorded_check):
        parser.add_argument('--json', action='store_true', default=not interactive, help='Output as JSON')
        parser.add_argument('--text', dest='json', action='store_false', help='Human-readable report result')
    create = sub.add_parser('from-case', help='Create a report from selected case evidence')
    create.set_defaults(report_command='generate')
    output = create.add_mutually_exclusive_group()
    output.add_argument('--json', dest='json', action='store_true', help='Output as JSON')
    output.add_argument('--text', dest='json', action='store_false', help='Show a readable result')
    create.set_defaults(json=not interactive)
    inputs = create.add_mutually_exclusive_group(required=True)
    inputs.add_argument(
        '--evidence',
        action='append',
        dest='evidence_ids',
        help='Explicit evidence ID (repeatable); not a complete investigation'
    )
    inputs.add_argument(
        '--investigation',
        action='append',
        dest='investigation_ids',
        help='Same-state V4 investigation ID (repeatable)'
    )
    create.add_argument('--transcript-root', help='Original investigation transcript directory')
    create.add_argument('--output', required=True, help='New report directory under an existing directory')
    create.add_argument('--profile', choices=('technical', 'executive'), default='technical', help='Report detail level')
    create.add_argument('--redact', choices=('none', 'identifiers'), default='none', help='Redact identifying information in the derived report')
    create.add_argument('--include-source-locations', action='store_true', help='Include original source locations in the report')
    for name in ('case-name', 'case-identifier', 'analyst-name', 'organization', 'title', 'scope-note'):
        create.add_argument('--' + name, help={'case-name':'Case name shown in report','case-identifier':'Case identifier shown in report','analyst-name':'Analyst name shown in report','organization':'Organization shown in report','title':'Report title','scope-note':'Report scope qualification'}[name])
    create.add_argument('--max-claims', type=int, default=100, help='Maximum report claims')
    create.add_argument('--max-timeline', type=int, default=500, help='Maximum timeline observations in the report')
    create.add_argument('--seconds', type=int, default=300, help='Seconds around the anchor')
    create.add_argument(
        '--llm-narrative',
        action='store_true',
        help='Optional grounded narrative composition through local MiniCPM; rejected output falls back safely'
    )
    create.add_argument('--endpoint', default=None, help='Local model endpoint')
    view = sub.add_parser('show', help='Show a report bundle')
    view.add_argument('directory', help='Report bundle directory, not a report ID')
    check = sub.add_parser('verify', help='Verify a report bundle and optional evidence grounding')
    check.set_defaults(report_command='validate')
    check.add_argument('directory', help='Report directory')
    check.add_argument('--case', help='Optional existing schema-3 case for fingerprint and grounding checks')
    check.add_argument('--transcript-root', help='Original transcripts for investigation-report grounding')

def dispatch(args):
    if args.report_command != 'generate':
        from contextlib import nullcontext
        from forensic_assistant.terminal_activity import operation
        with operation('Verifying report...', args) if args.report_command == 'validate' else nullcontext():
            return _dispatch(args)
    from forensic_assistant import activity
    from forensic_assistant.output import file_hash
    with activity.mutation('OUTPUT_WRITE', path=str(Path(args.output).absolute()), command='report generate',
                           output_kind='report_bundle') as record:
        result = _dispatch(args)
        from .bundle import FILES
        record['sha256'] = {name: file_hash(Path(args.output) / name) for name in FILES}
        record['report_id'] = result['report_id']
        return result


def _dispatch(args):
    if args.report_command == 'show':
        import re
        if re.fullmatch(r'[a-fA-F0-9]{32}', args.directory) and not Path(args.directory).is_dir():
            raise ValueError('report show expects a report directory, not a report ID. Use the directory returned by report from-case.')
        report, _ = inspect(args.directory)
        return dict(
            report_id=report['report_id'],
            status=report['data']['status'],
            input_mode=report['data']['input_mode'],
            scope=report['data']['scope'],
            profile=report['profile'],
            redaction=report['redaction'],
            claim_count=len(report['data']['claims']),
            caution=report['data']['caution']
        )
    if args.report_command == 'validate':
        return validate(args.directory, case=args.case, transcript_root=args.transcript_root)
    if args.investigation_ids and not args.transcript_root:
        raise ValueError('--transcript-root is required for investigation reports')
    client = None
    if args.llm_narrative:
        from forensic_assistant.ai.backend import backend as LocalClient
        client = LocalClient(args.endpoint, timeout=min(45, args.seconds))
    metadata = {name: getattr(args, name) for name in (
        'case_name',
        'case_identifier',
        'analyst_name',
        'organization',
        'title',
        'scope_note'
    ) if getattr(args, name) is not None}
    return generate(
        args.db,
        args.output,
        profile=args.profile,
        redaction=args.redact,
        narrative_client=client,
        evidence_ids=args.evidence_ids or (),
        investigation_ids=args.investigation_ids or (),
        transcript_root=args.transcript_root,
        limits=Limits(args.max_claims, args.max_timeline, args.seconds),
        include_source_locations=args.include_source_locations,
        metadata=metadata
    )


def render_result(result, args, palette):
    from forensic_assistant.retrieval.presentation import safe_text
    from .bundle import FILES
    directory = safe_text(result['output'])
    scope = (str(len(set(args.evidence_ids))) + ' explicit evidence records'
             if args.evidence_ids else str(len(args.investigation_ids)) + ' selected same-state investigations')
    status = ('Report generated with limitations.' if result['status'] == 'COMPLETE_WITH_LIMITATIONS'
              else 'Report generated.')
    from forensic_assistant.terminal import aligned_lines, field
    return aligned_lines([palette('heading', status), '', field('Directory', directory, palette),
                      field('Report ID', result['report_id'], palette), field('Scope', scope, palette),
                      palette('forensic_note', '  Completion applies to this bounded report, not a complete forensic examination.'),
                      '', 'Files:', *('  ' + name for name in FILES), '', 'Use:',
                      '  report show "' + directory + '"', '  report verify "' + directory + '"'])

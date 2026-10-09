from forensic_assistant.command_catalog import COMMANDS
from forensic_assistant.retrieval.presentation import human_error
import argparse
import json
import sqlite3
import sys
from contextlib import closing
from forensic_assistant.config import Config
from forensic_assistant.database.db import connect
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.llm.ask import ask
from forensic_assistant.llm.client import LLMError
from forensic_assistant.correlation.temporal import nearby
from forensic_assistant.retrieval.presentation import render_timeline
from forensic_assistant import v1_cli
from forensic_assistant import v2_cli
from forensic_assistant.correlation.models import get_event
from importlib.resources import files
from importlib.metadata import version

__version__ = version("locard-forensics")

def emit(value):
    # Escape control sequences from untrusted log content for terminal safety.
    print(json.dumps(value, ensure_ascii=True, indent=2))

def get_banner() -> str:
    return (
        files("forensic_assistant")
        .joinpath("resources/banner.txt")
        .read_text(encoding="utf-8")
    )

def get_liner() -> str:
    return (
        files("forensic_assistant")
        .joinpath("resources/liner.txt")
        .read_text(encoding="utf-8")
    )


def build_parser(*, interactive=False):
    from forensic_assistant.cli_parser import LocardParser, InteractiveParser, configure_interactive
    parser = (InteractiveParser if interactive else LocardParser)(
        prog='locard',
        description="Locard — local evidence-first Windows forensics"
    )
    parser.add_argument("--version", action="version", version="Locard " + __version__)
    parser.add_argument("--db", default=Config.database)
    parser.add_argument('--no-color', action='store_true', help='Disable terminal styling (also respects NO_COLOR)')
    commands = parser.add_subparsers(dest="command", required=True)
    v1_cli.configure(commands)
    search = commands.add_parser("search", help=COMMANDS['search'])
    for name in ("user", "ip", "hostname", "start", "end"):
        search.add_argument("--" + name)
    process = search.add_mutually_exclusive_group()
    process.add_argument(
        '--process',
        help='Exact executable name, case-insensitive; .exe may be omitted for a bare name. Explicit paths remain exact.'
    )
    process.add_argument(
        '--process-contains',
        metavar='PROCESS',
        help='Case-insensitive literal substring of the executable basename; no wildcards'
    )
    search.add_argument(
        '--ids',
        action='store_true',
        help='Include full copyable evidence IDs, numbered to match table rows; display paths may be shortened. Use show for details, --json for the existing structured projection, --raw for available raw payloads.'
    )
    search.add_argument("--event-id", type=int)
    search.add_argument(
        "--kind",
        choices=["logons", "failed-logons", "processes", "powershell", "scheduled-tasks", "services", "account-changes"]
    )
    timeline = commands.add_parser("timeline", help=COMMANDS['timeline'])
    timeline.add_argument("timestamp", nargs="?", help="Anchor time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:08:00Z")
    timeline.add_argument("--around", help="Anchor time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:08:00Z")
    timeline.add_argument("--start", help="Start time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:07:30Z")
    timeline.add_argument("--end", help="End time as ISO 8601 with Z or an explicit UTC offset, e.g. 2026-06-29T19:08:30Z")
    for name in ("user", "process", "ip", "hostname", "artifact-type"):
        timeline.add_argument("--" + name)
    timeline.add_argument("--event-id", type=int)
    timeline.add_argument("--minutes", type=int, default=5)
    around = commands.add_parser(
        "around",
        help=COMMANDS['around'],
        description='Compact text rounds timestamps and exact deltas to milliseconds (nearest, ties away from zero). JSON/raw and --ids retain full precision. Temporal proximity is not causation; timestamp meanings differ by artifact.'
    )
    around.add_argument("evidence_id")
    around.add_argument("--seconds", type=int, default=120)
    around.add_argument("--direction", choices=["before", "after", "around"], default="around")
    for command in (search, timeline):
        command.add_argument("--limit", type=int, default=20 if command is search else 100,
                             help='Maximum results (default: %(default)s)')
        command.add_argument("--offset", type=int, default=0)
        command.add_argument(
            "--raw",
            action="store_true",
            help="Include original XML or available artifact bytes/details"
        )
    around.add_argument("--limit", type=int, default=100)
    around.add_argument("--offset", type=int, default=0)
    around.add_argument("--raw", action="store_true")
    around.add_argument(
        '--ids',
        action='store_true',
        help='Include full evidence/source IDs, timestamp slots and original timestamp precision in --text output'
    )
    for command in (timeline, around):
        display = command.add_mutually_exclusive_group()
        display.add_argument("--json", action="store_true", help="JSON output (default)")
        display.add_argument("--text", action="store_true", help="Compact readable output")
    show = commands.add_parser(
        "show",
        help=COMMANDS['show'],
        description="Human summary with populated timestamps and bounded references. --json preserves the structured projection; --raw includes available XML/artifact bytes. Both retain existing 100-object/reference/value-ID bounds and truncation flags."
    )
    show.add_argument("evidence_id")
    show.add_argument("--raw", action="store_true")
    commands.add_parser("status", help=COMMANDS['status'])
    ask_parser = commands.add_parser("ask", help=COMMANDS['ask'])
    ask_parser.add_argument("question")
    ask_parser.add_argument("--endpoint", default=Config.endpoint)
    ask_parser.add_argument("--date", help="UTC date for time-only questions")
    ask_parser.add_argument("--limit", type=int, default=30)
    ask_parser.add_argument("--timeout", type=float, default=Config.timeout)
    ask_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show plan and evidence without contacting the model"
    )
    v2_cli.configure(commands)
    from forensic_assistant.semantic import cli as semantic_cli
    semantic_cli.configure(commands, ask_parser)
    from forensic_assistant.investigation_ai import cli as investigation_cli
    investigation_cli.configure(commands)
    from forensic_assistant.reporting import cli as report_cli
    report_cli.configure(commands)
    from forensic_assistant import source_cli
    source_cli.configure(commands)
    from forensic_assistant import activity
    activity.configure(commands)
    from forensic_assistant.output import configure
    configure(commands)
    if interactive:
        configure_interactive(parser)
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv == ['--no-color']:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            print('Locard: interactive mode requires a terminal; supply a command for scripts.', file=sys.stderr)
            return 2
        from forensic_assistant.terminal import banner
        no_color = '--no-color' in argv
        print(banner(get_banner(), argparse.Namespace(no_color=no_color)))
        from forensic_assistant.interactive.shell import run
        return run(no_color=True) if no_color else run()
    args = build_parser().parse_args(argv)
    args._argv = argv
    return dispatch(args)


def dispatch(args, *, existing_only=False):
    from forensic_assistant.output import Output
    from forensic_assistant import activity
    output = None
    with activity.Command(args) as command:
        try:
            output = Output(args)
            command.code = _dispatch(args, output, existing_only=existing_only)
            output.finish()
            return command.code
        except activity.Cancelled as exc:
            from forensic_assistant.terminal import message
            activity.note_error(exc)
            message(human_error(exc), args, role='warning')
            command.code = 130
            return 130
        except (ValueError, OSError, sqlite3.Error) as exc:
            from forensic_assistant.terminal import message
            activity.note_error(exc)
            message(human_error(exc), args)
            command.code = 2
            return 2
        finally:
            if output is not None:
                output.close()


def _dispatch(args, output, *, existing_only=False):
    from forensic_assistant import activity
    def emit(value):
        activity.result_count(value)
        output.json(value)
    from forensic_assistant.semantic import cli as semantic_cli
    from forensic_assistant.investigation_ai import cli as investigation_cli
    from forensic_assistant.reporting import cli as report_cli
    try:
        if args.command == 'activity':
            if activity.CURRENT.get() is None:
                raise ValueError('Activity requires an existing valid Locard case')
            result = activity.inspect(activity.sidecar(args.db), args.limit)
            if args.json:
                emit(result)
            else:
                output.write(activity.render(result, verify=args.verify, palette=output.palette))
            return 0 if result['valid'] else 2
        if args.command == 'report':
            try:
                result = report_cli.dispatch(args)
                emit(result)
                return 2 if any(result.get(k) == 'FAIL' for k in (
                    'file_integrity',
                    'structure',
                    'case_fingerprint',
                    'evidence_grounding'
                )) else 0
            except (ValueError, OSError, KeyError, TypeError) as exc:
                activity.note_error(exc)
                emit({
                    'status': 'FAILED',
                    'error': str(exc),
                    'published': getattr(exc, 'action_completed', False) if args.report_command == 'generate' else None
                })
                return 2
        if args.command in ('investigate-ai', 'investigation'):
            emit(investigation_cli.dispatch(args))
            return 0
        if args.command == 'semantic' and args.semantic_command == 'setup':
            from forensic_assistant.semantic.model import setup
            emit(setup(args.destination, args.model))
            return 0
        if args.command == 'semantic':
            from pathlib import Path
            if not Path(args.db).is_file():
                raise ValueError('Semantic commands require an existing evidence database')
        from pathlib import Path
        was_missing = str(args.db) != ':memory:' and not Path(args.db).exists()
        with closing(connect(args.db, existing_only=True) if existing_only or args.command == 'source' else connect(args.db)) as db:
            command = activity.COMMAND.get()
            if command:
                command.attach(args.db, created=was_missing)
            if args.command == 'source':
                from forensic_assistant import source_cli
                result = source_cli.dispatch(db, args)
                if args.source_command == 'list' and not args.json:
                    output.write(source_cli.render_list(result, output.palette, ids=args.ids))
                elif args.source_command == 'show' and not args.json and not args.details:
                    output.write(source_cli.render_show(result, output.palette))
                elif args.source_command == 'update' and not args.json:
                    output.write(source_cli.render_update(result, output.palette))
                elif args.source_command == 'assign' and not args.json:
                    output.write(source_cli.render_assignment(result, output.palette))
                else:
                    emit(result)
                return 0
            if args.command == 'semantic':
                emit(semantic_cli.dispatch(db, args))
                return 0
            presentation = {}
            v2_result = v2_cli.dispatch(db, args, presentation=presentation)
            if v2_result is not None:
                result, code = v2_result
                activity.result_count(result)
                if args.command == 'search' and not args.json and not args.raw:
                    from forensic_assistant.retrieval.search_display import render
                    output.write(render(result, output.palette, ids=args.ids))
                elif args.command == 'show' and not args.json and not args.raw:
                    from forensic_assistant.retrieval.show_display import render
                    output.write(render(result, output.palette, registry_values=presentation.get('registry_values')))
                elif args.command == 'status' and not args.json:
                    from forensic_assistant.retrieval.status_display import render
                    output.write(render(result, args.db, presentation['status'], output.palette))
                elif args.command == 'around' and args.text and not args.raw:
                    from forensic_assistant.retrieval.around_display import render
                    output.write(render(result, presentation['anchor'], presentation['stamp'], args, output.palette))
                elif getattr(args, 'text', False):
                    output.write(v2_cli.render(result, methodology=args.raw, palette=output.palette))
                else:
                    emit(result)
                return code
            v1_result = v1_cli.dispatch(db, args)
            if v1_result is not None:
                activity.result_count(v1_result)
                if not args.raw:
                    v1_result = v1_cli.omit_raw(v1_result)
                if args.text and not args.raw and args.command in ('logons', 'detections', 'process-tree'):
                    from forensic_assistant.retrieval import analyst_display
                    if args.command == 'logons':
                        context = analyst_display.evtx_context(db, v1_result['records'])
                        text = analyst_display.render_logons(v1_result, output.palette, context=context)
                    elif args.command == 'detections':
                        text = analyst_display.render_detections(v1_result, output.palette)
                    else:
                        text = analyst_display.render_process_tree(v1_result, output.palette)
                    output.write(text)
                elif args.text and not args.raw and args.command in ('session', 'investigate'):
                    from forensic_assistant.retrieval.analysis_display import render_session, render_investigation
                    if args.command == 'session':
                        from forensic_assistant.retrieval.analyst_display import evtx_context
                        output.write(render_session(v1_result, output.palette, context=evtx_context(db, v1_result['records'])))
                    else:
                        output.write(render_investigation(v1_result, output.palette))
                elif args.text:
                    output.write(v1_cli.render(v1_result, methodology=args.raw))
                else:
                    emit(v1_result)
                return 0
            queries = Queries(db)
            if args.command == "ask":
                emit(ask(
                    queries,
                    args.question,
                    endpoint=args.endpoint,
                    date_hint=args.date,
                    limit=args.limit,
                    dry_run=args.dry_run,
                    timeout=args.timeout,
                    semantic_index=args.semantic_index,
                    embedding_model=args.embedding_model
                ))
                return 0
            if args.command == "status":
                emit(queries.coverage())
                return 0
            if args.command == "show":
                result = queries.show(args.evidence_id)
                if not args.raw:
                    result.pop("raw_xml")
                emit(result)
                return 0
            if args.command == "around":
                result = nearby(db, args.evidence_id, args.seconds, args.direction, args.limit, args.offset)
            elif args.command == "timeline":
                if args.timestamp and args.around:
                    raise ValueError("Specify either positional timestamp or --around")
                anchor = args.around or args.timestamp
                filters = {k: getattr(args, k) for k in ("process", "ip", "hostname", "event_id", "limit", "offset")}
                filters["username"] = args.user
                filters["artifact_types"] = [args.artifact_type] if args.artifact_type else None
                if anchor:
                    if args.start or args.end:
                        raise ValueError("Do not combine --around with --start/--end")
                    result = queries.timeline_around(anchor, args.minutes, **filters)
                else:
                    if not args.start or not args.end:
                        raise ValueError("Timeline requires --start and --end, or --around")
                    result = queries.events_between(args.start, args.end, **filters)
            else:
                filters = {k: getattr(args, k) for k in (
                    "ip",
                    "process",
                    "hostname",
                    "start",
                    "end",
                    "event_id",
                    "limit",
                    "offset"
                )}
                filters["username"] = args.user
                function = getattr(queries, "find_" + args.kind.replace("-", "_")) if args.kind else queries.search
                result = function(**filters)
            rendered = result.as_dict()
            if args.command == "timeline":
                rendered["records"] = [get_event(db, record["id"]) for record in rendered["records"]]
            if not args.raw:
                for record in rendered["records"]:
                    record.pop("raw_xml")
            rendered["caution"] = queries.coverage()["caution"]
            if getattr(args, "text", False):
                output.write(render_timeline(rendered, methodology=args.raw))
            else:
                emit(rendered)
            return 0
    except (ValueError, OSError, sqlite3.Error, OverflowError, LLMError) as exc:
        from forensic_assistant.terminal import message
        activity.note_error(exc)
        message(human_error(exc), args)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

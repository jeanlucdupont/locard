import argparse
import json
import sqlite3
import sys
from contextlib import closing
from forensic_assistant import __version__
from forensic_assistant.config import Config
from forensic_assistant.database.db import connect
from forensic_assistant.database.migrations import migrate
from forensic_assistant.ingest.evtx import discover, ingest_file
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.llm.ask import ask
from forensic_assistant.llm.client import LLMError
from forensic_assistant.correlation.temporal import nearby
from forensic_assistant.retrieval.presentation import render_timeline
from forensic_assistant import v1_cli
from forensic_assistant import v2_cli
from forensic_assistant.correlation.models import get_event


def emit(value):
    # Escape control sequences from untrusted log content for terminal safety.
    print(json.dumps(value, ensure_ascii=True, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Locard — local evidence-first Windows forensics")
    parser.add_argument("--version", action="version", version="Locard V2 (" + __version__ + ")")
    parser.add_argument("--db", default=Config.database)
    commands = parser.add_subparsers(dest="command", required=True)
    v1_cli.configure(commands)
    commands.add_parser("migrate", help="Back up and explicitly migrate a V0/V1 database")
    ingest = commands.add_parser("ingest", help="Recursively ingest EVTX files")
    ingest.add_argument("path")
    search = commands.add_parser("search", help="Deterministic evidence search")
    for name in ("user", "ip", "process", "hostname", "start", "end"):
        search.add_argument("--" + name)
    search.add_argument("--event-id", type=int)
    search.add_argument("--kind", choices=["logons", "failed-logons", "processes", "powershell", "scheduled-tasks", "services", "account-changes"])
    timeline = commands.add_parser("timeline")
    timeline.add_argument("timestamp", nargs="?", help="V0-compatible anchor timestamp")
    timeline.add_argument("--around")
    timeline.add_argument("--start")
    timeline.add_argument("--end")
    for name in ("user", "process", "ip", "hostname", "artifact-type"):
        timeline.add_argument("--" + name)
    timeline.add_argument("--event-id", type=int)
    timeline.add_argument("--minutes", type=int, default=5)
    around = commands.add_parser("around", help="Same-host temporal context around evidence")
    around.add_argument("evidence_id")
    around.add_argument("--seconds", type=int, default=120)
    around.add_argument("--direction", choices=["before", "after", "around"], default="around")
    for command in (search, timeline):
        command.add_argument("--limit", type=int, default=100)
        command.add_argument("--offset", type=int, default=0)
        command.add_argument("--raw", action="store_true", help="Include original XML or available artifact bytes/details")
    around.add_argument("--limit", type=int, default=100)
    around.add_argument("--offset", type=int, default=0)
    around.add_argument("--raw", action="store_true")
    for command in (timeline, around):
        display = command.add_mutually_exclusive_group()
        display.add_argument("--json", action="store_true", help="JSON output (default)")
        display.add_argument("--text", action="store_true", help="Compact readable output")
    show = commands.add_parser("show", help="Look up evidence and all observed source paths")
    show.add_argument("evidence_id")
    show.add_argument("--raw", action="store_true")
    commands.add_parser("status", help="Show ingestion status and coverage limitations")
    ask_parser = commands.add_parser("ask", help="Retrieve evidence and ask local llama.cpp")
    ask_parser.add_argument("question")
    ask_parser.add_argument("--endpoint", default=Config.endpoint)
    ask_parser.add_argument("--date", help="UTC date for time-only questions")
    ask_parser.add_argument("--limit", type=int, default=30)
    ask_parser.add_argument("--timeout", type=float, default=Config.timeout)
    ask_parser.add_argument("--dry-run", action="store_true", help="Show plan and evidence without contacting the model")
    v2_cli.configure(commands)
    args = parser.parse_args(argv)
    try:
        if args.command == "migrate":
            emit(migrate(args.db))
            return 0
        with closing(connect(args.db)) as db:
            v2_result = v2_cli.dispatch(db,args)
            if v2_result is not None:
                result,code=v2_result
                if getattr(args,'text',False):print(v2_cli.render(result))
                else:emit(result)
                return code
            v1_result = v1_cli.dispatch(db, args)
            if v1_result is not None:
                if not args.raw:
                    v1_result = v1_cli.omit_raw(v1_result)
                if args.text:
                    print(v1_cli.render(v1_result))
                else:
                    emit(v1_result)
                return 0
            queries = Queries(db)
            if args.command == "ask":
                emit(ask(queries, args.question, endpoint=args.endpoint, date_hint=args.date,
                         limit=args.limit, dry_run=args.dry_run, timeout=args.timeout))
                return 0
            if args.command == "ingest":
                found = failed = False
                for path in discover(args.path):
                    found = True
                    result = ingest_file(db, path, reporter=lambda msg: print(json.dumps(msg), file=sys.stderr))
                    emit(result)
                    failed |= result["status"] != "complete"
                if not found:
                    print("No EVTX files found.", file=sys.stderr)
                    return 1
                return 1 if failed else 0
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
                filters = {k: getattr(args, k) for k in ("ip", "process", "hostname", "start", "end", "event_id", "limit", "offset")}
                filters["username"] = args.user
                function = getattr(queries, "find_" + args.kind.replace("-", "_")) if args.kind else queries.search
                result = function(**filters)
            output = result.as_dict()
            if args.command == "timeline":
                output["records"] = [get_event(db, record["id"]) for record in output["records"]]
            if not args.raw:
                for record in output["records"]:
                    record.pop("raw_xml")
            output["caution"] = queries.coverage()["caution"]
            if getattr(args, "text", False):
                print(render_timeline(output))
            else:
                emit(output)
            return 0
    except (ValueError, OSError, sqlite3.Error, OverflowError, LLMError) as exc:
        print("Locard: " + json.dumps(str(exc)), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

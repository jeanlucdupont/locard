"""V1 command wiring, leaving V0 command behavior in cli.py."""
from forensic_assistant.command_catalog import COMMANDS
from forensic_assistant.correlation.models import get_event
from forensic_assistant.correlation.processes import process_tree
from forensic_assistant.correlation.sessions import session, logons
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.retrieval.presentation import safe, render_timeline
from forensic_assistant.detections.engine import detections
from forensic_assistant.correlation.investigation import investigate
from forensic_assistant.llm.timeline import analyze_timeline


def output_options(parser, *, interactive_text=False):
    display = parser.add_mutually_exclusive_group()
    display.add_argument("--json", action="store_true", help='Output as JSON')
    display.add_argument("--text", action="store_true", help='Show readable text')
    parser.add_argument("--raw", action="store_true", help='Show the full diagnostic result as JSON')
    if interactive_text:
        parser.set_defaults(_interactive_text=True)
        parser.epilog = ('Interactive shell defaults to human text; direct CLI defaults to JSON. '
                         '--raw retains diagnostic output, defaulting to JSON. '
                         'Use --text for human paging; JSON paging is not supported.')


def configure(commands):
    tree = commands.add_parser("process-tree", help=COMMANDS['process-tree'])
    tree.missing_selector_guidance = (
        'process-tree requires either:\n  --evidence <process-creation evidence ID>\n'
        'or:\n  --process <name> --around <timestamp>\n\nType `help analyze process-tree` for details.')
    selector = tree.add_mutually_exclusive_group(required=True)
    selector.add_argument("--evidence", help='Process-creation evidence ID')
    selector.add_argument("--process", help='Process name filter')
    tree.add_argument("--around", help='Anchor time with timezone')
    tree.add_argument("--hostname", help='Hostname filter')
    tree.add_argument("--seconds", type=int, default=300, help='Child-process window in seconds')
    tree.add_argument("--pid-window", type=int, default=300, help='PID reuse lookback window in seconds')
    tree.add_argument("--max-nodes", type=int, default=100, help='Maximum process nodes')
    tree.add_argument("--max-depth", type=int, default=8, help='Maximum process relationship depth')
    auth = commands.add_parser("logons", help=COMMANDS['logons'], description=COMMANDS['logons'])
    for name in ("user", "ip", "hostname", "start", "end"):
        auth.add_argument("--" + name, help={'user': 'Username filter', 'hostname': 'Hostname filter', 'process': 'Process name filter', 'ip': 'IP address filter', 'start': 'Start time; ISO shorthand defaults to UTC', 'end': 'End time; ISO shorthand defaults to UTC', 'artifact-type': 'Normalized artifact type filter', 'rule': 'Detection rule', 'artifact': 'Artifact family filter', 'path': 'Literal evidence path filter'}[name])
    auth.add_argument("--limit", type=int, default=100, help='Maximum number of results')
    auth.add_argument("--offset", type=int, default=0, help='Skip this many results')
    sessions = commands.add_parser("session", help=COMMANDS['session'])
    sessions.add_argument(
        "--logon-id", required=True,
        help="Windows authentication Logon ID, decimal or hexadecimal (for example 0x1cd8f6); not a Locard evidence ID"
    )
    sessions.add_argument("--hostname", help='Hostname filter')
    sessions.add_argument("--around", help='Anchor time with timezone')
    sessions.add_argument("--evidence", help='Successful-logon evidence ID for disambiguation')
    sessions.add_argument("--max-hours", type=int, default=24, help='Maximum session duration in hours')
    sessions.add_argument("--limit", type=int, default=500, help='Maximum number of results')
    detect = commands.add_parser("detections", help=COMMANDS['detections'])
    for name in ("start", "end", "user", "hostname", "rule"):
        detect.add_argument("--" + name, help={'user': 'Username filter', 'hostname': 'Hostname filter', 'process': 'Process name filter', 'ip': 'IP address filter', 'start': 'Start time; ISO shorthand defaults to UTC', 'end': 'End time; ISO shorthand defaults to UTC', 'artifact-type': 'Normalized artifact type filter', 'rule': 'Detection rule', 'artifact': 'Artifact family filter', 'path': 'Literal evidence path filter'}[name])
    detect.add_argument("--severity", choices=["low", "medium", "high"], help='Recorded severity filter')
    detect.add_argument("--limit", type=int, default=100, help='Maximum number of results')
    detect.add_argument("--candidate-limit", type=int, default=1000, help='Maximum candidate records examined')
    detect.add_argument("--failure-threshold", type=int, default=5, help='Minimum failed logons for a detection')
    detect.add_argument("--failure-window", type=int, default=300, help='Failed-logon window in seconds')
    investigation = commands.add_parser("investigate", help=COMMANDS['investigate'],
        description="Deterministic correlation around a specific evidence record identified by its canonical evidence_id. Gathers nearby and related evidence within bounded criteria; no AI required.")
    investigation.add_argument("evidence_id", help='Anchor evidence ID')
    investigation.add_argument("--seconds", type=int, default=120, help="Time window around the anchor, in seconds (default: 120)")
    investigation.add_argument("--candidate-limit", type=int, default=500, help="Maximum candidate volume (default: 500)")
    analysis = commands.add_parser("analyze-timeline", help=COMMANDS['analyze-timeline'],
        description="Specialized workflow: deterministic retrieval and correlation in an explicit time range, followed by local AI analysis. --dry-run builds the bounded evidence bundle without calling the model. Model analysis is not evidence; citation checks do not establish factual correctness.")
    analysis.add_argument("--start", required=True, help='Start time; ISO shorthand defaults to UTC')
    analysis.add_argument("--end", required=True, help='End time; ISO shorthand defaults to UTC')
    analysis.add_argument("--hostname", help='Hostname filter')
    analysis.add_argument("--user", help='Username filter')
    analysis.add_argument("--candidate-limit", type=int, default=500, help='Maximum candidate records examined')
    analysis.add_argument("--endpoint", default=None, help='Local model endpoint')
    analysis.add_argument("--timeout", type=float, default=120, help='Request timeout in seconds')
    analysis.add_argument("--dry-run", action="store_true", help='Preview without contacting AI')
    for command in (tree, auth, sessions, detect, investigation):
        output_options(command, interactive_text=True)
    output_options(analysis)


def dispatch(db, args):
    if args.command == "analyze-timeline":
        return analyze_timeline(
            db,
            args.start,
            args.end,
            hostname=args.hostname,
            username=args.user,
            max_candidates=args.candidate_limit,
            endpoint=args.endpoint,
            timeout=args.timeout,
            dry_run=args.dry_run
        )
    if args.command == "investigate":
        result = investigate(
            db,
            args.evidence_id,
            seconds=args.seconds,
            max_candidates=args.candidate_limit,
            timestamp_slot=args.timestamp_slot
        )
        if args.raw:
            from forensic_assistant.retrieval.evidence import get_evidence
            result['evidence_records'] = [get_evidence(db, r['id'], raw=True) for r in result['evidence_records']]
        return result
    if args.command == "detections":
        return detections(
            db,
            start=args.start,
            end=args.end,
            username=args.user,
            hostname=args.hostname,
            severity=args.severity,
            rule_id=args.rule,
            limit=args.limit,
            candidate_limit=args.candidate_limit,
            failure_threshold=args.failure_threshold,
            failure_window_seconds=args.failure_window
        )
    if args.command == "process-tree":
        evidence_id = args.evidence
        if not evidence_id:
            if not args.around:
                raise ValueError("--process requires --around <timestamp> to bound candidate anchors. "
                                 "Alternatively, use --evidence <process-creation evidence ID>.")
            results = Queries(db).timeline_around(
                args.around,
                minutes=5,
                process=args.process,
                hostname=args.hostname,
                artifact_types=["process"],
                limit=100
            )
            if results.total != 1:
                return {
                    "status": "UNRESOLVED",
                    "reason": "Select a unique process using --evidence",
                    "candidate_evidence_ids": [e["id"] for e in results.records],
                    "total": results.total
                }
            evidence_id = results.records[0]["id"]
        return process_tree(
            db,
            evidence_id,
            lookback_seconds=args.pid_window,
            seconds=args.seconds,
            max_nodes=args.max_nodes,
            max_depth=args.max_depth
        )
    if args.command == "logons":
        return logons(db, args.user, args.ip, args.hostname, args.start, args.end, args.limit, args.offset).as_dict()
    if args.command == "session":
        return session(
            db,
            args.logon_id,
            hostname=args.hostname,
            around=args.around,
            anchor_id=args.evidence,
            max_hours=args.max_hours,
            limit=args.limit
        )
    return None


def omit_raw(value):
    if isinstance(value, dict):
        return {key: omit_raw(item) for key, item in value.items() if key != "raw_xml"}
    if isinstance(value, list):
        return [omit_raw(item) for item in value]
    return value


def render(value, *, methodology=True):
    if "nodes" in value:
        lines = ["PROCESS EVIDENCE"]
        for node in value["nodes"]:
            lines.append(f"{safe(node['timestamp_utc'])} | {safe(node['id'])} | {safe(node['process_name'])} | PID {safe(node['pid'])}")
        lines.append("PARENT -> CHILD RELATIONSHIPS")
        for relation in value["relationships"]:
            lines.append(f"{safe(relation['source_id'])} -> {safe(relation['target_id'])} [{relation['status']}]: {safe(relation['reason'])}")
        lines.extend(safe(limit) for limit in value["limits"])
        return "\n".join(lines)
    if "records" in value and "total" in value:
        return render_timeline(value, methodology=methodology)
    import json
    return json.dumps(value, ensure_ascii=True, indent=2)

"""V1 command wiring, leaving V0 command behavior in cli.py."""
from forensic_assistant.correlation.models import get_event
from forensic_assistant.correlation.processes import process_tree
from forensic_assistant.correlation.sessions import session, logons
from forensic_assistant.retrieval.queries import Queries
from forensic_assistant.retrieval.presentation import safe, render_timeline
from forensic_assistant.detections.engine import detections
from forensic_assistant.correlation.investigation import investigate
from forensic_assistant.llm.timeline import analyze_timeline


def output_options(parser):
    display = parser.add_mutually_exclusive_group()
    display.add_argument("--json", action="store_true", help="JSON output (default)")
    display.add_argument("--text", action="store_true")
    parser.add_argument("--raw", action="store_true")


def configure(commands):
    tree = commands.add_parser("process-tree", help="Reconstruct evidenced process relationships")
    selector = tree.add_mutually_exclusive_group(required=True)
    selector.add_argument("--evidence")
    selector.add_argument("--process")
    tree.add_argument("--around")
    tree.add_argument("--hostname")
    tree.add_argument("--seconds", type=int, default=300)
    tree.add_argument("--pid-window", type=int, default=300)
    tree.add_argument("--max-nodes", type=int, default=100)
    tree.add_argument("--max-depth", type=int, default=8)
    auth = commands.add_parser("logons", help="Authentication events with explicit subject/target roles")
    for name in ("user", "ip", "hostname", "start", "end"):
        auth.add_argument("--" + name)
    auth.add_argument("--limit", type=int, default=100)
    auth.add_argument("--offset", type=int, default=0)
    sessions = commands.add_parser("session", help="Host-scoped Logon ID correlation")
    sessions.add_argument("--logon-id", required=True)
    sessions.add_argument("--hostname")
    sessions.add_argument("--around")
    sessions.add_argument("--evidence", help="Successful-logon evidence ID to disambiguate")
    sessions.add_argument("--max-hours", type=int, default=24)
    sessions.add_argument("--limit", type=int, default=500)
    detect = commands.add_parser("detections", help="Dynamic deterministic observations requiring review")
    for name in ("start", "end", "user", "hostname", "rule"):
        detect.add_argument("--" + name)
    detect.add_argument("--severity", choices=["low", "medium", "high"])
    detect.add_argument("--limit", type=int, default=100)
    detect.add_argument("--candidate-limit", type=int, default=1000)
    detect.add_argument("--failure-threshold", type=int, default=5)
    detect.add_argument("--failure-window", type=int, default=300)
    investigation = commands.add_parser("investigate", help="Assemble deterministic context without a model")
    investigation.add_argument("evidence_id")
    investigation.add_argument("--seconds", type=int, default=120)
    investigation.add_argument("--candidate-limit", type=int, default=500)
    analysis = commands.add_parser("analyze-timeline", help="Local model summary of a deterministic timeline")
    analysis.add_argument("--start", required=True)
    analysis.add_argument("--end", required=True)
    analysis.add_argument("--hostname")
    analysis.add_argument("--user")
    analysis.add_argument("--candidate-limit", type=int, default=500)
    analysis.add_argument("--endpoint", default="http://127.0.0.1:8080")
    analysis.add_argument("--timeout", type=float, default=120)
    analysis.add_argument("--dry-run", action="store_true")
    for command in (tree, auth, sessions, detect, investigation, analysis):
        output_options(command)


def dispatch(db, args):
    if args.command == "analyze-timeline":
        return analyze_timeline(db, args.start, args.end, hostname=args.hostname, username=args.user,
                                max_candidates=args.candidate_limit, endpoint=args.endpoint,
                                timeout=args.timeout, dry_run=args.dry_run)
    if args.command == "investigate":
        result=investigate(db, args.evidence_id, seconds=args.seconds, max_candidates=args.candidate_limit,timestamp_slot=args.timestamp_slot)
        if args.raw:
            from forensic_assistant.retrieval.evidence import get_evidence
            result['evidence_records']=[get_evidence(db,r['id'],raw=True) for r in result['evidence_records']]
        return result
    if args.command == "detections":
        return detections(db, start=args.start, end=args.end, username=args.user, hostname=args.hostname,
                          severity=args.severity, rule_id=args.rule, limit=args.limit, candidate_limit=args.candidate_limit,
                          failure_threshold=args.failure_threshold, failure_window_seconds=args.failure_window)
    if args.command == "process-tree":
        evidence_id = args.evidence
        if not evidence_id:
            if not args.around:
                raise ValueError("--process requires --around to bound candidate anchors")
            results = Queries(db).timeline_around(args.around, minutes=5, process=args.process,
                         hostname=args.hostname, artifact_types=["process"], limit=100)
            if results.total != 1:
                return {"status": "UNRESOLVED", "reason": "Select a unique process using --evidence",
                        "candidate_evidence_ids": [e["id"] for e in results.records], "total": results.total}
            evidence_id = results.records[0]["id"]
        return process_tree(db, evidence_id, lookback_seconds=args.pid_window, seconds=args.seconds,
                            max_nodes=args.max_nodes, max_depth=args.max_depth)
    if args.command == "logons":
        return logons(db, args.user, args.ip, args.hostname, args.start, args.end, args.limit, args.offset).as_dict()
    if args.command == "session":
        return session(db, args.logon_id, hostname=args.hostname, around=args.around,
                       anchor_id=args.evidence, max_hours=args.max_hours, limit=args.limit)
    return None


def omit_raw(value):
    if isinstance(value, dict):
        return {key: omit_raw(item) for key, item in value.items() if key != "raw_xml"}
    if isinstance(value, list):
        return [omit_raw(item) for item in value]
    return value


def render(value):
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
        return render_timeline(value)
    import json
    return json.dumps(value, ensure_ascii=True, indent=2)

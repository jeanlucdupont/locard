"""Optional V4 commands are routed before the legacy write-capable opener."""
import json
from pathlib import Path
import sys
from forensic_assistant.config import Config
from forensic_assistant.llm.client import LocalClient
from .controller import run
from .state import Budget
from .transcript import load, implementation

def configure(commands):
    p = commands.add_parser('investigate-ai', help='Bounded local model requests for read-only forensic operations')
    p.add_argument('question')
    p.add_argument('--endpoint', default=Config.endpoint)
    p.add_argument('--date')
    p.add_argument('--max-steps', type=int, default=8)
    p.add_argument('--max-tool-calls', type=int, default=6)
    p.add_argument('--max-seconds', type=int, default=300)
    p.add_argument('--dry-run', action='store_true', help='Initial retrieval plus one model proposal; no iterative tool execution')
    p.add_argument('--approve-tools', action='store_true', help='Require interactive approval for each proposed operation')
    review = commands.add_parser('investigation', help='Inspect or replay derived investigation transcripts')
    subs = review.add_subparsers(dest='investigation_command', required=True)
    show = subs.add_parser('show'); show.add_argument('investigation_id')
    replay = subs.add_parser('replay'); replay.add_argument('investigation_id')
    for command in (p, show, replay):
        command.add_argument('--transcripts', help='Derived sidecar root; default: DATABASE.investigations')
        command.add_argument('--json', action='store_true')
        command.add_argument('--explain', action='store_true', help='Include step-by-step transcript data')
    for command in (p, replay):
        command.add_argument('--no-semantic', action='store_true')
        command.add_argument('--semantic-index')
        command.add_argument('--embedding-model')

def approve(proposal, seconds):
    if not sys.stdin.isatty(): raise ValueError('--approve-tools requires an interactive terminal')
    print(json.dumps(proposal, ensure_ascii=True), file=sys.stderr)
    from forensic_assistant.interactive.console import timed_line
    try:
        return timed_line('Approve this read-only operation? [y/N] ', max(.001,seconds)).strip().casefold() == 'y'
    except (TimeoutError,EOFError):
        return False


def dispatch(args):
    root = args.transcripts or str(Path(args.db)) + '.investigations'
    if args.command == 'investigation' and args.investigation_command == 'show':
        manifest, events = load(root, args.investigation_id)
        result = {'manifest': manifest, 'recorded_not_revalidated': True,
                  'caution': 'Derived untrusted transcript; case may have changed. Replay checks current compatibility.',
                  'terminal': next((e['data'] for e in reversed(events) if e['kind']=='terminal'), None)}
        result['implementation_matches'] = all(manifest.get(k)==v for k,v in implementation().items())
        from .runner import ForensicWorker
        try:
            with ForensicWorker({'case_path':args.db,'semantic_enabled':False}) as worker:
                current=worker.call('check',seconds=45)
            result['current_case_status']={'matches_recorded_fingerprint':current['fingerprint']==manifest.get('evidence_fingerprint')}
        except (OSError,ValueError) as exc:
            result['current_case_status']={'unavailable':str(exc)[:300]}
        if args.explain: result['events'] = events
        return result
    from forensic_assistant.semantic.index import default_root
    config = {'case_path': args.db, 'semantic_enabled': not args.no_semantic,
              'index_root': args.semantic_index or str(default_root(args.db)),
              'model_path': args.embedding_model or str(Path(args.db).parent/'semantic-models'/'bge'),
              'date_hint': getattr(args, 'date', None)}
    if args.command == 'investigation':
        from .replay import replay
        return replay(config, root, args.investigation_id)
    if args.approve_tools and not sys.stdin.isatty(): raise ValueError('--approve-tools requires an interactive terminal')
    result = run(config, args.question, root, budget=Budget(steps=args.max_steps, calls=args.max_tool_calls, seconds=args.max_seconds),
                 client=LocalClient(args.endpoint), dry_run=args.dry_run, approval=approve if args.approve_tools else None)
    if args.explain:
        _, events = load(root, result['investigation_id']); result['events'] = events
    return result

def render(result):
    # JSON quoting prevents terminal-control injection from evidence/model text.
    return json.dumps(result, ensure_ascii=True, indent=2)

"""Optional V4 commands are routed before the legacy write-capable opener."""
from forensic_assistant.command_catalog import COMMANDS
import json
from pathlib import Path
import sys
from forensic_assistant.config import Config
from forensic_assistant.ai.backend import backend as LocalClient
from .supervision import run
from .state import Budget
from .transcript import load, implementation

def configure(commands):
    p = commands.add_parser('investigate-ai', help=COMMANDS['investigate-ai'], description='Advanced / Diagnostic interface. Use ! <question> for normal interactive AI requests.')
    p.add_argument('question')
    p.add_argument('--endpoint', default=None, help='Advanced existing loopback endpoint; overrides configured provider for this invocation')
    p.add_argument('--date')
    p.add_argument('--max-steps', type=int, default=8)
    p.add_argument('--max-tool-calls', type=int, default=6)
    p.add_argument('--max-seconds', type=int, default=300)
    p.add_argument(
        '--dry-run',
        action='store_true',
        help='Initial retrieval plus one model proposal; no iterative tool execution'
    )
    p.add_argument(
        '--approve-tools',
        action='store_true',
        help='Require interactive approval for each proposed operation'
    )
    review = commands.add_parser('ai-history', help=COMMANDS['ai-history'],
        description='Review or replay saved derived AI investigation records for audit and review. These records are not source evidence.',
        epilog='Saved records are derived data; replay does not establish forensic conclusions.')
    subs = review.add_subparsers(dest='investigation_command', required=True)
    show = subs.add_parser('show', help='Review a saved AI investigation')
    show.add_argument('investigation_id')
    replay = subs.add_parser('replay', help='Replay saved lookups against the current case')
    replay.add_argument('investigation_id')
    for command in (p, show, replay):
        command.add_argument('--transcripts', help='Sensitive local derived records, not evidence; default: DATABASE.investigations. Analyst controls retention/deletion.')
        command.add_argument('--json', action='store_true')
        command.add_argument('--explain', action='store_true', help='Include step-by-step transcript data')
    for command in (p, replay):
        command.add_argument('--no-semantic', action='store_true')
        command.add_argument('--semantic-index')
        command.add_argument('--embedding-model')

def approve(proposal, seconds, *, args=None):
    if not sys.stdin.isatty():
        raise ValueError('--approve-tools requires an interactive terminal')
    from .presentation import proposal_text
    from forensic_assistant.terminal import Palette, enabled
    palette = Palette(enabled(args, sys.stderr))
    print(proposal_text(proposal, palette), file=sys.stderr)
    from forensic_assistant.interactive.console import timed_line
    try:
        from contextlib import redirect_stdout
        with redirect_stdout(sys.stderr):
            return timed_line(palette('key', 'Approve this lookup? [y/N] '), max(.001, seconds)).strip().casefold() == 'y'
    except (TimeoutError, EOFError):
        return False


def dispatch(args):
    from forensic_assistant.terminal_activity import ActivityIndicator
    label = ("Loading saved AI investigation..." if getattr(args, "investigation_command", None) == "show" else "Replaying AI investigation...") if args.command == "ai-history" else ""
    with ActivityIndicator(label, args=args):
        return _dispatch(args)


def _dispatch(args):
    root = args.transcripts or str(Path(args.db)) + '.investigations'
    if args.command == 'ai-history' and args.investigation_command == 'show':
        manifest, events = load(root, args.investigation_id)
        result = {
            'manifest': manifest,
            'recorded_not_revalidated': True,
            'caution': 'Derived untrusted transcript; case may have changed. Replay checks current compatibility.',
            'terminal': next((e['data'] for e in reversed(events) if e['kind'] == 'terminal'), None)
        }
        result['implementation_matches'] = all(manifest.get(k) == v for k, v in implementation().items())
        from .runner import ForensicWorker
        try:
            with ForensicWorker({'case_path': args.db, 'semantic_enabled': False}) as worker:
                current = worker.call('check', seconds=45)
            result['current_case_status'] = {'matches_recorded_fingerprint': current['fingerprint'] == manifest.get('evidence_fingerprint')}
        except (OSError, ValueError) as exc:
            result['current_case_status'] = {'unavailable': str(exc)[:300]}
        if args.explain:
            result['events'] = events
        return result
    from forensic_assistant.semantic.index import default_root
    config = {
        'case_path': args.db,
        'semantic_enabled': not args.no_semantic,
        'index_root': args.semantic_index or str(default_root(args.db)),
        'model_path': args.embedding_model or str(Path(args.db).parent / 'semantic-models' / 'bge'),
        'date_hint': getattr(args, 'date', None)
    }
    if args.command == 'ai-history':
        from .replay import replay
        return replay(config, root, args.investigation_id)
    if args.approve_tools and not sys.stdin.isatty():
        raise ValueError('--approve-tools requires an interactive terminal')
    if not Path(args.db).is_file():
        raise ValueError('Investigation requires an existing case database')
    from forensic_assistant.terminal_activity import ActivityIndicator
    from functools import partial
    from forensic_assistant.ai.backend import status_callback, waiting_label, restart_confirmation
    read = (getattr(args, '_confirm', input) if sys.stdin.isatty() and not getattr(args, 'json', False) else None)
    with ActivityIndicator('Preparing investigation...', args=args) as indicator, status_callback(indicator.update), restart_confirmation(read, indicator):
        result = run(
            config,
            args.question,
            root,
            budget=Budget(steps=args.max_steps, calls=args.max_tool_calls, seconds=args.max_seconds),
            client=LocalClient(args.endpoint),
            dry_run=args.dry_run,
            approval=partial(approve, args=args) if args.approve_tools else None,
            status=lambda phase: indicator.start(waiting_label()) if phase == "model" else indicator.phase(phase)
        )
    if args.explain:
        _, events = load(root, result['investigation_id'])
        result['events'] = events
    return result

def render(result):
    # JSON quoting prevents terminal-control injection from evidence/model text.
    return json.dumps(result, ensure_ascii=True, indent=2)


def rejection_notice(result):
    """Use controller counters only; never echo a model rejection explanation."""
    state = result.get('state') or {}
    count = state.get('final_grounding_rejections', 0)
    if type(count) is not int or not 1 <= count <= 16 or result.get('termination') == 'ANSWER_SUPPORTED':
        return ''
    completed = sum(entry.get('operation') != 'initial' for entry in state.get('investigation_path', [])
                    if isinstance(entry, dict))
    reason = ('they referenced evidence fields that had not been exposed to the model'
              if state.get('final_grounding_reasons') == ['unexposed_field'] else
              'the proposed findings did not satisfy the disclosed-evidence grounding contract')
    noun = 'conclusion' if count == 1 else 'conclusions'
    termination = {'BUDGET_EXHAUSTED': 'Investigation budget exhausted',
                   'TOO_MANY_REJECTIONS': 'Rejection limit reached',
                   'MAX_SECONDS': 'Time limit reached',
                   'USER_REJECTED': 'Analyst declined an operation'}.get(result.get('termination'), 'Investigation ended')
    return (f'Investigation stopped before a supported conclusion could be produced.\n'
            f'Locard rejected {count} unsupported AI {noun} because {reason}.\n'
            f'Successfully completed read-only operations: {completed}.\n'
            f'Termination: {termination}.\n'
            'The unsupported conclusions were not accepted as findings.')

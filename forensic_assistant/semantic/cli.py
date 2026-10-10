"""Shared CLI lifecycle; all setup writes require an explicit analyst action."""
from pathlib import Path
from forensic_assistant.command_catalog import COMMANDS
from . import runtime


def configure(commands, ask, *, interactive=False):
    ask.add_argument('--semantic-index')
    ask.add_argument('--embedding-model')
    semantic = commands.add_parser('semantic', help=COMMANDS['semantic'])
    sub = semantic.add_subparsers(dest='semantic_command', required=True)
    descriptions = {
        'search': 'Search current case evidence by semantic similarity',
        'status': 'Show semantic runtime, model, and current-case index status',
        'rebuild': 'Rebuild the semantic index for the current case',
        'setup': 'Install the reusable local embedding model (advanced setup)',
        'build': 'Build the current case semantic index manually (advanced)',
    }
    for name, description in descriptions.items():
        p = sub.add_parser(name, help=description, description=description)
        output = p.add_mutually_exclusive_group()
        output.add_argument('--json', dest='json', action='store_true', help='Full structured metadata, without terminal styling')
        output.add_argument('--text', dest='json', action='store_false', help='Concise human-readable output')
        p.set_defaults(json=not interactive)
        p.add_argument('--model-path', help='Advanced local model-directory override; does not change other commands')
        if name == 'setup':
            p.add_argument('destination', nargs='?', help='Optional legacy model directory; default is the reusable user-local model')
            p.add_argument('--model', choices=['bge', 'minilm'], default='bge')
            p.add_argument('--download', action='store_true', help='Approve Internet download of pinned model files; no evidence is uploaded')
            continue
        p.add_argument('--index', help='Advanced case-specific derived index directory override')
        if name in ('build', 'rebuild'):
            p.add_argument('--max-vectors', type=int, default=100000,
                           help='Safety limit: abort without publishing if the build exceeds N vectors; not sampling', metavar='N')
        if name == 'search':
            p.add_argument('question')
            p.add_argument('--limit', type=int, default=None)
            p.add_argument('--show-weak', action='store_true', help='Show candidates below the human display cutoff; JSON always retains all results')
            for field in ('artifact', 'start', 'end', 'hostname', 'user', 'path'):
                p.add_argument('--' + field)


def can_prompt(args):
    return (callable(getattr(args, '_confirm', None)) and not args.json
            and not getattr(args, 'output_file', None) and not getattr(args, 'append_file', None))


def approve(args, message, prompt='Continue? [Y/n]: '):
    from forensic_assistant.activity import Cancelled
    from forensic_assistant.retrieval.presentation import safe_text
    if not can_prompt(args):
        raise ValueError(message)
    try:
        print(safe_text(message))
        answer = args._confirm(prompt).strip().casefold()
    except (EOFError, KeyboardInterrupt):
        raise Cancelled('Semantic operation cancelled.') from None
    if answer not in ('', 'y', 'yes'):
        raise Cancelled('Semantic operation cancelled.')


def setup(args):
    from .model import setup as download, inspect_model, MODELS
    if args.destination and args.model_path:
        raise ValueError('Use either destination or --model-path, not both')
    destination = runtime.model_path(args.model_path or args.destination, args.model)
    if destination.exists():
        manifest = inspect_model(destination)
        if manifest['model_id'] != MODELS[args.model][0]:
            raise ValueError('Configured model differs from --model; select another --model-path')
    else:
        notice = (f"Download the pinned {MODELS[args.model][0]} embedding model from the Internet to {destination}. "
                  'No case evidence is uploaded. For scripts, explicitly approve with semantic setup --download.')
        if not args.download:
            approve(args, notice)
        manifest = download(destination, args.model)
        manifest = inspect_model(destination)
    if getattr(args, '_remember', True):
        runtime.remember(destination)
    return {**manifest, 'state': 'installed', 'location': str(destination), 'verification': 'passed'}


def status(db, args):
    from . import index
    from .model import inspect_model
    result = {'runtime': runtime.dependencies(), 'model_state': 'not_checked', 'index_state': 'not_checked'}
    if result['runtime']['state'] != 'ready':
        return {**result, 'state': 'dependencies_missing', 'next_step': result['runtime']['install_command']}
    path = runtime.model_path(args.model_path)
    result['model_location'] = str(path)
    if not path.exists():
        return {**result, 'state': 'model_missing', 'model_state': 'missing', 'next_step': 'semantic setup'}
    try:
        result['model'] = inspect_model(path)
    except (ValueError, OSError) as exc:
        return {**result, 'state': 'model_malformed', 'model_state': 'malformed', 'reason': str(exc),
                'next_step': 'Preserve the incomplete model; use semantic setup --model-path <new-directory>'}
    result['model_state'] = 'ready'
    root = args.index or index.default_root(args.db)
    result['current_evidence_records'] = db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]
    if not (Path(root) / 'CURRENT').exists():
        return {**result, 'state': 'index_missing', 'index_state': 'not_built', 'next_step': 'semantic build'}
    details = index.status(db, root)
    state = details['state']
    if state == 'current':
        identity = details['model']
        same_model = all(identity.get(k) == result['model'][k] for k in ('model_id', 'revision', 'files'))
        packages = identity.get('packages', {})
        same_packages = all(result['runtime']['packages'].get(k) == v for k, v in packages.items())
        if not same_model or not same_packages:
            state = 'stale'
    result['index'] = details
    return {**details, **result, 'model': details.get('model', result['model']),
            'index_state': state, 'state': {'current': 'ready', 'stale': 'index_stale'}.get(state, 'index_malformed'),
            'next_step': 'semantic search "question"' if state == 'current' else 'semantic rebuild'}


def dispatch(db, args):
    from . import index
    if args.semantic_command == 'search' and (not 1 <= args.limit <= 100 or not args.question.strip()
                                               or len(args.question.encode('utf-8')) > 1000):
        raise ValueError('Invalid semantic search bounds')
    if args.semantic_command == 'status':
        return status(db, args)
    root, model, built = prepare(db, args)
    if args.semantic_command != 'search':
        return built
    filters = {name: getattr(args, name) for name in ('artifact', 'start', 'end', 'hostname', 'path') if getattr(args, name)}
    if args.hostname:
        filters['strict_host'] = True
    if args.user:
        filters['username'] = args.user
    return index.search(db, root, model, args.question, limit=args.limit, **filters)


def prepare(db, args):
    """Resolve/approve the shared runtime before any retrieval snapshot is held."""
    from . import index
    from .model import LocalModel
    from .presentation import Progress
    result = status(db, args)
    if result['state'] == 'dependencies_missing':
        raise ValueError('Semantic runtime dependencies are unavailable in this Locard environment.\nPython: '
                         + result['runtime']['python'] + '\nInstall with:\n' + result['next_step']
                         + '\nRestart Locard after installation.')
    if result['state'] == 'model_missing' and can_prompt(args):
        from argparse import Namespace
        setup(Namespace(destination=None, model_path=args.model_path, model='bge', download=False,
                        json=False, _confirm=args._confirm, _remember=args.model_path is None))
        result = status(db, args)
    if result['model_state'] != 'ready':
        raise ValueError(result['state'] + ': ' + result.get('reason', '') + '\nNext step: ' + result['next_step'])
    root = args.index or index.default_root(args.db)
    operation = args.semantic_command
    if operation == 'search' and result['state'] != 'ready':
        action = 'build' if result['state'] == 'index_missing' else 'rebuild'
        state = result['state'].removeprefix('index_')
        approve(args, f'Semantic index is {state} for this case. Run semantic {action} before searching.',
                prompt=action.capitalize() + ' now? [Y/n]: ')
        operation = action
    model = LocalModel(runtime.model_path(args.model_path))
    built = None
    if operation in ('build', 'rebuild'):
        built = index.build(db, root, model, rebuild=operation == 'rebuild',
                            max_vectors=getattr(args, 'max_vectors', 100000), progress=Progress(args))
    return root, model, built

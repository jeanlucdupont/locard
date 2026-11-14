"""Presentation/confirmation adapter for local case-management services."""
from . import case_management as cases
from .interactive.console import safe


def run(args, *, read=None):
    operation = args.workflow.removeprefix('case-')
    if operation == 'list':
        return {'cases': cases.discover()}
    if operation == 'open':
        if not args.path:
            raise ValueError('Use case open in the interactive shell to select from a menu')
        return {'case': str(cases.resolve(args.path)), 'status': 'validated; use --db for subsequent scripted commands'}
    if operation == 'root' and not args.action:
        if args.path:
            raise ValueError('Use case root set PATH')
        return {'root': str(cases.root()), 'effect': 'Future creation/discovery only; existing cases are not moved'}
    if operation == 'root' and not args.path:
        raise ValueError('case root set requires an absolute directory')
    if operation == 'clone':
        source=cases.resolve(args.source, check_identity=False)
        destination=cases.destination(args.name)
        info=source.stat()
        source_identity=(info.st_dev,info.st_ino)
    description = {
        'root': 'Change future case creation/discovery root; no cases are moved.',
        'register': 'Register the original case location; no identity rebinding or data copying.',
        'unregister': 'Remove only the external reference; case data remains untouched.',
        'clone': 'Copy retained normalized evidence/provenance into a new case. External evidence is not copied; no investigative sidecars are inherited.',
    }[operation]
    if not getattr(args, 'yes', False):
        if not callable(read):
            raise ValueError(description + ' Explicit confirmation required: use --yes in scripts.')
        print(description)
        if operation=='clone':
            print('Resolved source: '+safe(str(source)))
            print('New database: '+safe(str(destination)))
        for key in ('source', 'name', 'path'):
            if getattr(args, key, None):print(key.capitalize()+': '+safe(getattr(args,key)))
        from .briefing_workflow import read_answer
        if read_answer(read, 'Confirm this case operation? [y/N]: ').casefold() not in ('y', 'yes'):
            return {'status': 'cancelled'}
    if operation == 'root':return {'root': str(cases.set_root(args.path))}
    if operation == 'register':return {'registered': args.name, 'path': str(cases.register(args.name, args.path))}
    if operation == 'unregister':
        cases.unregister(args.name)
        return {'unregistered': args.name, 'case_data': 'unchanged'}
    return cases.clone(str(source), args.name, expected_source=source_identity, expected_destination=destination)

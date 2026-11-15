"""Command-local source selection; no retained database or implicit source state."""
from contextlib import closing
from forensic_assistant.interactive.case import open_existing
from forensic_assistant.interactive.console import safe
from forensic_assistant.database import sources


def prepare(shell, args):
    if args.command == 'source' and args.source_command == 'show' and not args.source_id:
        if args.json:
            raise ValueError('Use an exact source ID with --json.')
        from forensic_assistant.terminal_activity import operation
        from forensic_assistant.source_cli import render_list
        from forensic_assistant.terminal import Palette, enabled
        offset = 0
        while True:
            with operation('Retrieving evidence sources...', args), closing(open_existing(shell.active)) as db:
                page = sources.listing(db, limit=100, offset=offset)
            print(render_list(page, Palette(enabled(args))))
            if not page['sources']: return False
            choice = shell.reader.read('Source number, N for next page, or Enter to cancel: ').strip()
            if not choice: return False
            if choice.lower() == 'n' and page['truncated']:
                offset += len(page['sources'])
                continue
            if not choice.isdecimal() or not offset < int(choice) <= offset + len(page['sources']):
                raise ValueError('Select a number from the displayed source page.')
            args.source_id = page['sources'][int(choice)-offset-1]['source_id']
            with closing(open_existing(shell.active)) as db:
                sources.current(db, args.source_id)
            return True
    if args.command.startswith('ingest-'):
        if getattr(args, 'source', None):
            return True
        with closing(open_existing(shell.active)) as db:
            page = sources.listing(db)
        print('Select evidence source (Enter cancels):')
        for n, s in enumerate(page['sources'], 1):
            print(str(n) + '. ' + safe(s['display_name']) + ' [' + s['source_id'] + ']')
        if page['truncated']:
            print('First 100 sources shown; enter a full source ID for another source.')
        print('N. New source')
        choice = shell.reader.read('Source number, ID, or N: ').strip()
        if not choice:
            return False
        if choice.lower() == 'n':
            args.source_name = shell.reader.read('Source name (Enter = generated label): ').strip() or None
            for field, prompt in [('hostname', 'Hostname'), ('user', 'Source user'), ('volume_root', 'Original drive')]:
                if getattr(args, field, None) is None:
                    if field == 'volume_root':
                        from .metadata import read_volume_root
                        from forensic_assistant.terminal import Palette, enabled
                        palette = Palette(enabled(shell))
                        read = lambda text: shell.reader.read(text)
                        value = read_volume_root(read, prompt + ' (Enter = unknown): ', palette)
                    else:
                        value = shell.reader.read(prompt + ' (Enter = unknown): ').strip() or None
                    setattr(args, field, value)
            args.source_explicit = True
        else:
            args.source = page['sources'][int(choice) - 1]['source_id'] if choice.isdecimal() and 1 <= int(choice) <= len(page['sources']) else choice
            with closing(open_existing(shell.active)) as db:
                sources.current(db, args.source)
        return True
    if args.command == 'source' and args.source_command in ('update', 'assign'):
        from forensic_assistant.source_cli import dispatch
        if args.yes:
            return True  # Dispatch still validates and applies the action transactionally.
        from forensic_assistant.terminal_activity import operation
        with operation('Loading source preview...', args), closing(open_existing(shell.active)) as db:
            preview = dispatch(db, args)
            args.confirmation_fingerprint = preview['confirmation_fingerprint']
        if args.source_command == 'assign':
            from forensic_assistant.source_cli import render_assignment
            from forensic_assistant.terminal import Palette, enabled, render_json
            print(render_json(preview, Palette()) if args.json else render_assignment(preview, Palette(enabled(args))))
        else:
            from forensic_assistant.source_cli import render_update_preview
            from forensic_assistant.terminal import Palette, enabled
            print(render_update_preview(preview['preview'], Palette(enabled(args))))
        if shell.reader.read('Apply this analyst-supplied change? [y/N]: ').strip().lower() not in ('y', 'yes'):
            return False
        args.yes = True
    return True

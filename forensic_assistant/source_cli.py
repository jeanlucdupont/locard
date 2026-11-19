"""Shared CLI surface for analyst provenance actions."""
from forensic_assistant.command_catalog import COMMANDS
from forensic_assistant.database import sources


def configure(commands):
    parser = commands.add_parser('source', help=COMMANDS['source'])
    sub = parser.add_subparsers(dest='source_command', required=True)
    for name in ('list', 'show', 'create', 'update', 'assign'):
        p = sub.add_parser(name, help={'list':'List evidence sources','show':'Show a source and its provenance','create':'Create analyst-supplied source metadata','update':'Update source metadata after confirmation','assign':'Assign retained files to a source after confirmation'}[name])
        p.add_argument('--json', action='store_true', help='Output as JSON')
        if name in ('show', 'update', 'assign'):
            p.add_argument('source_id', nargs='?' if name == 'show' else None, help='Exact source ID; omit show ID for interactive selection')
        if name in ('list', 'show'):
            p.add_argument('--limit', type=int, default=100, help='Maximum number of results')
            p.add_argument('--offset', type=int, default=0, help='Skip this many results')
        if name == 'show':
            p.add_argument(
                '--details',
                action='store_true',
                help='Show source identifiers and paginated provenance'
            )
        if name == 'list':
            p.description = 'List retained sources; use show for selection or --ids for canonical identifiers.'
        if name == 'list':
            p.add_argument(
                '--ids',
                action='store_true',
                help='Show complete, copyable source IDs'
            )
        if name in ('create', 'update'):
            for flag in ('name', 'hostname', 'user', 'volume-root'):
                p.add_argument('--' + flag, help={'name':'Source display name','hostname':'Analyst-supplied source hostname','user':'Analyst-supplied source username','volume-root':'Analyst-supplied original volume root'}[flag])
            p.add_argument('--time-zone', nargs='?', const='', help='Analyst-supplied IANA source time zone; omit value to clear to unknown')
        if name in ('update', 'assign'):
            p.add_argument(
                '--yes',
                action='store_true',
                help='Apply without interactive confirmation; otherwise confirm in the shell or preview in scripts'
            )
        if name == 'assign':
            p.add_argument(
                '--file-hash',
                action='append',
                help='Explicit existing file SHA-256; repeat or combine with --path (deduplicated union)'
            )
            p.add_argument(
                '--path',
                action='append',
                help='Recorded absolute Windows file/directory path; repeatable, no filesystem scan or wildcards. Requires --path or --file-hash.'
            )
            p.add_argument(
                '--confirmation-fingerprint',
                help='Require the case fingerprint returned by a reviewed preview before applying'
            )
            p.add_argument(
                '--reason',
                required=True,
                help='Reason for retrospective assignment (does not reconstruct ingestion)'
            )
    for name, p in commands.choices.items():
        if name.startswith('ingest-'):
            p.add_argument(
                '--source',
                help='Reuse this source ID; omitted in scripts creates a NEW automatic source for this invocation, never inferred or reused'
            )
    commands.choices['search'].add_argument('--source', help='Filter Locard source membership, not hostname identity')


def changes(args):
    result = {
        key: getattr(args, flag, None) for key,
        flag in
        [('display_name', 'name'), ('hostname', 'hostname'), ('username', 'user'), ('volume_root', 'volume_root'), ('time_zone', 'time_zone')]
        if getattr(args, flag, None) is not None
    }
    if 'time_zone' in result:
        from forensic_assistant.database.source_timezone import validate
        result['time_zone'] = validate(result['time_zone'])
    return result


def display_name(data):
    # Match only the application's generated label, not arbitrary analyst names.
    generated = 'Source ' + data['source_id'].removeprefix('src-')[:12]
    return 'Unnamed source' if data['display_name'] == generated else data['display_name']


def identity_note(source, *, detail=False):
    """One human-facing identity limitation for this source's structured state."""
    if source.get('host_conflict'):
        return ('Source identity is unconfirmed. Conflicting hostnames were observed; '
                'evaluate host attribution per evidence record.' if detail else
                'Source computer identity is unconfirmed; conflicting hostnames were observed.')
    if not source.get('hostname'):
        return 'Source computer identity has not been confirmed.'
    return None


def compact_limitations(source):
    # Replace only the two application-owned identity notes, and only when the
    # corresponding structured condition exists on this same source. Other
    # provenance limitations (and the detailed/JSON originals) remain intact.
    replaced = set()
    if not source.get('hostname'):
        replaced.add('Analyst hostname unknown; source membership alone does not establish a host')
    if source.get('host_conflict'):
        replaced.add('Source-level conflicting hostname assertions; record hosts are resolved individually')
    note = identity_note(source, detail=True)
    return ([note] if note else []) + [w for w in source.get('limitations', []) if w not in replaced]


def render_list(data, palette=None, *, ids=False, width=None):
    from forensic_assistant.terminal import Palette
    from forensic_assistant.retrieval.layout import table, pagination
    from forensic_assistant.retrieval.presentation import safe_text
    palette = palette or Palette()
    rows = [[n, display_name(r), f"{r['files']:,}", f"{r['evidence_count']:,}"]
            for n,r in enumerate(data['sources'], data['offset']+1)]
    lines = [palette('heading', 'Evidence sources'), '']
    lines += table(['#','NAME','FILES','RECORDS'],rows,palette,minimums=[3,12,7,10],
                   maximums=[6,55,15,18],roles=['value']*4,right=(2,3),width=width)
    for n,r in enumerate(data['sources'], data['offset']+1):
        lines.append(palette('label', f'  Source {n} time zone: ') + palette('value' if r.get('time_zone') else 'unknown', safe_text(r.get('time_zone') or 'unknown')))
        if ids: lines.append(palette('value', f"  {n}: " + safe_text(r['source_id'])))
        if r.get('host_conflict'):
            lines.append(palette('forensic_note', f'  Source {n}: ' + identity_note(r)))
        if r.get('ambiguous_files'):
            lines.append(palette('forensic_note', f"  Source {n}: {r['ambiguous_files']:,} files have multiple source memberships."))
    footer = pagination(len(rows),data['total'],data['offset'])
    if footer: lines += ['',footer]
    return '\n'.join(lines)


def dispatch(db, args):
    action = args.source_command
    if action == 'list':
        return sources.listing(db, args.limit, args.offset)
    if action == 'show':
        if not args.source_id:
            raise ValueError('Supply an exact source ID in scripts or use interactive evidence source show.')
        if not args.json and not args.details:
            return sources.summary(db, args.source_id)
        return sources.detail(db, args.source_id, args.limit, args.offset)
    from forensic_assistant import activity
    if action == 'create':
        with activity.mutation('SOURCE_CREATE', metadata=changes(args)) as audit_result, db:
            sid = sources.create(
                db,
                name=args.name,
                hostname=args.hostname,
                username=args.user,
                volume_root=args.volume_root,
                time_zone=getattr(args, 'time_zone', None)
            )
            audit_result.update(source_id=sid, assertion=sources.current(db, sid))
        return sources.summary(db, sid)
    # Hold a write reservation so preview, scope counts and mutation use one state.
    db.execute('BEGIN IMMEDIATE')
    try:
        from forensic_assistant.semantic.documents import fingerprint
        expected = getattr(args, 'confirmation_fingerprint', None)
        if expected:
            if fingerprint(db) != expected:
                raise ValueError('Case changed after confirmation preview; review and confirm again')
        scope = sources.summary(db, args.source_id)
        if action == 'update':
            values = changes(args)
            if not values:
                raise ValueError('Specify metadata to update')
            preview = dict(source=scope, proposed=values, basis='analyst-supplied; previous revision retained')
            if not args.yes:
                return dict(
                    preview=preview,
                    applied=False,
                    confirmation='Repeat with --yes to apply',
                    confirmation_fingerprint=fingerprint(db)
                )
            audit_fields = dict(source_id=args.source_id, changes={key: dict(previous_value=scope.get(key), new_value=value) for key, value in values.items()})
            with activity.mutation('SOURCE_UPDATE', **audit_fields) as audit_result:
                result = sources.update(db, args.source_id, **values)
                audit_result['changes'] = {key: dict(previous_value=scope.get(key), new_value=result[key]) for key in values}
                db.commit()
        else:
            from forensic_assistant.database import source_selection
            selection = source_selection.select(db, args.file_hash, getattr(args, 'path', None))
            preview = source_selection.preview(db, args.source_id, selection, args.reason)
            if not args.yes:
                return dict(
                    preview=preview,
                    applied=False,
                    confirmation='Repeat with --yes to apply',
                    confirmation_fingerprint=fingerprint(db)
                )
            with activity.mutation('SOURCE_ASSIGN', source_id=args.source_id,
                                   file_hashes=selection['file_hashes'], reason=args.reason) as audit_result:
                result = dict(assignment_id=sources.assign(
                    db, args.source_id, selection['file_hashes'], reason=args.reason,
                    selection_basis=source_selection.assignment_basis(selection)))
                db.commit()
                audit_result.update(result)
        db.commit()
        return dict(applied=True, result=result, scope=preview)
    finally:
        db.rollback()


def render_update_preview(preview, palette):
    """Human fields rather than Python repr of the proposed metadata dictionary."""
    from forensic_assistant.retrieval.presentation import safe, safe_path
    source = preview['source']
    lines = ['Source: ' + safe(source['source_id'])]
    for key, value in preview['proposed'].items():
        render = safe_path if key == 'volume_root' else safe
        lines.append(palette('label', key.replace('_', ' ').capitalize() + ': ')
                     + render(source.get(key)) + ' -> ' + render(value))
    lines.append(safe(preview['basis']))
    return '\n'.join(lines)


def render_update(data, palette):
    """Concise human projection; the complete structured result is unchanged."""
    from forensic_assistant.retrieval.presentation import safe_text
    if not data['applied']:
        return render_update_preview(data['preview'], palette) + '\nPreview only. Repeat with --yes to apply.'
    old, new = data['scope']['source'], data['result']
    labels = {'display_name': 'Name', 'hostname': 'Hostname', 'username': 'User', 'volume_root': 'Volume root', 'time_zone': 'Time zone'}
    lines = [palette('success', 'Source updated.')]
    for key in data['scope']['proposed']:
        lines.append(palette('label', labels[key] + ': ') + safe_text(old.get(key) or 'unknown')
                     + ' -> ' + safe_text(new.get(key) or 'unknown'))
    return '\n'.join(lines)


def render_assignment(data, palette=None):
    from forensic_assistant.terminal import Palette
    from forensic_assistant.retrieval.presentation import safe, safe_path
    palette = palette or Palette()
    p = data.get('preview', data.get('scope'))
    s = p['source']
    lines = [
        palette('heading', 'RETROSPECTIVE SOURCE ASSIGNMENT'),
        'Source: ' + safe(s['display_name']) + ' [' + safe(s['source_id']) + ']',
        'Analyst hostname: ' + safe(s['hostname'] or 'unknown')
    ]
    for path in p['paths']:
        lines.append('Recorded path: ' + safe_path(path))
    if p['explicit_hashes']:
        lines.append('Explicit hash selectors: ' + str(len(p['explicit_hashes'])))
    lines += [
        f"Distinct file hashes: {p['files']}",
        f"Evidence records: {p['evidence_records']}",
        'Artifact types: ' + safe(p['artifact_types']),
        'Existing provenance (file hashes):'
    ]
    for key, value in p['existing_provenance'].items():
        lines.append('  ' + key.replace('_', ' ') + ': ' + str(value))
    lines += ['Reason: ' + safe(p['reason']), 'Basis: ' + p['basis']]
    lines += [palette('forensic_note', text) for text in p['limitations']]
    if data['applied']:
        lines.append('Applied assignment: ' + data['result']['assignment_id'])
    else:
        lines += [
            'Preview only. Repeat with --yes to apply; add --confirmation-fingerprint below to require this case state.',
            data['confirmation_fingerprint']
        ]
    lines.append('Use --json for the full selected hash and matched-location lists; evidence source show exposes bounded assignment history.')
    return '\n'.join(lines)


def render_show(data, palette=None, *, details=False):
    from forensic_assistant.terminal import Palette
    from forensic_assistant.retrieval.presentation import safe, safe_path
    palette = palette or Palette()
    if not details:
        from .terminal import field, aligned_lines
        lines = [field('Source', display_name(data), palette), field('Retained files', f"{data['files']:,}", palette),
                 field('Evidence records', f"{data['evidence_count']:,}", palette)]
        lines += [field(kind.upper(), f'{count:,}', palette) for kind,count in sorted(data['artifacts'].items())]
        lines.append(field('Analyst-asserted time zone', data.get('time_zone') or 'unknown', palette, role='value' if data.get('time_zone') else 'unknown'))
        if data.get('hostname'): lines.append(field('Analyst-asserted hostname', data['hostname'], palette))
        if data.get('artifact_hostnames'): lines.append(field('Observed hostnames', ', '.join(data['artifact_hostnames']), palette))
        lines += [palette('forensic_note', safe(w)) for w in compact_limitations(data)]
        if data.get('artifact_hostnames_truncated'): lines.append(palette('forensic_note', 'Observed hostname list is bounded to 100.'))
        return aligned_lines(lines)
    lines = []
    def field(name, value, *, path=False):
        from .terminal import field as labeled_field
        lines.append(labeled_field(name, (safe_path if path else safe)(value), palette))
    for name, key in [
        ('Source', 'display_name'),
        ('Source ID', 'source_id'),
        ('Creation basis', 'creation_basis'),
        ('Created UTC', 'created_utc'),
        ('Analyst hostname', 'hostname'),
        ('Analyst user', 'username'),
        ('Volume root', 'volume_root'),
        ('Analyst-asserted time zone', 'time_zone'),
        ('Current assertion', 'assertion_id'),
        ('Assertion basis', 'basis'),
        ('Batches', 'batches'),
        ('Distinct source files', 'files'),
        ('Evidence records', 'evidence_count'),
        ('Files with multiple source memberships', 'ambiguous_files')
    ]:
        field(name, (data.get(key) or 'unknown') if key == 'time_zone' else data.get(key), path=key == 'volume_root')
    # Source-wide assertions cannot establish each file's effective host: legacy
    # file assertions and multiple memberships are resolved at evidence retrieval.
    field('Artifact hostnames', ', '.join(data.get('artifact_hostnames', [])) or 'unknown')
    lines.append('Effective hostname is resolved per evidence record; inspect show for file-specific context.')
    for kind, count in sorted(data.get('artifacts', {}).items()):
        field(kind.upper() + ' records', count)
    for label, key in [
        ('Assertion revisions', 'assertion_history'),
        ('Retrospective assignments', 'retrospective_assignments'),
        ('Retrospective assignment-to-file links', 'retrospective_files'),
        ('Ingestion file occurrences', 'file_occurrences')
    ]:
        field(label, data[key]['total'])
    for warning in data.get('limitations', []):
        lines.append(palette('forensic_note', safe(warning)))
    if data.get('artifact_hostnames_truncated'):
        lines.append(palette('forensic_note', 'Artifact hostname list is bounded to 100.'))
    from .terminal import aligned_lines
    return aligned_lines(lines)

"""Provider-free recorded reporting application service and guarded bundles."""
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile

from forensic_assistant import __version__
from forensic_assistant.investigation_ai.storage import local_path, DirectoryGuard
from . import recorded_model as model, recorded_view
from .recorded_source import Source
from .model import canonical, digest, loads

FILES = ('projection.json', 'report.html', 'manifest.json')


def build(root, run_id, *, workspace=None, report_type='technical', generation=None):
    """Return a frozen projection; subsequent source authority requires revalidate."""
    return _build(Source(root, run_id, workspace), report_type, generation)


def _build(source, report_type, generation):
    if report_type not in model.TYPES:
        raise ValueError('RECORDED_REPORT_TYPE')
    restored = source.restore()
    state = source.state()
    supports, units = model.support_map(restored, source.binding['view'])
    renderer = generation['renderer_version'] if generation is not None else model.RENDERER
    if renderer not in model.POLICIES:
        raise ValueError('RECORDED_REPORT_RENDERER')
    content = dict(report_type=report_type, source=deepcopy(source.binding['source']),
                   view=deepcopy(source.binding['view']), supports=supports, units=units,
                   workspace=deepcopy(source.snapshot), **state,
                   validation=dict(source_binding='valid_recorded_binding', support_reconstruction='validated',
                                   workspace='validated' if source.snapshot is not None else 'not_attached', semantic_truth='not_certified'),
                   policy=deepcopy(model.POLICIES[renderer]), caution=model.CAUTION)
    now = datetime.now(timezone.utc).isoformat()
    envelope = deepcopy(generation) if generation is not None else dict(generated_utc=now, validation_utc=now,
                      application_version=__version__, renderer_version=model.RENDERER)
    model.bounded(content)
    projection = dict(contract=model.CONTRACT, content=content, content_digest=digest(content), generation=envelope)
    model.validate(projection)
    source.check()
    return projection


validate_projection = model.validate
render_view = recorded_view.view
render_html = recorded_view.render


def _destination(value, protected):
    destination = local_path(value)
    if destination.exists():
        raise ValueError('RECORDED_REPORT_DESTINATION_EXISTS')
    if not destination.parent.is_dir():
        raise ValueError('RECORDED_REPORT_PARENT_REQUIRED')
    for parent in destination.parents:
        if any((parent/name).exists() for name in ('case.db', 'findings.sqlite3', 'manifest.json')):
            raise ValueError('RECORDED_REPORT_PROTECTED_DESTINATION')
    for part in destination.parts:
        name = part.casefold()
        if name.endswith(('.findings', '.investigations', '.briefing')) or name.startswith('.locard-'):
            raise ValueError('RECORDED_REPORT_PROTECTED_DESTINATION')
        if name.split('.')[0] in {'con', 'prn', 'aux', 'nul', *('com'+str(i) for i in range(1,10)), *('lpt'+str(i) for i in range(1,10))}:
            raise ValueError('RECORDED_REPORT_RESERVED_DESTINATION')
    for value in protected:
        path = Path(value).absolute()
        if destination == path or path in destination.parents:
            raise ValueError('RECORDED_REPORT_PROTECTED_DESTINATION')
    return destination


def _write(path, data):
    with path.open('xb') as stream:
        if stream.write(data) != len(data):
            raise OSError('RECORDED_REPORT_SHORT_WRITE')
        stream.flush()
        os.fsync(stream.fileno())
    if _read(path, len(data)) != data:
        raise OSError('RECORDED_REPORT_WRITE_MISMATCH')


def _rename_new(source, destination):
    if os.name == 'nt':
        # Windows rename fails if the destination exists; never os.replace.
        os.rename(source, destination)
    else:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        if not hasattr(libc, 'renameat2'):
            raise OSError('RECORDED_REPORT_ATOMIC_PUBLICATION_UNSUPPORTED')
        call = libc.renameat2
        call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        call.restype = ctypes.c_int
        if call(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
            raise OSError(ctypes.get_errno(), 'RECORDED_REPORT_PUBLICATION_FAILED')


def _payloads(projection):
    model.validate(projection)
    data = canonical(projection)
    html = render_html(projection)
    manifest = dict(contract='recorded-report-bundle-v1', content_digest=projection['content_digest'],
                    generation_digest=digest(projection['generation']),
                    files={'projection.json': hashlib.sha256(data).hexdigest(), 'report.html': hashlib.sha256(html).hexdigest()},
                    meaning='Internal consistency only; not authentication, source revalidation or proof of conclusions.')
    payloads = {'projection.json': data, 'report.html': html, 'manifest.json': canonical(manifest)}
    if len(data) > model.MAX_PROJECTION or len(html) > model.MAX_HTML or sum(map(len, payloads.values())) > model.MAX_BUNDLE:
        raise ValueError('RECORDED_REPORT_BUNDLE_LIMIT')
    return payloads


def publish(root, run_id, output, *, workspace=None, report_type='technical', generation=None, protected_roots=()):
    """Generate and publish. Final source/revision check occurs before rename.

    Additional evidence containers can be explicitly protected without opening a
    case. Unknown evidence locations cannot be inferred from a recorded history.
    """
    source = Source(root, run_id, workspace)
    protected = source.protected_paths() + [local_path(p) for p in protected_roots]
    destination = _destination(output, protected)
    staging = None
    try:
        with ExitStack() as stack:
            stack.enter_context(DirectoryGuard(destination.parent))
            stack.enter_context(DirectoryGuard(source.root))
            if source.workspace:
                stack.enter_context(DirectoryGuard(source.workspace.directory))
            projection = _build(source, report_type, generation)
            payloads = _payloads(projection)
            staging = Path(tempfile.mkdtemp(prefix='.locard-recorded-report-', dir=destination.parent))
            with DirectoryGuard(staging):
                for name, raw in payloads.items():
                    _write(staging/name, raw)
                _inspect(staging)
            source.check()
            _destination(destination, protected)
            local_path(staging)
            _rename_new(staging, destination)
            staging = None
        return dict(status='PUBLISHED', output=str(destination), report_type=report_type,
                    content_digest=projection['content_digest'], source_validation='recorded_history_only',
                    forensic_truth='not_certified')
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, sqlite3.Error) as exc:
        if destination.exists():
            raise OSError('RECORDED_REPORT_PUBLICATION_UNCERTAIN: inspect the selected destination; do not overwrite it') from exc
        raise
    finally:
        if staging is not None and staging.exists():
            # Only our resolved, directly-owned temporary directory is removed.
            try:
                checked = local_path(staging)
                if checked.parent != destination.parent or not checked.name.startswith('.locard-recorded-report-'):
                    raise ValueError('Unsafe staging cleanup')
                shutil.rmtree(checked)
            except (OSError, ValueError):
                raise OSError('RECORDED_REPORT_CLEANUP_UNCONFIRMED') from None


def _read(path, maximum):
    local_path(path)
    stat = path.stat()
    if not path.is_file() or stat.st_nlink != 1 or stat.st_size > maximum:
        raise ValueError('RECORDED_REPORT_FILE_LIMIT_OR_ALIAS')
    with path.open('rb') as stream:
        raw = stream.read(maximum+1)
    if len(raw) > maximum:
        raise ValueError('RECORDED_REPORT_FILE_LIMIT')
    return raw


def _inspect(directory):
    directory = local_path(directory)
    with DirectoryGuard(directory):
        if {p.name for p in directory.iterdir()} != set(FILES):
            raise ValueError('RECORDED_REPORT_BUNDLE_FILES')
        payloads = {name: _read(directory/name, 65536 if name=='manifest.json' else model.MAX_HTML if name=='report.html' else model.MAX_PROJECTION) for name in FILES}
    if sum(map(len, payloads.values())) > model.MAX_BUNDLE:
        raise ValueError('RECORDED_REPORT_BUNDLE_LIMIT')
    manifest = loads(payloads['manifest.json'])
    model.keys(manifest, 'contract content_digest generation_digest files meaning')
    if manifest['contract'] != 'recorded-report-bundle-v1':
        raise ValueError('RECORDED_REPORT_BUNDLE_VERSION')
    expected = {name: hashlib.sha256(payloads[name]).hexdigest() for name in ('projection.json', 'report.html')}
    if manifest['files'] != expected:
        raise ValueError('RECORDED_REPORT_FILE_DIGEST')
    projection = model.validate(loads(payloads['projection.json']))
    if manifest['content_digest'] != projection['content_digest'] or manifest['generation_digest'] != digest(projection['generation']):
        raise ValueError('RECORDED_REPORT_MANIFEST_DIGEST')
    if render_html(projection) != payloads['report.html']:
        raise ValueError('RECORDED_REPORT_RENDER_MISMATCH')
    return projection


def inspect(directory):
    projection = _inspect(directory)
    return dict(file_integrity='PASS', structure='PASS', source_binding='NOT_CHECKED',
                evidence_grounding='NOT_CHECKED', analyst_decisions='internal_chain_only',
                semantic_truth='NOT_CERTIFIED', content_digest=projection['content_digest'],
                report_type=projection['content']['report_type'],
                caution='Offline bundle consistency is not fresh forensic validation.')


def revalidate(directory, root, run_id, *, workspace=None):
    old = _inspect(directory)
    new = build(root, run_id, workspace=workspace, report_type=old['content']['report_type'], generation=old['generation'])
    if old != new:
        raise ValueError('RECORDED_REPORT_SOURCE_OR_REVISION_CHANGED')
    result = inspect(directory)
    result.update(source_binding='PASS', evidence_grounding='PASS',
                  analyst_decisions='PASS' if workspace is not None else 'not_attached')
    return result


def dispatch(args):
    """Small CLI adapter; errors must not disclose source payloads or paths."""
    if any(getattr(args, key, None) for key in ('output_file', 'append_file', 'force', 'page')):
        raise ValueError('RECORDED_REPORT_GENERIC_OUTPUT_OPTIONS_NOT_SUPPORTED')
    if args.report_command == 'recorded':
        return publish(args.transcript_root, args.run, args.output, workspace=args.workspace,
                       report_type=args.profile, protected_roots=args.protect_root)
    if args.transcript_root or args.run or args.workspace:
        if not args.transcript_root or not args.run:
            raise ValueError('RECORDED_REPORT_REVALIDATION_REQUIRES_ROOT_AND_RUN')
        return revalidate(args.directory, args.transcript_root, args.run, workspace=args.workspace)
    return inspect(args.directory)


def cli(args):
    import json
    try:
        print(json.dumps(dispatch(args), ensure_ascii=True, indent=2))
        return 0
    except KeyboardInterrupt:
        print('Recorded report cancelled. Inspect the destination if publication was in progress.')
        return 130
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, sqlite3.Error) as exc:
        # Existing validators may contain untrusted source text in exceptions.
        code = str(exc).split(':', 1)[0]
        if not code.startswith('RECORDED_REPORT_') or len(code) > 100 or not all(ch.isupper() or ch=='_' for ch in code):
            code = 'RECORDED_REPORT_SOURCE_OR_STORAGE_VALIDATION_FAILED'
        print(json.dumps(dict(status='FAILED', error=code, source_authority='not_established')))
        return 2

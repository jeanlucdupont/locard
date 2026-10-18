"""Read-only SHA-256 inventory for explicitly selected protected files.

Validation metadata only. A newly created baseline cannot prove historical bytes.
Selection JSON is a list of root-relative paths; verification covers those files,
not newly added unlisted files. Keep manifests outside evidence and source control.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat


def resolve(root, relative):
    path = PurePosixPath(relative)
    if not isinstance(relative, str) or '\\' in relative or ':' in relative or path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('Unsafe relative path')
    target = root.joinpath(*path.parts)
    for part in (root, *root.parents, target, *target.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 1024:
            raise ValueError('Symlink/reparse paths are not supported')
    if not target.is_file():
        raise ValueError('Not a regular file')
    return target


def record(root, relative):
    target = resolve(root, relative)
    before = target.stat()
    digest = hashlib.sha256()
    with target.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    after = target.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError('File changed during hashing')
    return {'path': relative, 'size': after.st_size, 'sha256': digest.hexdigest()}


def create(root, paths):
    if len(paths) != len(set(paths)):
        raise ValueError('Duplicate selected paths')
    return {'format': 1, 'algorithm': 'SHA-256', 'scope': 'explicit selected files',
            'historical_claim': False,
            'files': [record(root, name) for name in sorted(paths)]}


def verify(root, manifest):
    if manifest.get('format') != 1 or manifest.get('algorithm') != 'SHA-256':
        raise ValueError('Unsupported manifest')
    rows = manifest['files']
    if [r['path'] for r in rows] != sorted(set(r['path'] for r in rows)):
        raise ValueError('Manifest paths must be unique and sorted')
    differences = []
    for expected in rows:
        try:
            actual = record(root, expected['path'])
            if actual != expected:
                differences.append(expected['path'])
        except (OSError, ValueError):
            differences.append(expected['path'])
    return differences


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('create', 'verify'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--paths', type=Path, help='JSON list of explicit relative paths (create only)')
    args = parser.parse_args()
    root = args.root.absolute()
    if args.action == 'create':
        if not args.paths:
            parser.error('--paths is required for create')
        manifest = create(root, json.loads(args.paths.read_text(encoding='utf-8-sig')))
        with args.manifest.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(manifest, stream, ensure_ascii=True, sort_keys=True, indent=2)
            stream.write('\n')
        print(json.dumps({'created': len(manifest['files']), 'bytes': sum(r['size'] for r in manifest['files']), 'historical_integrity_proven': False}))
        return 0
    manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
    differences = verify(root, manifest)
    print(json.dumps({'checked': len(manifest['files']), 'differences': len(differences)}))
    return int(bool(differences))


if __name__ == '__main__':
    raise SystemExit(main())

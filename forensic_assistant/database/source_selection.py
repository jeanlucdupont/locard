"""Bounded retrospective selection from recorded provenance, never the filesystem."""
import json
import ntpath
import re
from . import sources


def path_key(value):
    """Lexical absolute Windows path; no cwd, resolution, expansion or I/O."""
    if not isinstance(value, str) or not value or len(value)>4096:
        raise ValueError('Recorded path must be a nonempty absolute Windows path (up to 4096 characters)')
    path=value.replace('/', '\\')
    if any(ord(c)<32 or c in '<>"|?*' for c in path) or path.startswith(('\\\\?\\','\\\\.\\')):
        raise ValueError('Invalid recorded path; wildcards and device paths are not supported')
    drive,tail=ntpath.splitdrive(path)
    unc=drive.startswith('\\\\') and len(drive[2:].split('\\'))==2 and all(drive[2:].split('\\'))
    if not (re.fullmatch('[A-Za-z]:',drive) or unc) or (tail and not tail.startswith('\\')) or (not tail and not unc):
        raise ValueError('Recorded path requires an absolute drive path or UNC share; use --file-hash for other historical paths')
    parts=[p for p in tail.split('\\') if p]
    if any(p in ('.','..') or p.endswith((' ','.')) or ':' in p for p in (parts+(drive[2:].split('\\') if unc else []))):
        raise ValueError('Invalid recorded path component; relative navigation and alternate streams are not supported')
    return (drive.lower(), *(p.lower() for p in parts))


def select(db, hashes=(), paths=()):
    sources.require4(db)
    hashes=hashes or []; paths=paths or []
    if not hashes and not paths:raise ValueError('Specify at least one --file-hash or --path; there is no implicit all selection')
    if len(paths)>100:raise ValueError('Use at most 100 path selectors')
    selected=set()
    for sha in set(hashes):
        if not re.fullmatch('[0-9a-fA-F]{64}',sha):raise ValueError('Invalid file hash: expected 64 hexadecimal SHA-256 characters')
        sha=sha.lower()
        if not db.execute('SELECT 1 FROM evidence_files WHERE sha256=?',(sha,)).fetchone():raise ValueError('File hash not found: '+sha)
        selected.add(sha)
        if len(selected)>1000:raise ValueError('Select at most 1000 distinct recorded file hashes')
    supplied=list(dict.fromkeys(paths))
    keys={path_key(p) for p in supplied}; found=set(); matched=[]
    if keys:
        for sha,path in db.execute('SELECT file_sha256,source_file FROM source_locations ORDER BY file_sha256,source_file'):
            try:key=path_key(path)
            except ValueError:continue
            hits={p for p in keys if key[:len(p)]==p}
            if hits:
                found.update(hits);selected.add(sha)
                matched.append(dict(file_sha256=sha,source_file=path))
                if len(selected)>1000 or len(matched)>10000:
                    raise ValueError('Selection exceeds 1000 files or 10000 matched recorded locations; narrow the explicit selectors')
        if keys-found:raise ValueError('Path matches no recorded source locations: '+next(p for p in supplied if path_key(p) not in found))
    if not selected or len(selected)>1000:raise ValueError('Select 1..1000 distinct recorded file hashes')
    return dict(file_hashes=sorted(selected),paths=supplied,explicit_hashes=sorted({h.lower() for h in hashes}),
                matched_locations=matched)


def preview(db, source_id, selection, reason):
    if not reason.strip() or len(reason)>4096:raise ValueError('Supply a reason of 1..4096 characters')
    hashes=selection['file_hashes']; counts={}; evidence=0
    provenance=dict(unassigned=0,already_assigned_here=0,assigned_to_other_sources=0,ambiguous=0,multiple_recorded_locations=0)
    members={sha:set() for sha in hashes}
    for sid,sha in db.execute(sources.MEMBERSHIP):
        if sha in members:members[sha].add(sid)
    for sha in hashes:
        for kind,count in db.execute('SELECT artifact_type,count(*) FROM evidence_records WHERE file_sha256=? GROUP BY artifact_type',(sha,)):
            counts[kind]=counts.get(kind,0)+count;evidence+=count
        ids=members[sha]
        provenance['unassigned']+=not ids
        provenance['already_assigned_here']+=source_id in ids
        provenance['assigned_to_other_sources']+=bool(ids-{source_id})
        provenance['ambiguous']+=len(ids)>1
        provenance['multiple_recorded_locations']+=db.execute('SELECT count(*) FROM source_locations WHERE file_sha256=?',(sha,)).fetchone()[0]>1
    return dict(source=sources.summary(db,source_id),**selection,files=len(hashes),evidence_records=evidence,
                artifact_types=counts,existing_provenance=provenance,reason=reason,basis='retrospective analyst assignment',
                limitations=['Selection assigns content hashes, not individual path occurrences; all records of selected content are affected.',
                             'Existing memberships are preserved. Adding another source leaves multiple-source ambiguity visible.',
                             'Provenance counts are distinct file hashes; categories may overlap. Ambiguous means more than one source membership.',
                             'Recorded paths do not prove machine identity. This does not reconstruct historical ingestion batches.'])


def assignment_basis(selection):
    if selection['paths']:
        return 'recorded-path selection '+json.dumps(dict(paths=selection['paths'],explicit_hashes=selection['explicit_hashes']),ensure_ascii=True,sort_keys=True)
    return None

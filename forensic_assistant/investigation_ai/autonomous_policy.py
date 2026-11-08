"""Stage A policy: explicit record eligibility and bounded full-record context."""
from pathlib import Path
import time
from forensic_assistant.correlation.models import time_ns
from forensic_assistant.retrieval.queries import required_time
from forensic_assistant.database.sources import memberships
from forensic_assistant.database.browser import provenance
from .contracts import EID

CONTRACT = 'investigation-authorization-v1'
S4_CONTRACT = 'investigation-s4-authorization-v1'
S4_ALLOCATION = dict(analysis=6, decomposition=1, organization=0, total=7,
                     finalization_reserve_seconds=15, decomposition_seconds=30)
TEMPORAL = 'any retained timestamp in window; bounded full-record context permitted'


def validate(grant, case):
    if grant.get('contract') == S4_CONTRACT:
        validate_s4_shape(grant)
        # Reuse every existing source/time/tool check, without altering old grants.
        grant = {**grant, 'contract': CONTRACT, 'limits': {**grant['limits'], 'requests': 6}}
    if grant.get('contract') != CONTRACT or grant.get('tools') != ['show_evidence']:
        raise ValueError('AUTHORIZATION_INVALID')
    path = Path(case).resolve(strict=True)
    info = path.stat()
    if grant['case'] != str(path) or grant['file_identity'] != [info.st_dev, info.st_ino]:
        raise ValueError('AUTHORIZATION_CASE_CHANGED')
    if grant['provider'] != 'openai' or not grant['model'] or grant['temporal_policy'] != TEMPORAL:
        raise ValueError('AUTHORIZATION_INVALID')
    if not 0 < grant['expires']-grant['issued'] <= 300 or not grant['issued'] <= time.time() < grant['expires']:
        raise ValueError('AUTHORIZATION_EXPIRED')
    if not 1 <= len(grant['evidence_ids']) <= 12 or len(set(grant['evidence_ids'])) != len(grant['evidence_ids']):
        raise ValueError('AUTHORIZATION_INVALID')
    if any(not EID.fullmatch(i) for i in grant['evidence_ids']) or not grant['source_ids']:
        raise ValueError('AUTHORIZATION_INVALID')
    if grant['limits'] != dict(requests=6,steps=8,seconds=300,records=200,prompt_bytes=5600,tool_calls=6,tool_seconds=45,output_tokens=1024):
        raise ValueError('AUTHORIZATION_INVALID')
    low,high = time_ns(required_time(grant['start'])),time_ns(required_time(grant['end']))
    if not 0 <= high-low <= 86400*10**9:raise ValueError('AUTHORIZATION_INVALID')


def validate_s4_shape(grant):
    """Historical-safe shape check; no filesystem access or expiry renewal."""
    if (grant.get('contract') != S4_CONTRACT or grant.get('allocations') != S4_ALLOCATION
            or grant.get('limits') != dict(requests=7,steps=8,seconds=300,records=200,
                prompt_bytes=5600,tool_calls=6,tool_seconds=45,output_tokens=1024)
            or grant.get('tools') != ['show_evidence'] or grant.get('provider') != 'openai'):
        raise ValueError('AUTHORIZATION_INVALID')


def operation(grant, case, name, args):
    validate(grant,case)
    if name!='show_evidence' or set(args)!={'evidence_id'} or args['evidence_id'] not in grant['evidence_ids']:
        raise ValueError('ADDITIONAL_SCOPE_REQUIRED')


def dispatch(db, grant, case, name, args):
    """Check source and time metadata BEFORE retrieving original record content."""
    operation(grant,case,name,args)
    eid=args['evidence_id']
    row=db.execute('SELECT evidence_id,source_type,file_sha256 FROM evidence_records WHERE evidence_id=?',(eid,)).fetchone()
    if row is None or row['source_type'] not in grant['families']:raise ValueError('ADDITIONAL_SCOPE_REQUIRED')
    sources=(provenance(db,eid)[0] if row['source_type']=='browser' else memberships(db,row['file_sha256']))
    ids={s['source_id'] for s in sources}
    if not ids or not ids <= set(grant['source_ids']):raise ValueError('ADDITIONAL_SCOPE_REQUIRED')
    # Same bounded timestamp eligibility as assessment handoff; no timezone inference.
    stamps=db.execute('SELECT timestamp_utc FROM evidence_timestamps WHERE evidence_id=? ORDER BY slot LIMIT 32',(eid,))
    low,high=time_ns(required_time(grant['start'])),time_ns(required_time(grant['end']))
    if not any(r[0] and low<=time_ns(required_time(r[0]))<=high for r in stamps):raise ValueError('ADDITIONAL_SCOPE_REQUIRED')

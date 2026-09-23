"""Closed claim vocabulary and bounded, canonical report data."""
import hashlib
import json
import math
from dataclasses import dataclass

CATEGORIES = ('OBSERVED FACT', 'DETERMINISTIC RELATIONSHIP', 'CORROBORATED RELATIONSHIP',
              'DETECTION', 'MODEL/ANALYST HYPOTHESIS', 'CONFLICT', 'UNKNOWN', 'LIMITATION')
FORMAT = 1
MAX_FILE = 32 * 1024 * 1024
CAUTION = ('A Locard report is derived from forensic evidence; original evidence remains authoritative. '
           'AI narrative and semantic similarity do not create forensic facts. A detection alone does not '
           'prove compromise. Absence of matching evidence does not prove an event did not occur. '
           'Hash validation checks file integrity, not the truth of forensic conclusions. COMPLETE means '
           'completion of the requested bounded report, not completeness of a forensic examination.')
DIRECT_SCOPE = ('Explicit evidence selection only. No complete investigation was performed by report '
                'generation. Findings cover the supplied evidence IDs and required supporting records only. '
                'An empty finding category is not an investigative negative result.')

def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def digest(value): return hashlib.sha256(canonical(value)).hexdigest()

def loads(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    def constant(value): raise ValueError('Nonfinite JSON value')
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        def bounded(item, depth=0):
            if depth > 32: raise ValueError('JSON nesting limit')
            if isinstance(item,float) and not math.isfinite(item): raise ValueError('Nonfinite JSON value')
            if isinstance(item, dict):
                for child in item.values(): bounded(child, depth+1)
            elif isinstance(item, list):
                for child in item: bounded(child, depth+1)
        bounded(value)
        return value
    except (RecursionError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('Malformed report JSON') from exc

@dataclass(frozen=True)
class Limits:
    claims: int = 100
    timeline: int = 500
    seconds: int = 300

    def __post_init__(self):
        for name, ceiling in [('claims',1000), ('timeline',5000), ('seconds',600)]:
            value = getattr(self,name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError('Invalid report limit: '+name)

def claim(category, assertion, evidence_ids=(), origins=()):
    if category not in CATEGORIES: raise ValueError('Unknown claim category')
    core = dict(category=category, assertion=assertion, evidence_ids=sorted(set(evidence_ids)))
    return dict(claim_id='CLM:'+digest(core), **core, origins=sorted(set(origins)))

def graph(claims, evidence):
    known = set(evidence)
    reverse = {eid:[] for eid in sorted(known)}
    edges = []; objects = {}; object_claims = {}; qualifications=[]
    ids = set()
    for item in claims:
        if item['claim_id'] in ids: raise ValueError('Duplicate claim ID')
        ids.add(item['claim_id'])
        if item['category'] not in CATEGORIES or not set(item['evidence_ids']) <= known:
            raise ValueError('Claim lacks supporting evidence')
        for eid in item['evidence_ids']:
            reverse[eid].append(item['claim_id'])
            relation = 'references' if item['category'] in ('MODEL/ANALYST HYPOTHESIS','UNKNOWN') else 'supports'
            edges.append(dict(claim_id=item['claim_id'],evidence_id=eid,relation=relation))
        obj=item['assertion'].get('engine_object')
        if obj is not None:
            oid=obj.get('relationship_id',obj.get('detection_id'))
            if not oid or not set(obj['evidence_ids'])<=known: raise ValueError('Invalid engine object support')
            if oid in objects and objects[oid]!=obj: raise ValueError('Conflicting engine object identity')
            objects[oid]=obj;object_claims.setdefault(oid,[]).append(item['claim_id'])
    for conflict in claims:
        if conflict['category']=='CONFLICT':
            for other in claims:
                if other['claim_id']!=conflict['claim_id'] and set(other['evidence_ids']) & set(conflict['evidence_ids']):
                    qualifications.append(dict(claim_id=conflict['claim_id'],qualifies=other['claim_id'],relation='qualifies'))
    return dict(edges=edges,evidence_to_claims=reverse,engine_objects=objects,
                engine_object_to_claims=object_claims,qualification_edges=qualifications)

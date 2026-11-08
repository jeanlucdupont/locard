"""Application services for assessment selection, authorization and current-view hydration.

Historical projections never enter the investigation evidence ledger.
"""
import copy
import re
from .assessment_store import AssessmentStore
from .briefing_store import Store, digest
from .investigation_ai.contracts import EID
from .retrieval.temporal_scope import window
from .retrieval.queries import required_time

MAX_REFERENCES = 12


def select(case, identity='latest'):
    store = AssessmentStore(case)
    if identity == 'latest':
        rows = store.history()
        if not rows:
            raise ValueError('No saved assessments; run briefing --assess first')
        identity = rows[-1]['id']
    assessment = store.load(identity)
    if assessment['plan']['case'] != store.identity:
        raise ValueError('Assessment plan case identity mismatch')
    return assessment


def references(assessment):
    ids = sorted(assessment['records'])
    if len(ids) > 500 or any(not EID.fullmatch(eid) for eid in ids):
        raise ValueError('Invalid assessment evidence references')
    return {f'E{i+1}': eid for i, eid in enumerate(ids)}


def resolve_references(question, mapping):
    if not isinstance(question, str) or not question.strip() or len(question.encode()) > 1000:
        raise ValueError('Question must be 1..1000 UTF-8 bytes')
    requested = list(dict.fromkeys(re.findall(r'(?<![\w-])E[0-9]+(?![\w-])', question)))
    if any(ref not in mapping for ref in requested):
        raise ValueError('Unknown assessment-local evidence reference')
    if len(requested) > MAX_REFERENCES:
        raise ValueError('Too many assessment references in one question')
    return requested


def prepare(case, identity, question, start=None, end=None):
    assessment = select(case, identity)
    mapping = references(assessment)
    requested = resolve_references(question, mapping)
    selected = (requested + [ref for ref in mapping if ref not in requested])[:MAX_REFERENCES]
    plan = assessment['plan']
    if bool(start) != bool(end):
        raise ValueError('Supply both --start and --end')
    scope = window(start or plan['start'], end or plan['end'], source='analyst-confirmed assessment handoff')
    state = Store(case).load()
    revision = next((r for r in (state or {}).get('revisions', []) if r['digest'] == plan['digest']), None)
    document = revision['content'].get('canonical', {}).get('document', {}) if revision else {}
    summary = document.get('summary', {})
    stale = not state or state['revisions'][-1]['digest'] != plan['digest']
    limitations = ['Historical briefing/chronology is abbreviated; full originals remain in the saved assessment.',
                  'Historical assessment is not current evidence; live-case equality is unknown. Only retained timestamps/context are compared; other historical fields are not equality-verified.',
                  'Unknown or analyst-supplied host/source relationships are not independently established.',
                  'Reported incident time may have an unknown timezone; only the confirmed window authorizes searches.']
    coverage = {status: sorted({r['artifact'] for r in assessment['rows'] if r['status']==status})
                for status in ('match','no_match','unsupported','unavailable','incomplete','failed','not_searched')}
    incomplete = coverage['incomplete']
    if incomplete:
        limitations.append('Historical search coverage incomplete: ' + ', '.join(incomplete) + '; no absence conclusion.')
    for status in ('unsupported','unavailable','failed','not_searched'):
        if coverage[status]:limitations.append('Historical routes '+status+': '+', '.join(coverage[status])+'; not an absence conclusion.')
    if stale:
        limitations.append('Assessment references an older or unavailable briefing revision; no current revision is substituted.')
    if len(mapping) > len(selected):
        limitations.append('Assessment evidence references omitted by the 12-record initial retrieval bound.')
    historical = dict(objectives=plan.get('objectives', [])[:4],
        editorial_summary=summary.get('text', '')[:400] if summary.get('status') == 'accepted' else '',
        leads=[{'id':l['id'], 'value':l['occurrences'][0]['original'][:160]} for l in plan['leads'][:12]],
        chronology=[{k:t.get(k) for k in ('evidence_id','timestamp_utc','slot','meaning')} for t in assessment['timeline'][:8]],
        reported_times=[{k:t.get(k) for k in ('kind','value','status')} for t in plan.get('reported_times', [])[:4]])
    if len(str(historical)) > 4000:
        historical = {'omitted': 'Historical narrative/chronology exceeds context bound; retain question, references and limitations.'}
    hints = []
    for ref in selected:
        eid = mapping[ref]; record = assessment['records'][eid]
        # A comparison of retained timestamp/context projections, not a case fingerprint.
        expected = digest({'timestamps':record['match'].get('timestamps', []), 'context':record.get('source_context', {})})
        hints.append({'ref':ref, 'id':eid, 'projection_digest':expected})
    return dict(case=assessment['case'], assessment_id=assessment['id'], assessment_digest=digest(assessment),
                briefing_revision=plan['revision'], briefing_digest=plan['digest'], question=question,
                scope=scope, hints=hints, historical=historical, limitations=limitations, incomplete_families=incomplete, coverage_states=coverage,
                briefing_stale=stale, latest_briefing_digest=state['revisions'][-1]['digest'] if state else None, context_is_unverified=True)


def authorize(handoff, confirm):
    """confirm receives a reviewable plan; callers own their UI, never the model."""
    if not confirm(copy.deepcopy(handoff)):
        return None
    result = copy.deepcopy(handoff)
    result['authorization'] = digest(handoff)
    return result


def validate(handoff, case):
    data = {k:v for k,v in handoff.items() if k != 'authorization'}
    if handoff.get('authorization') != digest(data):
        raise ValueError('Assessment handoff requires explicit unchanged authorization')
    store = AssessmentStore(case)
    if handoff['case'] != store.identity:
        raise ValueError('Handoff case identity changed')
    if digest(store.load(handoff['assessment_id'])) != handoff['assessment_digest']:
        raise ValueError('Assessment changed after handoff preparation')
    state = Store(case).load()
    if (state['revisions'][-1]['digest'] if state else None) != handoff['latest_briefing_digest']:
        raise ValueError('Briefing changed after handoff preparation; confirm a new handoff')
    window(handoff['scope']['start'], handoff['scope']['end'], source='validation')
    if len(handoff['hints']) > MAX_REFERENCES or any(not EID.fullmatch(h['id']) for h in handoff['hints']):
        raise ValueError('Invalid handoff references')


def investigate(handoff, *, approval, client=None, status=None, runner=None):
    if approval is None:
        raise ValueError('Assessment investigation requires the existing tool approval handler')
    case = handoff['case']['path']
    validate(handoff, case)
    from .investigation_ai.supervision import run
    return (runner or run)({'case_path':case, 'semantic_enabled':False, '_assessment_handoff':handoff},
                          handoff['question'], case + '.investigations', client=client,
                          approval=approval, status=status)


def hydrate(db, handoff):
    """Current authorized view only; reuse original-detail adapters and projection rules."""
    from .investigation_ai import tools
    from .retrieval.evidence import get_evidence
    from .correlation.models import time_ns
    low, high = (time_ns(required_time(handoff['scope'][k])) for k in ('start', 'end'))
    records = []; outcomes = []; limits = list(handoff['limitations'])
    for hint in handoff['hints']:
        eid = hint['id']
        if not db.execute('SELECT 1 FROM evidence_records WHERE evidence_id=?', (eid,)).fetchone():
            outcomes.append({**hint, 'status':'unavailable'}); continue
        raw = get_evidence(db, eid)
        if not any(t.get('timestamp_utc') and low <= time_ns(required_time(t['timestamp_utc'])) <= high for t in raw.get('timestamps', [])):
            outcomes.append({**hint, 'status':'outside_scope_or_undated'}); continue
        current = tools.execute(db, 'show_evidence', {'evidence_id':eid}, {'known_ids':[eid]})
        # Initial membership/identity exposure only. Full fields require ordinary approved show_evidence.
        records.extend({k:r[k] for k in ('id','source_type','kind') if k in r} for r in current['records'])
        limits.extend(current['limitations'])
        projection = digest({'timestamps':raw.get('timestamps', [])[:32], 'context':tools.compact(raw).get('source_context', {})})
        outcomes.append({**hint, 'status':'timestamp_context_match_only' if projection == hint['projection_digest'] else 'timestamp_context_changed'})
    # Already compacted by the normal show adapter; do not compact twice.
    result = tools.envelope(db, 'assessment_initial', {'records': []})
    result.update(records=records, returned_count=len(records), limitations=list(dict.fromkeys(limits)),
                  plan={'assessment_revalidation':outcomes, 'browser_available':bool(db.execute("SELECT 1 FROM evidence_records WHERE source_type='browser' LIMIT 1").fetchone())})
    for outcome in outcomes:
        if outcome['status'] != 'timestamp_context_match_only':
            result['limitations'].append(outcome['ref'] + ': ' + outcome['status'] + '; historical fields are not substituted.')
    return result

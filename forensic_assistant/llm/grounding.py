"""ASK-only selection roles and conservative artifact limits, not a classifier.

No scores, filenames, host assertions or model judgments establish support here.
The narrow credential-use guard applies only to the selected MFT metadata.
Other questions still require field-based review; selection is not claim validation.
"""
import re


ARTIFACT_GUIDANCE = {
    'mft': 'MFT presence and access timestamps do not prove execution. MFT does not record execution timestamps. Its timestamps provide filesystem activity context, not meaningful usage or credential use.',
    'prefetch': 'Prefetch timestamps may support execution, not malicious intent; counts and retained runs are incomplete.',
    'evtx': 'EVTX meaning depends on event type; relevant events may support authentication or execution observations.',
    'registry': 'Registry provides configuration/user-activity context; interpretation depends on key/value semantics.',
    'browser': 'Browser records describe browsing/download activity, not proof of execution.',
}
CREDENTIAL_USE = re.compile(
    r'\bcredentials?\s+(?:use|usage|handling)\b|\b(?:use|usage|handling)\s+of\s+credentials?\b', re.I)


def artifact(record):
    return record.get('source_type') or record['id'].partition(':')[0].lower()


def assess(bundle, plan):
    """Derive guidance without editing selected records or engine relationships."""
    records = bundle['EVIDENCE']
    direct = set(bundle['DIRECT_EVIDENCE'])
    semantic_only_plan = plan.get('operation') == 'conceptual'
    candidates = [r['id'] for r in records if r['id'] not in direct and (
        semantic_only_plan or 'semantic_similarity' in r.get('selection_reasons', []))]
    context = [r['id'] for r in records if r['id'] not in direct and r['id'] not in candidates]
    kinds = {artifact(r) for r in records}
    # This is an artifact-capability limit, not a negative finding about a case.
    unsupported = kinds == {'mft'} and bool(CREDENTIAL_USE.search(bundle['QUESTION']))
    statement = None
    limitations = []
    if unsupported:
        statement = ('No direct evidence of credential use was identified in the selected MFT metadata. '
                     'This does not establish absence of activity outside this selection.')
        limitations = [
            'The selected evidence is MFT metadata, which does not by itself establish credential use.',
            'Review relevant authentication/event logs and Registry context if available; their individual semantics still govern interpretation.',
        ]
    elif candidates and not direct:
        statement = ('Deterministic retrieval did not identify direct support for the requested activity in this selection. '
                     'Semantic candidates are leads; assess their fields before drawing conclusions.')
    return {
        'deterministic_selection_ids': [r['id'] for r in records if r['id'] in direct],
        'candidate_lead_ids': candidates,
        'context_evidence_ids': context,
        'statement': statement,
        'limitations': limitations,
        'withhold_model_analysis': unsupported,
        'basis': 'Selected artifact capabilities and retrieval roles only; not a general claim validator.',
    }

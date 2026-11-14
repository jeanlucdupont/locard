"""Bounded recorded report projection; offline structure is not source authority."""
from copy import deepcopy
from datetime import datetime
import re
import json

from .model import canonical, digest, loads
from forensic_assistant.investigation_ai import synthesis, relationships, question_assessment, findings
from forensic_assistant.investigation_ai.transcript import validate_evidence_state
from forensic_assistant.investigation_ai.projection import same

CONTRACT = 'recorded-investigation-report-v1'
RENDERER = 'recorded-html-v2'
TYPES = ('executive', 'technical', 'handover')
MAX_PROJECTION = 32 * 1024 * 1024
MAX_HTML = 32 * 1024 * 1024
MAX_BUNDLE = 64 * 1024 * 1024
MAX_NODES = 400000
MAX_TEXT = 262144
MAX_SUPPORTS = 4096
MAX_BLOCKS = 16384
LEGACY_POLICY = dict(output_version='recorded-html-v1', redaction='none', display_clipping=False,
              ordering='stable source identity; findings creation revision',
              local_paths='workspace storage paths in audit projection only',
              evidence_paths='original recorded values retained')
POLICY = dict(LEGACY_POLICY, output_version=RENDERER,
              ordering='audience sections; stable identity references; exact question text deduplication')
POLICIES = {'recorded-html-v1': LEGACY_POLICY, RENDERER: POLICY}
CAUTION = ('Recorded investigation only; not a revalidation of the current case. '
           'Analyst acceptance does not establish forensic truth. AI-origin findings remain unverified inferences. '
           'Citations do not prove entailment. Completed authorized processing is not whole-case completeness. '
           'Hashes establish consistency, not authentication.')


def keys(value, names):
    if type(value) is not dict or set(value) != set(names.split()):
        raise ValueError('RECORDED_REPORT_SHAPE')


def bounded(value):
    """Bound tree expansion before serialization (including keys and Unicode)."""
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_NODES or depth > 32:
            raise ValueError('RECORDED_REPORT_TREE_LIMIT')
        if type(item) is str:
            if len(item.encode('utf-8')) > MAX_TEXT:
                raise ValueError('RECORDED_REPORT_TEXT_LIMIT')
        elif type(item) is dict:
            if any(type(k) is not str for k in item):
                raise ValueError('RECORDED_REPORT_KEY_TYPE')
            pending.extend((v, depth + 1) for pair in item.items() for v in pair)
        elif type(item) is list:
            pending.extend((v, depth + 1) for v in item)
        elif item is not None and type(item) not in (int, float, bool):
            raise ValueError('RECORDED_REPORT_VALUE_TYPE')
    size = 0
    for part in json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).iterencode(value):
        size += len(part.encode('utf-8'))
        if size > MAX_PROJECTION:
            raise ValueError('RECORDED_REPORT_PROJECTION_LIMIT')


def timestamp(value):
    if type(value) is not str or datetime.fromisoformat(value).tzinfo is None:
        raise ValueError('RECORDED_REPORT_TIMESTAMP')


def support_map(restored, view):
    result = {}
    units = {}
    for cid, bundle in sorted(restored.items()):
        refs = []
        for leaf in bundle['leaves']:
            leaf = dict(leaf, view=deepcopy(view))
            identity = digest(leaf)
            result[identity] = deepcopy(leaf)
            refs.append(identity)
        units[cid] = dict(support_refs=sorted(set(refs)),
                          interpretations=deepcopy(bundle['interpretations']),
                          qualifications=deepcopy(bundle['qualifications']))
    if len(result) > MAX_SUPPORTS:
        raise ValueError('RECORDED_REPORT_SUPPORT_LIMIT')
    return result, units


def validate(projection):
    """Strict structure and internal consistency only. Use revalidate for authority."""
    bounded(projection)
    keys(projection, 'contract content content_digest generation')
    if projection['contract'] != CONTRACT:
        raise ValueError('RECORDED_REPORT_VERSION')
    keys(projection['generation'], 'generated_utc validation_utc application_version renderer_version')
    c = projection['content']
    keys(c, 'report_type source view engine frontiers question original_assessment factual related organization explanation_pages supports units workspace validation policy caution execution historical_proposals')
    if type(c['historical_proposals']) is not list or len(c['historical_proposals']) > 8:
        raise ValueError('RECORDED_REPORT_PROPOSAL_LIMIT')
    keys(c['execution'], 'manifest_status terminal_present recorded')
    if type(c['execution']['manifest_status']) is not str or type(c['execution']['terminal_present']) is not bool:
        raise ValueError('RECORDED_REPORT_EXECUTION_SHAPE')
    if type(c['execution']['recorded']) is not dict or not set(c['execution']['recorded']) <= {
            'termination', 'primary_termination', 'analysis_coverage', 'controller_diagnostic', 'limitations', 'cleanup'}:
        raise ValueError('RECORDED_REPORT_EXECUTION_SHAPE')
    if c['report_type'] not in TYPES or c['caution'] != CAUTION:
        raise ValueError('RECORDED_REPORT_TYPE')
    keys(c['policy'], 'output_version redaction display_clipping ordering local_paths evidence_paths')
    renderer = projection['generation']['renderer_version']
    if type(renderer) is not str or renderer not in POLICIES:
        raise ValueError('RECORDED_REPORT_RENDERER')
    if c['policy'] != POLICIES[renderer]:
        raise ValueError('RECORDED_REPORT_POLICY')
    keys(c['validation'], 'source_binding support_reconstruction workspace semantic_truth')
    if c['validation'] != dict(source_binding='valid_recorded_binding', support_reconstruction='validated',
                               workspace='validated' if c['workspace'] is not None else 'not_attached', semantic_truth='not_certified'):
        raise ValueError('RECORDED_REPORT_AUTHORITY_LABEL')
    keys(c['source'], 'run_id manifest_sha256 event_head')
    for name, length in (('run_id', 32), ('manifest_sha256', 64), ('event_head', 64)):
        if type(c['source'][name]) is not str or not re.fullmatch('[a-f0-9]{'+str(length)+'}', c['source'][name]):
            raise ValueError('RECORDED_REPORT_SOURCE_ID')
    validate_evidence_state(c['view'])
    keys(c['frontiers'], 'manifest_chain accepted')
    if type(c['frontiers']['accepted']) is not list or len(c['frontiers']['accepted']) > 6:
        raise ValueError('RECORDED_REPORT_FRONTIER')
    if type(c['question']) is not str or not c['question'].strip():
        raise ValueError('RECORDED_REPORT_QUESTION')
    synthesis.render(c['factual'])
    keys(c['factual'], 'contract recorded_not_revalidated evidence_state validated_batches clauses hypotheses unresolved_questions coverage limitations')
    if c['factual']['evidence_state'] != c['view']:
        raise ValueError('RECORDED_REPORT_CROSS_VIEW')
    if relationships._build(c['factual']) != c['related']:
        raise ValueError('RECORDED_REPORT_RELATIONSHIP')
    if question_assessment._assess(c['question'], c['source']['run_id'], c['related']) != c['original_assessment']:
        raise ValueError('RECORDED_REPORT_S3_CHANGED')
    if type(c['supports']) is not dict or len(c['supports']) > MAX_SUPPORTS:
        raise ValueError('RECORDED_REPORT_SUPPORT_LIMIT')
    clauses = {v['id']: v for v in c['factual']['clauses']}
    if type(c['units']) is not dict or set(c['units']) != set(clauses):
        raise ValueError('RECORDED_REPORT_UNIT_CLOSURE')
    used = set()
    for cid, unit in c['units'].items():
        keys(unit, 'support_refs interpretations qualifications')
        if type(unit['support_refs']) is not list or not unit['support_refs'] or len(set(unit['support_refs'])) != len(unit['support_refs']):
            raise ValueError('RECORDED_REPORT_SUPPORT_REFERENCES')
        if unit['qualifications'] != clauses[cid]['qualifications']:
            raise ValueError('RECORDED_REPORT_QUALIFICATIONS')
        for ref in unit['support_refs']:
            if ref not in c['supports']:
                raise ValueError('RECORDED_REPORT_MISSING_SUPPORT')
            leaf = c['supports'][ref]
            required = {'contract', 'evidence_id', 'source', 'lineage', 'clause_id', 'field', 'view'}
            if type(leaf) is not dict or set(leaf) not in (required, required | {'timestamp'}):
                raise ValueError('RECORDED_REPORT_LEAF_SHAPE')
            if digest(leaf) != ref or leaf['clause_id'] != cid or leaf['view'] != c['view']:
                raise ValueError('RECORDED_REPORT_SUPPORT_BINDING')
            support = clauses[cid]['supports'][0]
            if (leaf['contract'] != 'synthesis-support-v1' or leaf['evidence_id'] != support['evidence_id']
                    or leaf['lineage'] not in clauses[cid]['lineage']):
                raise ValueError('RECORDED_REPORT_ORIGINAL_IDENTITY')
            keys(leaf['source'], 'context provenance projection_sha256 source_type')
            if (leaf['source']['context'] != support['context'] or leaf['source']['provenance'] != support['provenance']
                    or leaf['source']['source_type'] != support['source_type']
                    or leaf['source']['projection_sha256'] != leaf['lineage']['record_projection_sha256']):
                raise ValueError('RECORDED_REPORT_ORIGINAL_PROVENANCE')
            if clauses[cid]['type'] == 'observation':
                if not same(leaf['field'], support['field']) or leaf.get('timestamp') != support.get('timestamp'):
                    raise ValueError('RECORDED_REPORT_ORIGINAL_FIELD')
            elif (leaf['field']['pointer'] not in support['premise_pointers'] or
                  not same(leaf['field']['value'], support['premises'][leaf['field']['pointer'][1:]])):
                raise ValueError('RECORDED_REPORT_INTERPRETATION_PREMISE')
            used.add(ref)
        if clauses[cid]['type'] == 'deterministic_interpretation':
            support = clauses[cid]['supports'][0]
            if {c['supports'][ref]['field']['pointer'] for ref in unit['support_refs']} != set(support['premise_pointers']):
                raise ValueError('RECORDED_REPORT_INCOMPLETE_PREMISES')
            expected = [dict(contract='synthesis-interpretation-support-v1', interpretation=clauses[cid]['arguments'],
                             premise_pointers=support['premise_pointers'], evidence_id=support['evidence_id'])]
            if unit['interpretations'] != expected:
                raise ValueError('RECORDED_REPORT_INTERPRETATION_IDENTITY')
        elif unit['interpretations'] or len(unit['support_refs']) != 1:
            raise ValueError('RECORDED_REPORT_OBSERVATION_SHAPE')
    if used != set(c['supports']):
        raise ValueError('RECORDED_REPORT_UNUSED_SUPPORT')
    if type(c['explanation_pages']) is not list or len(c['explanation_pages']) > 193:
        raise ValueError('RECORDED_REPORT_PAGES')
    for page in c['explanation_pages']:
        keys(page, 'contract rules mode binding question original_assessment answer_boundary summary summary_omitted sections statements omissions counts limits next_cursor coverage_scope source_coverage source_organization_stops assembly_exhausted page_complete assembly_limit_omitted source_organization_incomplete')
        if page.get('contract') != 'integrated-explanation-v1' or page['binding']['read_view'] != c['view']:
            raise ValueError('RECORDED_REPORT_EXPLANATION_BINDING')
    if c['organization'] is not None and (c['organization'].get('contract') != 'investigative-organization-v1' or c['organization']['read_view'] != c['view']):
        raise ValueError('RECORDED_REPORT_ORGANIZATION')
    if c['organization'] is not None:
        keys(c['organization'], 'contract rules run_id read_view revision frontier entities links entity_revisions coverage operations dependency_visits mode state_digest processing_stops resource_use incomplete finalization limitations')
    w = c['workspace']
    if w is not None:
        keys(w, 'metadata revision head findings history')
        keys(w['metadata'], 'contract id created actor source_root binding')
        if w['metadata']['contract'] != findings.CONTRACT:
            raise ValueError('RECORDED_REPORT_WORKSPACE_CONTRACT')
        findings._id(w['metadata']['id'])
        timestamp(w['metadata']['created'])
        if w['metadata']['binding'] != dict(source=c['source'], view=c['view']):
            raise ValueError('RECORDED_REPORT_WORKSPACE_BINDING')
        events = []
        for event in w['history']:
            value = {k: v for k, v in event.items() if k not in ('hash', 'actor_authority')}
            events.append((event['sequence'], canonical(value).decode(), event['hash']))
        rebuilt = findings._reduce(w['metadata'], events)
        if rebuilt != {k: w[k] for k in ('revision', 'head', 'findings', 'history')}:
            raise ValueError('RECORDED_REPORT_WORKSPACE_CHAIN')
    keys(projection['generation'], 'generated_utc validation_utc application_version renderer_version')
    timestamp(projection['generation']['generated_utc'])
    timestamp(projection['generation']['validation_utc'])
    if projection['generation']['renderer_version'] not in POLICIES or type(projection['generation']['application_version']) is not str:
        raise ValueError('RECORDED_REPORT_RENDERER')
    if projection['content_digest'] != digest(c):
        raise ValueError('RECORDED_REPORT_CONTENT_DIGEST')
    return projection

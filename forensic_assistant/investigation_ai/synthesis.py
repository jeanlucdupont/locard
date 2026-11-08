"""S1 recorded-view factual clauses. No case reads, model calls or evidence authority.

The public grounding entry point is reconstruct(), which verifies the existing
Stage A journal and replays its disclosure/accepted-delta validation. Serialized
clauses alone are NOT a grounding input. render() is only a presentation service.
"""
from copy import deepcopy
import json
import re

from . import disclosure
from .conclusions import interpretations
from .projection import same
from .state import encoded
from .transcript import digest, validate_evidence_state

CONTRACT = 'synthesis-clause-v1'
RESULT = 'recorded-factual-clauses-v1'
MAX_BATCHES = 6
MAX_CLAUSES = 96  # Six existing packets, at most 12 observations + 4 derivations each.
MAX_CLAUSE_BYTES = 32768
MAX_RESULT_BYTES = 1024 * 1024

# Each predicate reports recorded data, never real-world execution or causality.
RULES = {
    'record_reports_field': ('record-field-v1', 'The record'),
    'browser_download_field': ('browser-download-field-v1', 'The browser download record'),
    'mft_metadata_field': ('mft-metadata-field-v1', 'The filesystem metadata'),
    'evtx_recorded_field': ('evtx-recorded-field-v1', 'The Windows event'),
    'prefetch_metadata_field': ('prefetch-metadata-field-v1', 'The Prefetch record'),
    'defender_asr_block': ('defender-asr-block-v1', 'Defender recorded an ASR blocking action.'),
}
BASE = 'Reported field; not proof of execution, attribution, intent or causation'
CAUTIONS = {
    'browser_download_field': 'A download record does not establish opening or execution.',
    'mft_metadata_field': 'MFT metadata and SI/FN timestamps do not establish process execution.',
    'evtx_recorded_field': 'Event fields retain their provider/event meaning; no execution outcome is inferred.',
    'prefetch_metadata_field': 'Referenced files are not executed images; recorded executable/run metadata does not prove successful execution of a referenced script.',
}


def _bounded(value, limit):
    size = len(encoded(value).encode('utf-8'))
    if size > limit:
        raise ValueError('Factual clause serialization budget exceeded')
    return size


def _predicate(family, eid, pointer):
    if family == 'browser' and ':download:' in eid and (
        pointer in ('/target_path', '/current_path') or pointer.startswith('/url_chain/')
    ):
        return 'browser_download_field'
    if family == 'mft' and (pointer.startswith('/objects/') or re.fullmatch(r'/timestamps/\d+/utc', pointer)):
        return 'mft_metadata_field'
    if family == 'evtx':
        return 'evtx_recorded_field'
    if family == 'prefetch' and (
        pointer == '/executable' or pointer.startswith('/objects/') or re.fullmatch(r'/timestamps/\d+/utc', pointer)
    ):
        return 'prefetch_metadata_field'
    return 'record_reports_field'


def _context(record):
    return deepcopy({key: record.get(key) for key in (
        'source_file', 'source_context', 'supporting_evidence_ids',
        'truncated_fields', 'coverage_notes', 'warnings', 'host_context_basis',
    )})


def _body(view, predicate, support, *, interpretation=None):
    """Application-owned templates; no model wording enters factual arguments."""
    qualifiers = [BASE]
    if predicate in CAUTIONS:
        qualifiers.append(CAUTIONS[predicate])
    context = support['context']
    if context.get('source_context'):
        qualifiers.append('Source context retains its recorded basis; analyst assertions are not independently verified.')
    if context.get('truncated_fields') or support.get('field', {}).get('semantic', {}).get('truncated'):
        qualifiers.append('The supporting projection is bounded/truncated; no assertion about omitted content is made.')
    if context.get('coverage_notes'):
        qualifiers.append('Recorded coverage limitations apply; absence is not established.')
    field = support.get('field')
    if field and ('timestamp' in field['pointer'] or field['pointer'].endswith('/utc')):
        qualifiers.append('Timestamp value and slot are preserved as recorded; precision, timezone and clock equivalence are not inferred.')
    if interpretation is not None:
        qualifiers.append(interpretation['text'])
    return {
        'contract': CONTRACT,
        'type': 'deterministic_interpretation' if interpretation else 'observation',
        'predicate': predicate,
        'rule': RULES[predicate][0],
        'arguments': deepcopy(interpretation if interpretation else field),
        'supports': [deepcopy(support)],
        'interpretation_ids': [interpretation['interpretation_id']] if interpretation else [],
        'evidence_state': deepcopy(view),
        'qualifications': sorted(set(qualifiers)),
        'validation': 'recorded_deterministic_interpretation' if interpretation else 'recorded_observation',
    }


class _Reducer:
    """Private accepted-delta sink; never an importer of model/cached clauses."""

    def __init__(self):
        self.clauses = {}
        self.view = None
        self.batches = 0
        self.previous = None
        self.summary = {}
        self.hypotheses = {}
        self.unknowns = set()

    def _add(self, body, lineage):
        _bounded(body, MAX_CLAUSE_BYTES)
        identity = digest(body)
        if identity not in self.clauses:
            if len(self.clauses) >= MAX_CLAUSES:
                raise ValueError('Factual clause count budget exceeded')
            self.clauses[identity] = dict(body, id=identity, lineage=[])
        refs = self.clauses[identity]['lineage']
        if lineage not in refs:
            refs.append(deepcopy(lineage))
            refs.sort(key=encoded)
        _bounded(self.clauses, MAX_RESULT_BYTES)

    def consume(self, state, delta, exposure):
        # Defense in depth: callback is reached only after autonomous.reconstruct
        # validates identity/chain; recheck grounding here before deriving clauses.
        from .autonomous import DELTA
        view = validate_evidence_state(delta['evidence_state'])
        if self.batches >= MAX_BATCHES:
            raise ValueError('Factual clause batch budget exceeded')
        if (delta['contract'] != DELTA or delta['batch'] != self.batches + 1
                or delta['based_on'] != self.previous or (self.view is not None and not same(view, self.view))):
            raise ValueError('Invalid factual clause delta/view chain')
        if delta['disclosure_sha256'] != digest(exposure) or not same(state.last_compact, exposure):
            raise ValueError('Invalid factual clause disclosure binding')
        findings = state.render(delta['proposal']['answer'])
        if not same(findings, delta['findings']):
            raise ValueError('Invalid factual clause observation binding')
        packet = disclosure.decode(exposure)
        groups = {group['id']: group for group in packet['records']}
        lineage = dict(delta_id=delta['id'], batch=delta['batch'], disclosure_sha256=digest(exposure),
                       projection_contract=packet['contract'], projection_encoding=exposure['encoding'])
        for row in findings['observed']:
            eid, pointer = row['evidence_ids'][0], row['field']
            group = groups[eid]
            item = next((i for i in group['observations'] if i['field']['pointer'] == pointer), None)
            if item is None or not same(item['field']['value'], row['reported_value']):
                raise ValueError('Missing factual clause original field')
            record = (state.records if item['origin'] == 'current' else state.exposed)[eid]
            if (group['sources'][item['origin']]['provenance'] != disclosure.provenance(record)
                    or not same(item['field'], disclosure.descriptor(record, pointer, row['reported_value']))):
                raise ValueError('Factual clause source projection changed')
            support = dict(evidence_id=eid, field=deepcopy(item['field']),
                           source_type=record.get('source_type'),
                           provenance=disclosure.provenance(record), context=_context(record))
            # Keep exact timestamp slot, normalization/precision metadata where present.
            match = re.fullmatch(r'/timestamps/(\d+)/utc', pointer)
            if match:
                support['timestamp'] = deepcopy(record['timestamps'][int(match[1])])
            predicate = _predicate(record.get('source_type'), eid, pointer)
            self._add(_body(view, predicate, support), dict(lineage,
                      origin=item['origin'], record_projection_sha256=digest(record)))
        for row in findings.get('interpretations', []):
            iid, eid = row['interpretation_id'], row['evidence_ids'][0]
            item = next((i for i in groups[eid]['interpretations'] if i['id'] == iid), None)
            if item is None:
                raise ValueError('Missing factual clause interpretation disclosure')
            record = (state.records if item['origin'] == 'current' else state.exposed)[eid]
            expected = interpretations(record).get(iid)
            if not same(expected, row) or not same(item['value'], row):
                raise ValueError('Unrecognized factual clause interpretation')
            support = dict(evidence_id=eid, interpretation_id=iid,
                           source_type=record.get('source_type'),
                           provenance=disclosure.provenance(record), context=_context(record),
                           premise_pointers=['/provider', '/channel', '/event_id', '/defender_asr'],
                           premises={k: deepcopy(record[k]) for k in ('provider', 'channel', 'event_id', 'defender_asr')})
            self._add(_body(view, 'defender_asr_block', support, interpretation=expected), dict(lineage,
                      origin=item['origin'], record_projection_sha256=digest(record)))
        for hypothesis in findings['hypotheses']:
            self.hypotheses[encoded(hypothesis)] = deepcopy(hypothesis)
        self.unknowns.update(findings['model_proposed_unknowns'])
        self.batches += 1
        self.previous = delta['id']
        self.view = deepcopy(view)
        self.summary = state.summary()

    def finish(self):
        clauses = sorted(self.clauses.values(), key=lambda c: (
            c['supports'][0]['evidence_id'], c['supports'][0].get('field', {}).get('pointer', ''), c['id']))
        represented = {c['supports'][0]['evidence_id'] for c in clauses}
        inspected = set(self.summary.get('inspected_ids', []))
        result = dict(contract=RESULT, recorded_not_revalidated=True, evidence_state=self.view,
                      validated_batches=self.batches, clauses=deepcopy(clauses),
                      hypotheses=[self.hypotheses[k] for k in sorted(self.hypotheses)],
                      unresolved_questions=sorted(self.unknowns),
                      coverage=dict(inspected_record_ids=sorted(inspected), represented_record_ids=sorted(represented),
                                    inspected_not_represented=sorted(inspected - represented),
                                    basis='State at the latest accepted batch; later operations are not counted here.',
                                    disclosure=self.summary, relevance_of_omissions='Not evaluated'),
                      limitations=['Recorded-view derivation, not revalidation against the current case.',
                                   'Clauses are derived representations, not evidence or permissions for new model reasoning.',
                                   'Only accepted batch observations and recognized interpretations are included; no completeness claim.'])
        _bounded(result, MAX_RESULT_BYTES)
        return result


def reconstruct(root, identity):
    """Read/validate a saved Stage A transcript; never open the evidence database."""
    from .autonomous import reconstruct as replay
    reducer = _Reducer()
    replay(root, identity, _on_validated=reducer.consume)
    return reducer.finish()


def _validate_render_clause(clause):
    """Reject altered/unsupported render contracts; NOT evidence revalidation."""
    _bounded(clause, MAX_CLAUSE_BYTES)
    try:
        body = {k: v for k, v in clause.items() if k not in ('id', 'lineage')}
        predicate = body['predicate']
        if predicate not in RULES or len(body['supports']) != 1:
            raise ValueError('Unsupported factual predicate/support')
        validate_evidence_state(body['evidence_state'])
        support = body['supports'][0]
        if predicate == 'defender_asr_block':
            original = dict(support['premises'], id=support['evidence_id'])
            recognized = interpretations(original).get(support['interpretation_id'])
            if not same(recognized, body['arguments']):
                raise ValueError('Unsupported factual interpretation render contract')
        elif predicate != _predicate(support['source_type'], support['evidence_id'], support['field']['pointer']):
            raise ValueError('Factual predicate does not match its recorded support')
        expected = _body(body['evidence_state'], predicate, body['supports'][0],
                         interpretation=body['arguments'] if predicate == 'defender_asr_block' else None)
        if not same(body, expected) or clause['id'] != digest(body) or not clause['lineage']:
            raise ValueError('Invalid factual clause render contract')
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        raise ValueError('Malformed factual clause render contract') from exc


def render(result):
    """Controlled text for a reconstruct() result. Never accepts factual AI prose."""
    _bounded(result, MAX_RESULT_BYTES)
    if result.get('contract') != RESULT or result.get('recorded_not_revalidated') is not True:
        raise ValueError('Unsupported factual clause result')
    if len(result['clauses']) > MAX_CLAUSES:
        raise ValueError('Factual clause count budget exceeded')
    lines = ['Recorded-view factual clauses — not revalidated against the current case', '']
    notes = set(result['limitations'])
    for clause in result['clauses']:
        _validate_render_clause(clause)
        predicate = clause['predicate']
        subject = RULES[predicate][1]
        args = clause['arguments']
        # JSON quoting escapes control characters in untrusted labels and values.
        if predicate == 'defender_asr_block':
            text = subject
        else:
            text = subject + ' reports ' + json.dumps(args['label'], ensure_ascii=True) + ' as ' + json.dumps(args['value'], ensure_ascii=True) + '.'
        lines.extend([text, '  Clause: ' + clause['id']])
        for support in clause['supports']:
            lines.append('  Evidence: ' + json.dumps(support['evidence_id']) + ' ' + json.dumps(support.get('field', {}).get('pointer', support.get('interpretation_id'))))
            if support.get('timestamp'):
                lines.append('  Timestamp semantics: ' + encoded(support['timestamp']))
            for key in ('coverage_notes', 'warnings', 'truncated_fields'):
                if support['context'].get(key):
                    lines.append('  ' + key + ': ' + encoded(support['context'][key]))
        notes.update(clause['qualifications'])
    lines += ['', 'Qualifications (apply to supporting clauses)'] + ['  - ' + json.dumps(n, ensure_ascii=True) for n in sorted(notes)]
    lines += ['', 'Unverified hypotheses — not factual clauses']
    lines += ['  ' + encoded(h) for h in result['hypotheses']] or ['  None recorded.']
    lines += ['', 'Unresolved questions — unverified model proposals']
    lines += ['  ' + json.dumps(q, ensure_ascii=True) for q in result['unresolved_questions']] or ['  None recorded.']
    lines += ['', 'Coverage: ' + encoded({k: v for k, v in result['coverage'].items() if k != 'disclosure'})]
    return '\n'.join(lines)


def main():
    """Independent read-only inspection utility; does not alter Locard commands."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', help='Directory containing saved investigation directories')
    parser.add_argument('identity', help='Original 32-character investigation ID (directory name)')
    parser.add_argument('--json', action='store_true', help='Print structured clauses and support lineage')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--relationships', action='store_true', help='Inspect S2 typed relationships and recorded-value chronology')
    mode.add_argument('--assessment', action='store_true', help='Inspect S3 deterministic assessment of the saved original question')
    mode.add_argument('--decomposition', action='store_true', help='Inspect recorded S4-A mappings and scoped assessments; never invokes AI')
    args = parser.parse_args()
    try:
        if args.decomposition:
            from . import decomposition
            result = decomposition.reconstruct(args.root, args.identity)
            print(encoded(result) if args.json else decomposition.render(result))
        elif args.assessment:
            from . import question_assessment
            result = question_assessment.reconstruct(args.root, args.identity)
            print(encoded(result) if args.json else question_assessment.render(result))
        elif args.relationships:
            from . import relationships
            result = relationships.reconstruct(args.root, args.identity)
            print(encoded(result) if args.json else relationships.render(result))
        else:
            result = reconstruct(args.root, args.identity)
            print(encoded(result) if args.json else render(result))
    except (ValueError, OSError) as exc:
        parser.exit(1, 'Factual clause inspection failed: ' + type(exc).__name__ + '\n')


if __name__ == '__main__':
    main()

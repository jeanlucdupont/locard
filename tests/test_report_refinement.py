"""Presentation-format-3 regressions using synthetic records only."""
import copy
import hashlib
import json

import pytest

from forensic_assistant.reporting import bundle, narrative, narrative_v2, view
from forensic_assistant.reporting.boundaries import approved
from forensic_assistant.reporting.model import canonical, claim
from forensic_assistant.reporting.render import render, markdown, esc, md
from test_report_humanization import selected, rehash
from test_v5_narrative import Model


def reply(supplied, *, boundaries=True):
    options = narrative.statement_options(supplied, 'summary_paragraphs')
    option = next(o for o in options if bool(o.get('boundary_ids')) == boundaries)
    return {'summary_paragraphs': [option], 'key_points': [], 'limitations': []}


def assisted(report):
    result = copy.deepcopy(report)
    result['narrative'] = narrative.assist(result['data'], Model(
        lambda messages: json.dumps(reply(json.loads(messages[1]['content'])))))
    assert result['narrative']['status'] == 'ACCEPTED'
    return result


def section(report, title):
    return next(s for s in view.build(report)['sections'] if s['title'] == title)


def test_joint_sentence_exact_support_and_separate_boundaries(selected):
    before = copy.deepcopy(selected[3])
    report = assisted(before)
    item = report['narrative']['summary_paragraphs'][0]
    assert 'coreupdater.exe' in item['text'] and 'loot.zip' in item['text']
    assert ';' in item['text'] and 'Within the selected MFT metadata' in item['text']
    expected = {c['claim_id'] for c in report['data']['claims']
                if c['category'] == 'OBSERVED FACT' and c['assertion']['field'] in ('/objects/0', '/allocated')}
    assert set(item['claim_ids']) == expected and len(expected) == 4
    assert set(item['boundary_ids']) == {'mft_metadata_boundary', 'no_relationship_asserted'}
    assert report['data'] == before['data']
    assert bundle.structure(report)


@pytest.mark.parametrize('attack', ['missing_claim', 'extra_claim', 'missing_boundary',
    'extra_boundary', 'false_boundary', 'execution', 'relationship', 'sequence', 'intent',
    'compromise', 'attribution', 'proof_of_absence', 'category', 'tools'])
def test_joint_narrative_fail_closed(selected, attack):
    data = selected[3]['data']
    supplied = narrative.packet(data, 'technical')
    result = reply(supplied)
    item = result['summary_paragraphs'][0]
    if attack == 'missing_claim':
        item['claim_ids'].pop()
    elif attack == 'extra_claim':
        item['claim_ids'].append('CLM:' + 'f' * 64)
    elif attack == 'missing_boundary':
        item['boundary_ids'].pop()
    elif attack == 'extra_boundary':
        item['boundary_ids'].append('model_invented_boundary')
    elif attack == 'false_boundary':
        item['text'] = item['text'].replace('is asserted by this report', 'exists')
    elif attack == 'category':
        item['category'] = 'CONFIRMED COMPROMISE'
    elif attack == 'tools':
        result['tools'] = ['execute']
    else:
        item['text'] += {'execution': ' The executable ran.',
            'relationship': ' These records are related.',
            'sequence': ' The executable then produced the archive.',
            'intent': ' The analyst established malicious intent.',
            'compromise': ' The machine was compromised.',
            'attribution': ' The user created both files.',
            'proof_of_absence': ' No execution occurred.'}[attack]
    with pytest.raises(ValueError):
        narrative.validate_output(result, supplied, set(data['evidence']))


@pytest.mark.parametrize('category', ['DETERMINISTIC RELATIONSHIP', 'CORROBORATED RELATIONSHIP'])
def test_absence_of_assertion_is_withdrawn_when_relationship_present(selected, category):
    data = copy.deepcopy(selected[3]['data'])
    original = narrative.packet(data, 'technical')
    response = reply(original)
    data['claims'].append(claim(category, {'engine_object': {
        'relationship': 'synthetic', 'status': 'CORROBORATED' if category.startswith('CORROBORATED') else 'CONFIRMED'}}, selected[1]))
    assert 'no_relationship_asserted' not in {b['boundary_id'] for b in approved(data)}
    with pytest.raises(ValueError):
        narrative.validate_output(response, narrative.packet(data, 'technical'), set(data['evidence']))


def test_mft_boundary_requires_mft_and_cannot_be_cited_as_claim(selected):
    data = copy.deepcopy(selected[3]['data'])
    for r in data['evidence'].values():
        r['fields']['source_type'] = 'registry'
    assert 'mft_metadata_boundary' not in {b['boundary_id'] for b in approved(data)}
    supplied = narrative.packet(selected[3]['data'], 'technical')
    result = reply(supplied)
    result['summary_paragraphs'][0]['claim_ids'].append('mft_metadata_boundary')
    with pytest.raises(ValueError):
        narrative.validate_output(result, supplied, set(selected[3]['data']['evidence']))


def test_generation_grammar_prefers_joint_prose_without_weakening_validation(selected):
    class Grammar:
        def complete(self, messages, schema):
            prop = schema['properties']['summary_paragraphs']
            assert prop['maxItems'] == 1
            for option in prop['items']['oneOf']:
                assert 'Within the selected MFT metadata' in option['properties']['text']['const']
                assert len(option['properties']['claim_ids']['const']) == 4
            return json.dumps(reply(json.loads(messages[1]['content'])))
    assert narrative.assist(selected[3]['data'], Grammar())['status'] == 'ACCEPTED'


def test_key_point_with_same_grounded_meaning_is_not_repeated(selected):
    report = assisted(selected[3])
    supplied = narrative.packet(report['data'], 'technical')
    unit = next(s for s in supplied['sentences'] if len(s['claim_ids']) == 2)
    report['narrative']['key_points'] = [{'text': unit['text'], 'claim_ids': unit['claim_ids']}]
    summary = str(section(report, 'Executive summary'))
    assert unit['text'] not in summary
    assert report['narrative']['key_points']  # Structured audit still records the return.


def test_synthesis_does_not_use_fields_whose_claim_was_omitted(selected):
    data = copy.deepcopy(selected[3]['data'])
    removed = next(c for c in data['claims'] if c['category'] == 'OBSERVED FACT'
                   and c['assertion']['field'] == '/allocated')
    data['claims'].remove(removed)
    supplied = narrative.packet(data, 'technical')
    assert not any(s.get('synthesis') for s in supplied['sentences'])
    assert all(removed['claim_id'] not in s['claim_ids'] for s in supplied['sentences'])


def test_only_limitations_never_trigger_an_invalid_model_request(selected):
    data = copy.deepcopy(selected[3]['data'])
    data['claims'] = [c for c in data['claims'] if c['category'] == 'LIMITATION']
    client = Model(lambda _: pytest.fail('No factual summary can be requested'))
    result = narrative.assist(data, client)
    assert result['status'] == 'REJECTED' and result['validation'] == 'NOT_ATTEMPTED'
    assert not client.calls


@pytest.mark.parametrize('profile', ['technical', 'executive'])
def test_limitations_render_once_with_all_narrative_provenance_retained(selected, profile):
    report = copy.deepcopy(selected[3])
    report['profile'] = profile
    data = report['data']
    supplied = narrative.packet(data, profile)
    result = reply(supplied)
    # A separate small packet exercises the limitation contract without relying
    # on whether long evidence clauses leave room in the normal prompt budget.
    units = [s for s in narrative.catalog(data) if s['category'] == 'LIMITATION'][:2]
    limits = [c for c in data['claims'] if c['category'] == 'LIMITATION']
    supplied['sentences'] += units
    supplied['claims'] += [c for c in limits if c not in supplied['claims']]
    combined = {'text': ' '.join(u['text'] for u in units),
                'claim_ids': sorted({cid for u in units for cid in u['claim_ids']})}
    result['limitations'] = [combined, {'text': units[0]['text'], 'claim_ids': units[0]['claim_ids']}]
    assert narrative.validate_output(result, supplied, set(data['evidence']))
    report['narrative'] = dict(status='ACCEPTED', **result)
    before = copy.deepcopy(report)
    for content, escape in ((render(report).decode(), esc), (markdown(report).decode(), md)):
        for item in data['limitations']:
            assert content.count(escape(item)) == 1
    assert report == before  # Suppression changes no structured provenance.
    assert report['narrative']['limitations'] == result['limitations']


@pytest.mark.parametrize('profile', ['technical', 'executive'])
def test_approved_boundaries_visible_once(selected, profile):
    report = assisted(selected[3])
    report['profile'] = profile
    for b in approved(report['data']):
        assert render(report).decode().count(esc(b['text'])) == 1
        assert markdown(report).decode().count(md(b['text'])) == 1


@pytest.mark.parametrize('profile', ['technical', 'executive'])
def test_timeline_profile_details_and_meanings(selected, profile):
    report = copy.deepcopy(selected[3])
    report['profile'] = profile
    original = copy.deepcopy(report['data']['timeline'])
    for output, escape in ((render(report).decode(), esc), (markdown(report).decode(), md)):
        assert 'MFT SI Created' in output and 'MFT FN Created' in output
        assert 'Timestamps do not imply execution or causality.' in output
        if profile == 'technical':
            assert 'Original value' in output and 'Normalization' in output
            assert all(escape(t['slot']) in output for t in original)
            assert all(escape(t['original_value']) in output for t in original)
        else:
            assert 'Time observations' in output
            for token in ('Original value', 'Precision', 'precision_ns', 'Claim provenance', 'Slot'):
                assert token not in output
            assert all(escape(t['slot']) not in output for t in original)
            assert all(escape(t['original_value']) not in output for t in original)
    assert report['data']['timeline'] == original


@pytest.mark.parametrize('metadata', [{}, {'analyst_name': 'Synthetic Analyst', 'title': 'Synthetic report'}])
def test_empty_metadata_is_omitted_supplied_metadata_preserved(selected, metadata):
    report = copy.deepcopy(selected[3])
    report['data']['analyst_metadata'] = metadata
    tables = [b for b in section(report, 'Scope and analyst metadata')['blocks'] if b[0] == 'table']
    assert bool(tables) == bool(metadata)
    assert all(b[1][1] for b in tables)
    if metadata:
        assert 'Synthetic Analyst' in render(report).decode()
        assert 'Synthetic Analyst' in markdown(report).decode()


def test_compact_references_preserve_primary_fields_and_conflicts(selected):
    report = copy.deepcopy(selected[3])
    r = next(iter(report['data']['evidence'].values()))
    r['context']['source_assertions'] = [dict(display_name='Synthetic source', hostname='host-a',
        username='analyst-a', volume_root='C:', assertion_id=314159, source_id='src-hidden',
        creation_basis='fixture-hidden', supersedes=None, updated_utc='hidden-time')]
    r['context']['conflicts'] = ['hostname']
    before = copy.deepcopy(report)
    technical = str(section(report, 'Evidence references'))
    for term in (r['id'], r['source']['sha256'], r['source']['parser'], 'Parser version',
                 'Extractor version', 'Locator / Offset', 'Locator / Length', 'Synthetic source',
                 'host-a', 'analyst-a', 'C:', 'Warnings', 'Context conflicts'):
        assert term in technical
    for term in ('314159', 'src-hidden', 'fixture-hidden', 'hidden-time', 'Supersedes'):
        assert term not in technical
    assert report == before
    report['profile'] = 'executive'
    executive = str(section(report, 'Evidence references'))
    assert len(executive) < len(technical)
    assert r['id'] in executive and r['source']['sha256'] in executive and 'Artifact' in executive
    assert 'Parser version' not in executive and 'Synthetic source' not in executive


@pytest.mark.parametrize('profile', ['technical', 'executive'])
def test_compact_ai_provenance_and_same_view_semantics(selected, profile):
    report = assisted(selected[3])
    report['profile'] = profile
    report['narrative']['model_metadata'] = {'model': 'synthetic-model'}
    original = copy.deepcopy(report)
    disclosure = str(section(report, 'AI disclosure and integrity'))
    for required in ('Accepted', 'synthetic-model', 'Pass', 'no tools'):
        assert required in disclosure
    for forbidden in ('CLM:', 'Prompt bytes', 'Prompt sha256', 'Claim order'):
        assert forbidden not in disclosure
    assert ('Contract' in disclosure) == (profile == 'technical')
    assert ('Thinking' in disclosure) == (profile == 'technical')
    html, markdown_text = render(report).decode(), markdown(report).decode()
    for sec in view.build(report)['sections']:
        assert esc(sec['title']) in html and md(sec['title']) in markdown_text
        for block, body in sec['blocks']:
            scalars = [body] if block in ('paragraph', 'heading') else body if block == 'bullets' else []
            if block == 'table':
                scalars = [*body[0], *(cell for row in body[1] for cell in row)]
            for value in scalars:
                assert esc(value) in html and md(value) in markdown_text
    assert report == original


def test_new_bundle_provenance_and_grounding(selected, tmp_path):
    case, ids, _, baseline, _ = selected
    client = Model(lambda messages: json.dumps(reply(json.loads(messages[1]['content']))))
    client.last_metadata = {'model': 'synthetic-model', 'usage': {'total_tokens': 234}}
    output = tmp_path / 'joint'
    bundle.generate(case, output, evidence_ids=ids, narrative_client=client)
    report, manifest = bundle.inspect(output)
    assert report['presentation_format'] == 3
    assert report['data'] == baseline['data']
    assert report['narrative'] == manifest['narrative']
    assert report['narrative']['summary_paragraphs'][0]['boundary_ids']
    assert report['narrative']['prompt_sha256'] and report['narrative']['prompt_bytes'] <= 5600
    assert report['narrative']['model_metadata']['usage']['total_tokens'] == 234
    result = bundle.validate(output, case=case)
    assert all(result[k] == 'PASS' for k in ('file_integrity', 'structure', 'case_fingerprint', 'evidence_grounding'))
    assert result['conclusions_truth'] == 'NOT_ESTABLISHED'


@pytest.mark.parametrize('with_narrative', [False, True])
@pytest.mark.parametrize('profile', ['technical', 'executive'])
def test_format_two_bundle_keeps_original_render_and_contract(selected, tmp_path, profile, with_narrative):
    report = copy.deepcopy(selected[3])
    report.update(presentation_format=2, profile=profile, application_version='6.40')
    if with_narrative:
        def old_reply(messages):
            unit = json.loads(messages[1]['content'])['sentences'][0]
            return json.dumps(dict(summary_paragraphs=[{'text': unit['text'], 'claim_ids': unit['claim_ids']}],
                                   key_points=[], limitations=[]))
        report['narrative'] = narrative_v2.assist(report['data'], Model(old_reply), profile)
    assert bundle.structure(report)
    from forensic_assistant.reporting import view_v2
    assert view.build(report) == view_v2.build(report)
    assert b'Original value' in markdown(report)  # Historical executive layout is preserved too.
    manifest = copy.deepcopy(selected[4])
    manifest.update(application_version='6.40', profile=profile, narrative=report['narrative'])
    payloads = {'report.json': canonical(report), 'report.html': render(report), 'report.md': markdown(report)}
    manifest['outputs'] = {name: hashlib.sha256(raw).hexdigest() for name, raw in payloads.items()}
    payloads['manifest.json'] = canonical(manifest)
    output = tmp_path / 'historical'
    output.mkdir()
    rehash(output, payloads)
    assert bundle.validate(output, case=selected[0])['evidence_grounding'] == 'PASS'

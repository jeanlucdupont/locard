"""Synthetic evidence; real collection, publication and grounding validation."""
import copy
import hashlib
import json

import pytest

from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.cli import build_parser, dispatch, main
from forensic_assistant.database.db import connect
from forensic_assistant.reporting import bundle, narrative, view
from forensic_assistant.reporting.collect import build
from forensic_assistant.reporting.model import canonical, claim, graph
from forensic_assistant.reporting.render import render, markdown
from test_v5_narrative import Model
from v2_fixtures import mft_file, mft_record


@pytest.fixture(scope='module')
def selected(tmp_path_factory):
    root = tmp_path_factory.mktemp('synthetic-reports')
    case = root / 'case.db'
    source = mft_file(root / 'synthetic-mft', names=('coreupdater.exe',))
    with source.open('ab') as stream:
        stream.write(mft_record(number=7, sequence=2, names=('loot.zip',), allocated=False))
    db = connect(case)
    ingest_artifact(db, source, 'mft')
    ids = [r[0] for r in db.execute('SELECT evidence_id FROM mft_records WHERE record_number IN (6,7) ORDER BY record_number')]
    db.close()
    bundle.generate(case, root / 'technical', evidence_ids=ids)
    report, manifest = bundle.inspect(root / 'technical')
    return case, ids, root, report, manifest


def valid_reply(messages):
    packet = json.loads(messages[1]['content'])
    units = [s for s in packet['sentences'] if s['category'] == 'OBSERVED FACT']
    # Choose one phrasing for each set of supporting claims, then compose prose.
    chosen = list({tuple(s['claim_ids']): s for s in units}.values())[:2]
    return json.dumps({'summary_paragraphs': [{'text': ' '.join(s['text'] for s in chosen),
        'claim_ids': sorted({cid for s in chosen for cid in s['claim_ids']})}],
        'key_points': [], 'limitations': []})


def test_human_summary_and_structured_preservation(selected):
    case, ids, root, report, manifest = selected
    data = report['data']
    assert data == build(case, evidence_ids=ids)
    html = (root / 'technical/report.html').read_text(encoding='utf-8')
    summary = html.split('<h2>Executive summary</h2>')[1].split('</section>')[0]
    assert '2 explicit evidence records' in summary
    assert 'coreupdater.exe' in summary and 'loot.zip' in summary
    assert 'an allocated MFT record' in summary and 'an unallocated MFT record' in summary
    for raw in ('/objects/0', '/timestamps/0/precision_ns', 'CLM:', 'precision_ns', '{"', '[{'):
        assert raw not in summary
    assert 'do not establish execution' in summary
    assert 'No relationship between the selected records is asserted' in summary
    assert 'No complete investigation' in html
    assert 'Empty categories are not investigative negative results.' in html
    assert 'No deterministic relationship claims within the selected report scope.' in html
    assert all(eid in html for eid in ids)
    assert 'MFT SI Created' in html and 'MFT FN Created' in html
    assert data['graph'] == graph(data['claims'], data['evidence'])
    assert manifest['claim_evidence_graph'] == data['graph']
    assert bundle.validate(root / 'technical', case=case)['evidence_grounding'] == 'PASS'


def test_readable_provenance_and_accurate_omissions(selected):
    _, _, root, report, _ = selected
    html = (root / 'technical/report.html').read_text(encoding='utf-8')
    assert 'dissect.ntfs' in html and 'Extractor version' in html and 'SHA-256' in html
    assert 'Locator' in html and 'Offset' in html
    for raw in ('{"items"', '{&quot;', '[{', '/objects/0', 'claim_order'):
        assert raw not in html
    assert all(not r['warnings'] for r in report['data']['evidence'].values())
    assert all('parser warnings' not in item for item in report['data']['limitations'])
    assert all('compact-field omissions' in item for item in report['data']['limitations'])
    assert 'Compact projection has omissions/truncation' not in html
    assert 'Timestamp observations' in html and 'Normalization' in html


def test_same_view_both_formats_and_profile_only_presentation(selected, tmp_path):
    case, ids, _, report, _ = selected
    before = copy.deepcopy(report)
    model = view.build(report)
    html, md = render(report).decode(), markdown(report).decode()
    from forensic_assistant.reporting.render import esc, md as escape_md
    for section in model['sections']:
        assert esc(section['title']) in html and escape_md(section['title']) in md
        for kind, body in section['blocks']:
            if kind == 'paragraph':
                assert esc(body) in html and escape_md(body) in md
    assert report == before
    bundle.generate(case, tmp_path / 'executive', evidence_ids=ids, profile='executive')
    executive = bundle.inspect(tmp_path / 'executive')[0]
    assert executive['data'] == report['data']
    assert len(render(executive)) < len(render(report))
    assert all(eid in markdown(executive).decode() for eid in ids)


def test_narrative_actual_prose_preserves_claims_and_metadata(selected, tmp_path):
    case, ids, _, deterministic, _ = selected
    client = Model(valid_reply)
    client.last_metadata = {'model': 'synthetic-model', 'usage': {'total_tokens': 123}, 'identity_basis': 'Synthetic'}
    before = case.read_bytes()
    bundle.generate(case, tmp_path / 'report', evidence_ids=ids, narrative_client=client)
    report, manifest = bundle.inspect(tmp_path / 'report')
    result = report['narrative']
    assert result['status'] == 'ACCEPTED' and result['validation'] == 'PASS'
    assert result['summary_paragraphs'] and 'MFT record' in result['summary_paragraphs'][0]['text']
    assert len(result['summary_paragraphs'][0]['claim_ids']) >= 4
    assert result['configuration']['contract'] == narrative.CONTRACT
    assert 'Claim ordering only' not in canonical(result).decode()
    assert result['prompt_bytes'] <= 5600 and len(result['prompt_sha256']) == 64
    assert result['model_metadata']['usage']['total_tokens'] == 123
    assert manifest['narrative'] == result and report['data'] == deterministic['data']
    assert case.read_bytes() == before
    assert bundle.validate(tmp_path / 'report', case=case)['evidence_grounding'] == 'PASS'


@pytest.mark.parametrize('attack', ['unknown_claim', 'unknown_evidence', 'uncited', 'unsupported',
    'extra_category', 'tool', 'shape', 'oversized', 'duplicate_key', 'wrong_citation', 'wrong_section'])
def test_narrative_rejects_unsupported_prose_and_metadata(selected, attack):
    data = selected[3]['data']
    def response(messages):
        result = json.loads(valid_reply(messages))
        item = result['summary_paragraphs'][0]
        if attack == 'unknown_claim':
            item['claim_ids'] = ['CLM:' + 'f' * 64]
        elif attack == 'unknown_evidence':
            item['text'] += ' MFT:' + 'f' * 64 + ':Offset:1'
        elif attack == 'uncited':
            item['claim_ids'] = []
        elif attack == 'unsupported':
            item['text'] = 'The program executed and stole credentials.'
        elif attack == 'extra_category':
            item['category'] = 'PROVEN COMPROMISE'
        elif attack == 'tool':
            result['tools'] = ['execute command']
        elif attack == 'shape':
            result['summary_paragraphs'] = 'arbitrary prose'
        elif attack == 'oversized':
            return 'x' * 8193
        elif attack == 'duplicate_key':
            return '{"summary_paragraphs":[],"summary_paragraphs":[]}'
        elif attack == 'wrong_citation':
            item['claim_ids'] = item['claim_ids'][:1]
        elif attack == 'wrong_section':
            result['limitations'] = [item]
        return json.dumps(result)
    result = narrative.assist(data, Model(response))
    assert result['status'] == 'REJECTED'
    assert all(result[k] == [] for k in narrative.SECTIONS)
    assert 'stole credentials' not in canonical(result).decode()


@pytest.mark.parametrize('failure', ['reject', 'unavailable'])
def test_failed_narrative_publishes_deterministic_fallback(selected, tmp_path, failure):
    case, ids, _, _, _ = selected
    def response(_):
        if failure == 'unavailable':
            raise RuntimeError('sensitive synthetic transport diagnostic')
        return '{"summary_paragraphs":[{"text":"Executed malware","claim_ids":[]}],"key_points":[],"limitations":[]}'
    bundle.generate(case, tmp_path / 'fallback', evidence_ids=ids, narrative_client=Model(response))
    report, _ = bundle.inspect(tmp_path / 'fallback')
    assert report['narrative']['status'] == ('REJECTED' if failure == 'reject' else 'FAILED')
    assert report['data']['status'] == 'COMPLETE_WITH_LIMITATIONS'
    html = render(report).decode()
    assert 'an allocated MFT record' in html and 'Executed malware' not in html
    assert 'sensitive synthetic' not in html
    assert bundle.validate(tmp_path / 'fallback', case=case)['evidence_grounding'] == 'PASS'


def rehash(directory, payloads):
    payloads['checksums.sha256'] = ''.join(hashlib.sha256(raw).hexdigest() + '  ' + name + '\n'
        for name, raw in sorted(payloads.items()) if name != 'checksums.sha256').encode()
    for name, raw in payloads.items():
        (directory / name).write_bytes(raw)


@pytest.mark.parametrize('rehash_files', [False, True])
def test_markdown_tampering_cannot_pass_validation(selected, tmp_path, rehash_files):
    import shutil
    source = selected[2] / 'technical'
    target = tmp_path / 'report'
    shutil.copytree(source, target)
    payloads = bundle.read_payloads(target)
    manifest = json.loads(payloads['manifest.json'])
    assert 'report.md' in manifest['outputs'] and b'report.md' in payloads['checksums.sha256']
    payloads['report.md'] += b'\nUnsupported execution conclusion'
    if rehash_files:
        manifest['outputs']['report.md'] = hashlib.sha256(payloads['report.md']).hexdigest()
        payloads['manifest.json'] = canonical(manifest)
        rehash(target, payloads)
    else:
        (target / 'report.md').write_bytes(payloads['report.md'])
    result = bundle.validate(target)
    assert result['structure' if rehash_files else 'file_integrity'] == 'FAIL'


def test_legacy_bundle_still_validates(selected, tmp_path):
    case, ids, _, current, _ = selected
    report = copy.deepcopy(current)
    del report['presentation_format']
    report['data'] = build(case, evidence_ids=ids, _legacy_limitations=True)
    from forensic_assistant.reporting.model import digest
    manifest = copy.deepcopy(selected[4])
    data = report['data']
    manifest.update(deterministic_sha256=digest(data), claim_ids=[c['claim_id'] for c in data['claims']], claim_evidence_graph=data['graph'])
    payloads = {'report.json': canonical(report), 'report.html': render(report)}
    manifest['outputs'] = {name: hashlib.sha256(raw).hexdigest() for name, raw in payloads.items()}
    payloads['manifest.json'] = canonical(manifest)
    target = tmp_path / 'legacy'
    target.mkdir()
    rehash(target, payloads)
    assert bundle.validate(target, case=case)['evidence_grounding'] == 'PASS'


@pytest.mark.parametrize('interactive,explicit_json', [(True, False), (True, True), (False, False)])
def test_generation_cli_contract(selected, tmp_path, capsys, interactive, explicit_json):
    case, ids, _, _, _ = selected
    directory = tmp_path / 'report with spaces'
    args = build_parser(interactive=interactive).parse_args(['--db', str(case), 'report', 'generate',
        '--evidence', ids[0], '--output', str(directory)] + (['--json'] if explicit_json else []))
    assert dispatch(args) == 0
    output = capsys.readouterr().out
    if not interactive or explicit_json:
        assert json.loads(output)['output'] == str(directory)
    else:
        assert 'Directory:' in output and 'report.md' in output
        assert f'report show "{directory}"' in output and '1 explicit evidence records' in output
    assert main(['report', 'show', str(directory)]) == 0
    assert json.loads(capsys.readouterr().out)['claim_count'] > 0


def test_missing_parent_and_id_lookup_are_actionable(selected, tmp_path, capsys):
    case, ids, _, _, _ = selected
    parent = tmp_path / 'missing parent'
    words = ['--db', str(case), 'report', 'generate', '--evidence', ids[0], '--output', str(parent / 'report')]
    assert dispatch(build_parser(interactive=True).parse_args(words)) == 2
    human = capsys.readouterr().out
    assert str(parent) in human and 'Create the parent directory first' in human
    assert not parent.exists()
    assert main(words) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'FAILED'
    assert main(['report', 'show', 'f' * 32]) == 2
    assert 'not a report ID' in json.loads(capsys.readouterr().out)['error']


def test_hostile_markup_and_controls_stay_data(selected):
    report = copy.deepcopy(selected[3])
    report['data']['analyst_metadata']['title'] = '<script>alert(1)</script> ![x](https://invalid.example)\x1b[31m'
    html, md = render(report).decode(), markdown(report).decode()
    assert '<script>' not in html + md and '\x1b' not in html + md
    assert '<img' not in html and '![' not in md
    assert "default-src 'none'" in html and '<script src=' not in html


def test_parser_warning_is_distinct_from_projection_omission(tmp_path):
    from v2_fixtures import registry_file
    case = tmp_path / 'registry.db'
    db = connect(case)
    ingest_artifact(db, registry_file(tmp_path / 'synthetic-hive', dirty=True), 'registry')
    eid = db.execute("SELECT evidence_id FROM evidence_records WHERE source_type='registry' ORDER BY evidence_id LIMIT 1").fetchone()[0]
    db.close()
    data = build(case, evidence_ids=[eid])
    assert data['evidence'][eid]['warnings']
    assert any('has parser warnings' in line for line in data['limitations'])
    assert not any('warnings or compact-field' in line for line in data['limitations'])


@pytest.mark.parametrize('legacy', [False, True])
def test_redaction_omissions_are_accurate_and_historical_projection_preserved(selected, legacy):
    from forensic_assistant.reporting.redact import apply
    case, ids, _, _, _ = selected
    data = build(case, evidence_ids=ids, _legacy_limitations=legacy)
    redacted = apply(data, 'identifiers', legacy_limitations=legacy)
    if legacy:
        assert '2 records have compact-field omissions or parser warnings.' in redacted['limitations']
    else:
        assert '2 records have compact-field omissions.' in redacted['limitations']
        assert all('parser warnings' not in line for line in redacted['limitations'])


def test_generation_schema_constrains_text_and_citations_together(selected):
    class GrammarModel:
        def complete(self, messages, schema):
            options = schema['properties']['summary_paragraphs']['items']['oneOf']
            assert options and all('const' in option['properties']['text'] for option in options)
            assert all('const' in option['properties']['claim_ids'] for option in options)
            return valid_reply(messages)
    assert narrative.assist(selected[3]['data'], GrammarModel())['status'] == 'ACCEPTED'


def test_live_partial_summary_keeps_other_selected_records_visible(selected):
    report = copy.deepcopy(selected[3])
    def one(messages):
        sentence = json.loads(messages[1]['content'])['sentences'][0]
        return json.dumps({'summary_paragraphs': [{'text': sentence['text'], 'claim_ids': sentence['claim_ids']}],
                           'key_points': [], 'limitations': []})
    report['narrative'] = narrative.assist(report['data'], Model(one))
    summary = render(report).decode().split('<h2>Executive summary</h2>')[1].split('</section>')[0]
    assert 'coreupdater.exe' in summary and 'loot.zip' in summary
    assert 'Additional selected observations (deterministic summary)' in summary

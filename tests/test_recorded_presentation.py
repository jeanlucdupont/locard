"""Presentation checks; source authority regressions live in test_recorded_reporting."""
from copy import deepcopy
from html.parser import HTMLParser
import json

import pytest
from test_recorded_reporting import source, projection, no_provider
from forensic_assistant.reporting import recorded as r, recorded_model as m, recorded_view as v, recorded_view_v1
from forensic_assistant.reporting.model import canonical, digest, loads


class HTML(HTMLParser):
    def __init__(self, raw):
        super().__init__()
        self.ids, self.links, self.tags = [], [], []
        self.feed(raw)
    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for name, value in attrs:
            if name == 'id': self.ids.append(value)
            if name == 'href': self.links.append(value)
            assert not name.startswith('on')
            assert name not in ('src', 'action')


def profile(p, name):
    p = deepcopy(p)
    p['content']['report_type'] = name
    p['content_digest'] = digest(p['content'])
    return p


@pytest.mark.parametrize('name', m.TYPES)
def test_navigation_canonical_roundtrip(projection, name):
    p = profile(projection, name)
    original = deepcopy(p)
    raw = r.render_html(p)
    assert raw == r.render_html(loads(canonical(p)))
    assert p == original
    parsed = HTML(raw.decode())
    assert len(parsed.ids) == len(set(parsed.ids))
    assert parsed.links and all(x.startswith('#') and x[1:] in parsed.ids for x in parsed.links)
    assert not set(parsed.tags) & {'script', 'img', 'iframe', 'details', 'dl'}
    assert '@media print' in raw.decode()


def test_profiles_and_s3(projection):
    before = deepcopy(projection['content']['original_assessment'])
    views = {name: r.render_view(profile(projection, name)) for name in m.TYPES}
    assert len({tuple(s['id'] for s in view) for view in views.values()}) == 3
    executive = {s['id']: s for s in views['executive']}
    technical = {s['id']: s for s in views['technical']}
    assert not any(x['kind'] == 'card' for x in executive['observations']['items'])
    assert any(x['kind'] == 'card' for x in technical['observations']['items'])
    assert len(json.dumps(executive['assessment'])) < len(json.dumps(before))
    assert projection['content']['original_assessment'] == before
    assert 'No accepted findings' in json.dumps(executive)
    assert 'No defensible importance ranking' in json.dumps(executive)


def test_exact_questions_only(projection):
    # Test display equality directly; this is not an importer or authority validator.
    c = deepcopy(projection['content'])
    c['report_type'] = 'handover'
    c['factual']['unresolved_questions'] = ['Was it executed?', 'Was it executed?', 'Was it executed here?', 'Whether the']
    c['explanation_pages'] = []
    result = next(s for s in v._sections(c) if s['id'] == 'questions')
    rows = [dict(x['rows']) for x in result['items'] if x['kind'] == 'card']
    assert [r['Text'] for r in rows] == ['Was it executed?', 'Was it executed here?', 'Whether the']
    assert rows[0]['Occurrences'] == 2
    assert c['factual']['unresolved_questions'].count('Was it executed?') == 2


def test_qualification_applicability_and_full_support(projection):
    p = profile(projection, 'technical')
    sections = {s['id']: s for s in r.render_view(p)}
    notes = {item['id']: dict(item['rows'])['Original qualification'] for item in sections['qualifications']['items']}
    rows = [item for item in sections['observations']['items'] if item['kind'] == 'card']
    for clause, row in zip(sorted(p['content']['factual']['clauses'], key=lambda c: c['id']), rows):
        refs = dict(row['rows'])['Qualifications']
        assert [notes[ref['target']] for ref in refs] == clause['qualifications']
    raw = r.render_html(p).decode()
    import html
    for leaf in p['content']['supports'].values():
        assert html.escape(leaf['evidence_id'], quote=True) in raw
        assert html.escape(leaf['field']['pointer'], quote=True) in raw
    relation_rows = [item for item in sections['relationships']['items'] if item['kind'] == 'card']
    assert relation_rows
    assert all(all(isinstance(x, v.Reference) for x in dict(row['rows'])['Original observations']) for row in relation_rows)


def test_legacy_bundle_revalidation(tmp_path, source, projection):
    generation = dict(projection['generation'], renderer_version='recorded-html-v1', application_version='6.135')
    legacy = r.build(source[0], source[1], generation=generation)
    assert legacy['content']['policy'] == m.LEGACY_POLICY
    assert r.render_html(legacy) == recorded_view_v1.render(legacy)
    out = tmp_path/'old'
    r.publish(source[0], source[1], out, generation=generation)
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    assert r.inspect(out)['source_binding'] == 'NOT_CHECKED'
    assert r.revalidate(out, source[0], source[1])['evidence_grounding'] == 'PASS'
    assert before == {p.name: p.read_bytes() for p in out.iterdir()}
    fresh = r.build(source[0], source[1], generation=dict(generation, renderer_version=m.RENDERER))
    old_content, new_content = deepcopy(legacy['content']), deepcopy(fresh['content'])
    old_content.pop('policy'); new_content.pop('policy')
    assert old_content == new_content
    assert legacy['content_digest'] != fresh['content_digest']


def test_renderer_only_change_does_not_mutate_digest(projection, monkeypatch):
    before = deepcopy(projection)
    original = v.render(projection)
    monkeypatch.setattr(v, 'text', lambda value: 'Presentation '+str(value) if value is None else original_text(value))
    changed = v.render(projection)
    assert projection == before
    assert original != changed


original_text = v.text


def test_evidence_cannot_create_active_link(projection):
    from unittest.mock import patch
    blocks = [dict(id='safe', title='<script>test</script>', items=[dict(kind='card', id='safe-card', title='" onclick="bad', rows=[
        ('Original value', [{'target': 'safe', 'text': 'forged'}]),
        ('Unicode path', 'C:\\証拠\\'+('字'*1000)), ('Dangerous text', 'file:///secret javascript:evil <img src=x>')])])]
    with patch.object(v, 'view', return_value=blocks):
        raw = v.render(projection).decode()
    parsed = HTML(raw)
    assert parsed.links == ['#safe']
    assert '&lt;script&gt;' in raw and '&lt;img' in raw
    assert '字'*1000 in raw

@pytest.mark.parametrize('renderer', ['unknown-renderer', [], None])
def test_unknown_renderer_rejected(projection, renderer):
    p = deepcopy(projection)
    p['generation']['renderer_version'] = renderer
    with pytest.raises(ValueError, match='RENDERER'):
        r.validate_projection(p)


def test_distinct_qualifications_not_merged(projection):
    c = deepcopy(projection['content'])
    c['original_assessment']['limitations'] = ['Clock uncertain.', 'Clock uncertain.', 'Clock is uncertain.']
    sections = {s['id']: s for s in v._sections(c)}
    notes = [dict(item['rows'])['Original qualification'] for item in sections['qualifications']['items']]
    assert notes.count('Clock uncertain.') == 1
    assert notes.count('Clock is uncertain.') == 1


def test_finding_contrary_and_decision_navigation(tmp_path, source):
    from forensic_assistant.investigation_ai import findings as f
    from test_findings import refs
    w = f.create(tmp_path/'links.findings', source[0], source[1], actor='Synthetic')
    references = refs(source)
    fid = w.register(actor='Synthetic', expected_revision=0, kind='analyst_hypothesis',
                     statement='Synthetic competing explanation.', supporting_ids=references[:1], contrary_ids=references[1:2])
    w.review(fid, 'reject', actor='Synthetic', expected_revision=1)
    p = r.build(source[0], source[1], workspace=w.directory, report_type='handover')
    sections = {s['id']: s for s in r.render_view(p)}
    finding = next(x for x in sections['findings']['items'] if x['kind'] == 'card')
    rows = dict(finding['rows'])
    assert rows['Support'] and rows['Contrary']
    assert all(isinstance(x, v.Reference) for x in rows['Support']+rows['Contrary'])
    decision = sections['decisions']['items'][-1]
    assert dict(decision['rows'])['Finding'][0]['target'] == finding['id']
    parsed = HTML(r.render_html(p).decode())
    assert all(x[1:] in parsed.ids for x in parsed.links)

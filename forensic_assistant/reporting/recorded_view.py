"""Versioned, inert audience views over the unchanged validated projection."""
import html
import json
from collections import Counter

from . import recorded_model as m
from . import recorded_view_v1


class Reference(dict):
    """Application-created navigation, never recognized by shape in source data."""


def text(value):
    if value is None:
        return 'Not recorded / unknown'
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)


def view(projection):
    m.validate(projection)
    if projection['generation']['renderer_version'] == 'recorded-html-v1':
        return recorded_view_v1.view(projection)
    return _sections(projection['content'])


def _sections(c):
    """Presentation only. No evidence retrieval, assessment or relevance inference."""
    from forensic_assistant.investigation_ai.explanation import _fact_text
    sections = {}
    def section(key, title):
        sections[key] = dict(id=key, title=title, items=[])
        return sections[key]['items']
    def paragraph(items, value):
        items.append(dict(kind='paragraph', text=text(value)))
    def card(items, anchor, title, rows):
        items.append(dict(kind='card', id=anchor, title=title, rows=rows))
    def link(anchor, label):
        return Reference(target=anchor, text=label)

    clauses = {x['id']: x for x in c['factual']['clauses']}
    relations = {x['id']: x for x in c['related']['relationships']}
    workspace = c['workspace']
    findings = sorted(workspace['findings'], key=lambda x: (x['creation_revision'], x['id'])) if workspace else []
    selected = [f for f in findings if f['state'] == 'accepted'] if c['report_type'] == 'executive' else findings
    ids = {}
    for prefix, values in [('o', sorted(clauses)), ('r', sorted(relations)), ('f', [f['id'] for f in findings])]:
        ids.update({identity: (prefix+'-'+str(i), prefix.upper()+str(i)) for i, identity in enumerate(values, 1)})
    requested = set()
    def refs(values):
        result = []
        for value in values:
            if value in ids:
                requested.add(value)
                result.append(link(*ids[value]))
            else:
                result.append(text(value))
        return result
    notes = {}
    def qualifications(values):
        result = []
        for value in values:
            value = text(value)
            if value not in notes:
                notes[value] = 'q-'+str(len(notes)+1)
            result.append(link(notes[value], 'Q'+notes[value].split('-')[1]))
        return result
    overview = section('overview', 'Investigation overview and current state')
    paragraph(overview, c['question'])
    card(overview, 'scope', 'Recorded scope', [
        ('Original S3 status', c['original_assessment']['status']),
        ('Source validation', c['validation']), ('Recorded termination and cleanup boundary', c['execution']),
        ('Workspace', dict(id=workspace['metadata']['id'], revision=workspace['revision']) if workspace else 'No attached analyst-reviewed findings workspace.'),
        ('Finding states', dict(Counter(f['state'] for f in findings)))])
    paragraph(overview, c['caution'])
    paragraph(overview, 'Presentation scope: this audience view is not exhaustive evidence disclosure. Complete unchanged validated source material, original S3 and support dependencies remain in projection.json. Displayed values are not clipped. No new ranking or conclusions are inferred.')
    assessment = section('assessment', 'Original S3 assessment')
    for i, p in enumerate(c['original_assessment']['propositions'], 1):
        rows = [(k.replace('_', ' ').capitalize(), p[k]) for k in ('text', 'type', 'status', 'support_search', 'new_evidence_search', 'unassessed_candidates', 'incomplete_support_candidates') if k in p]
        for k in ('direct_clauses', 'direct_relationships', 'contradictory_clauses', 'contradictory_relationships', 'conflicting_supports'):
            rows.append((k.replace('_', ' ').capitalize(), refs(p.get(k, []))))
        rows.append(('Assessment gaps', qualifications(p.get('gaps', []))))
        rows.append(('Contextual support retained', str(len(p.get('contextual_clauses', [])))+' clauses; '+str(len(p.get('contextual_relationships', [])))+' relationships (context is not a direct answer).'))
        card(assessment, 's3-'+str(i), 'Recorded proposition '+str(i), rows)
    paragraph(assessment, 'Original assessment is unchanged. Contextual candidates and full registered arguments remain in projection.json; they are not promoted to direct support.')
    reviewed = section('findings', 'Analyst findings and reviewed conclusions')
    if not any(f['state'] == 'accepted' for f in findings):
        paragraph(reviewed, 'No accepted findings recorded. This is not absence of original observations or suspicious activity.')
    shown = set(clauses) if c['report_type'] == 'technical' else set()
    shown_rel = set(relations) if c['report_type'] == 'technical' else set()
    appendix_leaves = dict(c['supports'])
    required_leaves = set(c['supports']) if c['report_type'] == 'technical' else set()
    actions = section('actions', 'Proposed examinations — not performed')
    for f in selected:
        candidate = f['candidate']
        rows = [(k.replace('_', ' ').capitalize(), candidate[k]) for k in ('origin', 'assertion_authority', 'statement', 'explanation')]
        rows += [('Review state', f['state']), ('Analyst classification', f['reviewed_classification']),
                 ('Support', refs(candidate['supporting_ids'])), ('Contrary', refs(candidate['contrary_ids'])),
                 ('Qualifications', qualifications(candidate['limitations'])),
                 ('Replaces', refs([f['replaces']]) if f['replaces'] else []),
                 ('Superseded by', refs([f['superseded_by']]) if f['superseded_by'] else [])]
        if candidate['ai']:
            rows.append(('AI proposal — unverified, including alternatives', candidate['ai']['validated']))
        for label in ('support', 'contrary'):
            for bundle in candidate[label]:
                shown.update(x for x in bundle['clauses'] if x in clauses)
                shown_rel.update(x['id'] for x in bundle['relationships'] if x['id'] in relations)
                rows.append((label.title()+' mandatory qualifications', qualifications(bundle['qualifications'])))
                for leaf in bundle['leaves']:
                    # Original bundles retain their own view and full source dependencies.
                    leaf = dict(leaf, view=c['view'])
                    key = m.digest(leaf)
                    appendix_leaves[key] = leaf
                    required_leaves.add(key)
        title = 'Historical inactive finding' if f['state'] in ('rejected', 'superseded') else 'Analyst finding'
        card(reviewed, ids[f['id']][0], ids[f['id']][1]+' — '+title+' — '+f['state'], rows)
        if candidate['recommendations']:
            card(actions, 'action-'+ids[f['id']][0], 'Recorded unexecuted examinations', [('Finding', refs([f['id']])), ('Recommendations', candidate['recommendations']), ('Availability', 'Unknown; no execution or authorization implied.')])
    for cid in shown:
        required_leaves.update(c['units'][cid]['support_refs'])
    pids = {key: ('p-'+str(i), 'P'+str(i)) for i, key in enumerate(sorted(appendix_leaves), 1)}
    observations = section('observations', 'Recorded evidence overview and observations')
    paragraph(observations, dict(Counter(x['supports'][0]['source_type'] for x in clauses.values())))
    if not clauses:
        paragraph(observations, 'No accepted factual clauses.')
    if c['report_type'] != 'technical':
        paragraph(observations, 'Only observations referenced by displayed findings are expanded. Other observations are counted above and retained in the canonical projection. No defensible importance ranking is inferred.')
    for cid in sorted(shown):
        clause = clauses[cid]
        support = clause['supports'][0]
        card(observations, ids[cid][0], ids[cid][1]+' — '+support['source_type']+' — '+clause['type'], [
            ('Recorded assertion', _fact_text(clause)), ('Timestamp semantics', support.get('timestamp')),
            ('Qualifications', qualifications(clause['qualifications'])),
            ('Original support', [link(*pids[k]) for k in c['units'][cid]['support_refs']])])
    relationship_section = section('relationships', 'Registered relationships and qualified chronology')
    for rid in sorted(shown_rel):
        rel = relations[rid]
        card(relationship_section, ids[rid][0], ids[rid][1]+' — '+rel['predicate'], [
            ('Original observations', refs(rel['endpoints'])),
            ('Registered comparison', {k: v for k, v in rel.items() if k not in ('supports', 'qualifications', 'endpoints', 'id', 'evidence_state', 'lineage')}),
            ('Qualifications', qualifications(rel['qualifications']))])
    questions = section('questions', 'Outstanding recorded questions')
    question_rows = []
    for q in c['factual']['unresolved_questions']:
        question_rows.append((q if isinstance(q, str) else q.get('text', text(q)), []))
    uncertainty = section('uncertainty', 'Material uncertainty and contrary evidence')
    card(uncertainty, 'limitations', 'Coverage and interpretation limitations', [('Qualifications', qualifications(c['factual']['limitations']+c['related']['limitations']+c['original_assessment'].get('limitations', [])))])
    context_notes = []
    for _, leaf in sorted(c['supports'].items()):
        context = leaf['source']['context']
        for key in ('warnings', 'coverage_notes', 'truncated_fields'):
            for value in context.get(key) or []:
                note = key+': '+text(value)
                if note not in context_notes:
                    context_notes.append(note)
    card(uncertainty, 'source-limitations', 'Recorded source warnings and truncation', [('Qualifications', qualifications(context_notes))])
    if c['report_type'] != 'executive' and c['factual']['hypotheses']:
        paragraph(uncertainty, 'Historical hypotheses — unverified; not forensic conclusions.')
        paragraph(uncertainty, c['factual']['hypotheses'])
    elif c['factual']['hypotheses']:
        paragraph(uncertainty, str(len(c['factual']['hypotheses']))+' historical unverified hypotheses retained in projection.json; not analyst-accepted conclusions.')
    coverage = section('coverage', 'Coverage and continuation boundaries')
    paragraph(coverage, 'Completed authorized processing is not whole-case completeness. Source revalidation can check the recorded binding, not the current case or semantic truth. No continuation is authorized by this report.')
    factual_coverage = c['factual']['coverage']
    paragraph(coverage, {k: len(factual_coverage[k]) for k in ('inspected_record_ids', 'represented_record_ids', 'inspected_not_represented')})
    paragraph(coverage, {k: factual_coverage[k] for k in ('basis', 'relevance_of_omissions')})
    paragraph(coverage, 'Coverage counts summarize recorded identifiers only. Full disclosure accounting and omitted identifier lists remain in projection.json.')
    if c['organization'] is not None:
        org = c['organization']
        paragraph(coverage, {k: v for k, v in org['coverage'].items() if type(v) in (int, bool) or k.endswith('meaning')})
        paragraph(coverage, {k: org[k] for k in ('incomplete', 'processing_stops', 'finalization')})
        card(coverage, 'organization-limitations', 'Organization limitations', [('Qualifications', qualifications(c['organization']['limitations']))])
    else:
        paragraph(coverage, 'No C1/D1 organization contract recorded; no retrospective organization is invented.')
    pages = c['explanation_pages']
    paragraph(coverage, {'explanation_pages': len(pages),
                         'pages_with_recorded_omissions': sum(bool(p['omissions']) for p in pages),
                         'assembly_limit_omitted': sum(p['assembly_limit_omitted'] for p in pages),
                         'assembly_exhausted_any_page': any(p['assembly_exhausted'] for p in pages),
                         'source_organization_incomplete': any(p['source_organization_incomplete'] for p in pages)})
    paragraph(coverage, 'Page-level omissions may repeat across pages; these are page accounting, not distinct missing-evidence totals. Exact omitted units and reasons remain in projection.json.')
    if c['report_type'] == 'technical':
        page_table = dict(kind='table', headers=['Page', 'Original counts', 'Omission entries', 'assembly_limit_omitted', 'assembly_exhausted', 'source_organization_incomplete'], rows=[])
        coverage.append(page_table)
    for i, page in enumerate(pages, 1):
        if c['report_type'] == 'technical':
            page_table['rows'].append(['Explanation page '+str(i), page['counts'], len(page['omissions']), page['assembly_limit_omitted'], page['assembly_exhausted'], page['source_organization_incomplete']])
        for j, statement in enumerate(page['statements'], 1):
            kind = statement['classification']
            if kind == 'unresolved_question':
                question_rows.append((statement['text'], statement.get('qualifications', [])))
            elif kind == 'coverage_limitation':
                card(coverage, 'explanation-'+str(i)+'-'+str(j), 'Recorded coverage limitation '+str(i)+'.'+str(j), [('Text', statement['text']), ('Qualifications', qualifications(statement.get('qualifications', [])))])
            elif kind == 'validated_relationship':
                # Current S2 relationships already have a full dedicated presentation.
                # Earlier-frontier relations stay distinguishable, never relabeled AI.
                if c['report_type'] == 'technical' and not set(statement['source_units']) <= shown_rel:
                    card(relationship_section, 'explanation-'+str(i)+'-'+str(j), 'Recorded historical relationship '+str(i)+'.'+str(j), [('Text', statement['text']), ('Qualifications', qualifications(statement.get('qualifications', []))), ('Original observations', refs(statement.get('metadata', {}).get('endpoints', [])))])
            elif kind in ('recommended_action', 'unverified_hypothesis', 'unverified_explanation'):
                target = actions if kind == 'recommended_action' else uncertainty
                if c['report_type'] != 'executive' or kind == 'recommended_action':
                    metadata = statement.get('metadata', {})
                    card(target, 'explanation-'+str(i)+'-'+str(j), 'Recorded '+kind+' '+str(i)+'.'+str(j)+' — unverified', [('Text', statement['text']), ('Alternatives', metadata.get('alternatives', [])), ('Qualifications', qualifications(statement.get('qualifications', []))), ('Reference scope', 'Any aliases in this original text are local to its source proposal, not this report. Exact mappings, binding and dependencies remain in projection.json.'), ('Original statement identity', statement['id'])])
    grouped = {}
    for value, quals in question_rows:
        row = grouped.setdefault(value, dict(count=0, qualifications=[]))
        row['count'] += 1
        row['qualifications'].extend(q for q in quals if q not in row['qualifications'])
    paragraph(questions, 'Exact text equality only is deduplicated for display. Near-duplicates and incomplete wording are retained unchanged. Recorded model text is unverified and may be incomplete; original records remain in projection.json.')
    if c['report_type'] == 'executive':
        paragraph(questions, str(len(grouped))+' distinct recorded question texts; see handover or projection.json for unresolved work.')
    else:
        for i, (value, row) in enumerate(grouped.items(), 1):
            card(questions, 'question-'+str(i), 'Recorded question '+str(i)+' — unverified wording', [('Text', value), ('Occurrences', row['count']), ('Qualifications', qualifications(row['qualifications']))])
    decisions = section('decisions', 'Analyst decisions — locally asserted identity')
    if workspace and c['report_type'] != 'executive':
        for e in workspace['history']:
            card(decisions, 'decision-'+str(e['sequence']), 'Revision '+str(e['sequence']), [
                ('Finding', refs([e['finding_id']]) if e['finding_id'] else []), ('Action', e['action']),
                ('Actor', e['actor']), ('Actor authority', e['actor_authority']), ('Time', e['timestamp']),
                ('Decision', {k: v for k, v in e['payload'].items() if k != 'candidate'})])
    appendix = section('appendix', 'Original support and provenance appendix')
    for key in sorted(required_leaves):
        leaf = appendix_leaves[key]
        card(appendix, pids[key][0], pids[key][1]+' — original support', [(k.replace('_', ' ').capitalize(), v) for k, v in sorted(leaf.items())])
    # A compact identity index keeps references resolvable without expanding unrelated
    # evidence in executive/handover. It never presents an omitted assertion as a fact.
    rendered = shown | shown_rel | {f['id'] for f in selected}
    for identity in sorted(requested-rendered):
        card(appendix, ids[identity][0], ids[identity][1]+' — retained reference', [('Original identity', identity), ('Presentation', 'Not expanded in this profile; complete original unit is retained in projection.json.')])
    if c['report_type'] == 'technical':
        card(appendix, 'provenance', 'Recorded investigation provenance', [('Source', c['source']), ('Read view', c['view']), ('Frontiers', c['frontiers'])])
    qsection = section('qualifications', 'Qualifications — exact text, linked applicability')
    for note, anchor in notes.items():
        card(qsection, anchor, 'Q'+anchor.split('-')[1], [('Original qualification', note)])
    paragraph(appendix, 'Full source data and all original identifiers remain in projection.json. Display policy: display_clipping=false. Paths and URL strings are inert text, not navigable evidence links.')
    orders = {
        'executive': 'overview findings observations assessment uncertainty actions questions relationships qualifications appendix coverage',
        'technical': 'overview assessment observations relationships findings decisions uncertainty questions actions coverage qualifications appendix',
        'handover': 'overview findings questions actions decisions assessment uncertainty coverage observations relationships qualifications appendix',
    }
    result = [sections[k] for k in orders[c['report_type']].split()]
    if sum(1+len(s['items']) for s in result) > m.MAX_BLOCKS:
        raise ValueError('RECORDED_REPORT_BLOCK_LIMIT')
    return result


def render(projection):
    if projection['generation']['renderer_version'] == 'recorded-html-v1':
        return recorded_view_v1.render(projection)
    blocks = view(projection)
    anchors = {b['id'] for b in blocks} | {item['id'] for b in blocks for item in b['items'] if item['kind'] == 'card'}
    chunks = []
    size = 0
    def write(value):
        nonlocal size
        raw = value.encode('utf-8')
        size += len(raw)
        if size > m.MAX_HTML:
            raise ValueError('RECORDED_REPORT_HTML_LIMIT')
        chunks.append(raw)
    def escape(value):
        return html.escape(text(value), quote=True)
    def cell(value):
        if isinstance(value, list) and any(isinstance(v, Reference) for v in value):
            for v in value:
                if not isinstance(v, Reference):
                    write('<span>'+escape(v)+'</span> ')
                    continue
                if v['target'] not in anchors:
                    raise ValueError('RECORDED_REPORT_REFERENCE')
                write('<a href="#'+escape(v['target'])+'">'+escape(v['text'])+'</a> ')
        else:
            write('<span>'+escape(value)+'</span>')
    title = 'Locard '+projection['content']['report_type']+' report'
    write('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+escape(title)+'</title><style>body{font:16px system-ui,sans-serif;max-width:74rem;margin:2rem auto;padding:1rem;color:#181818;background:white}h2{border-bottom:1px solid #aaa;padding-top:1rem}h3{font-size:1rem}p{max-width:75ch}table{border-collapse:collapse;width:100%;table-layout:fixed}th,td{border-bottom:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}th{width:24%}th[scope=col]{width:auto}td{font: .9rem ui-monospace,monospace}span,td,p{overflow-wrap:anywhere;white-space:pre-wrap}article{margin:1rem 0;border-left:3px solid #777;padding-left:1rem}a{color:#164478}nav ul{columns:2}a:focus{outline:2px solid} @media print{body{margin:0;font-size:10pt;max-width:none}h2,h3{break-after:avoid}tr{break-inside:avoid}nav ul{columns:1}}</style></head><body><h1>'+escape(title)+'</h1><p>Generated '+escape(projection['generation']['generated_utc'])+'</p><nav aria-label="Table of contents"><h2>Contents</h2><ul>')
    for block in blocks:
        write('<li><a href="#'+block['id']+'">'+escape(block['title'])+'</a></li>')
    write('</ul></nav>')
    for block in blocks:
        write('<section id="'+block['id']+'"><h2>'+escape(block['title'])+'</h2>')
        for item in block['items']:
            if item['kind'] == 'paragraph':
                write('<p>'+escape(item['text'])+'</p>')
            elif item['kind'] == 'table':
                write('<table><thead><tr>')
                for header in item['headers']:
                    write('<th scope="col">'+escape(header)+'</th>')
                write('</tr></thead><tbody>')
                for row in item['rows']:
                    write('<tr>')
                    for value in row:
                        write('<td>'); cell(value); write('</td>')
                    write('</tr>')
                write('</tbody></table>')
            else:
                write('<article id="'+item['id']+'"><h3>'+escape(item['title'])+'</h3><table>')
                for label, value in item['rows']:
                    write('<tr><th scope="row">'+escape(label)+'</th><td>')
                    cell(value)
                    write('</td></tr>')
                write('</table></article>')
        write('</section>')
    write('<footer>Semantic content digest: '+escape(projection['content_digest'])+'<br>Renderer: '+escape(projection['generation']['renderer_version'])+'</footer></body></html>')
    return b''.join(chunks)

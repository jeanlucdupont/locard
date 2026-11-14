"""Deterministic shared blocks and inert HTML. Never resolves evidence."""
import html
import json

from . import recorded_model as m


def view(projection):
    m.validate(projection)
    c = projection['content']
    blocks = []

    def add(title, value):
        if len(blocks) >= m.MAX_BLOCKS:
            raise ValueError('RECORDED_REPORT_BLOCK_LIMIT')
        blocks.append(dict(title=title, value=value))

    add('Investigation objective', c['question'])
    add('Authority and scope', c['caution'])
    add('Original S3 assessment — unchanged', c['original_assessment'] if c['report_type'] == 'technical' else
        {k: c['original_assessment'][k] for k in ('status', 'propositions')})
    add('Source validation', c['validation'])
    add('Recorded execution and cleanup boundary', c['execution'])
    add('Recorded investigation identity', dict(source=c['source'], view=c['view'], engine=c['engine'], frontiers=c['frontiers']))
    w = c['workspace']
    if w is None:
        add('Analyst findings', 'No attached analyst-reviewed findings workspace. Historical observations may still be present.')
        rows = []
    else:
        add('Workspace snapshot', dict(id=w['metadata']['id'], revision=w['revision'], head=w['head']))
        rows = sorted(w['findings'], key=lambda f: (f['creation_revision'], f['id']))
    accepted = [f for f in rows if f['state'] == 'accepted']
    if not accepted:
        add('Active analyst-accepted conclusions', 'No accepted findings recorded. This is not absence of original observations or suspicious activity.')
    selected = accepted if c['report_type'] == 'executive' else rows
    for finding in selected:
        candidate = finding['candidate']
        title = ('Historical inactive finding' if finding['state'] in ('rejected', 'superseded') else 'Analyst finding')
        add(title + ' — ' + finding['state'], dict(
            id=finding['id'], origin=candidate['origin'], review_state=finding['state'],
            analyst_classification=finding['reviewed_classification'],
            assertion_authority=candidate['assertion_authority'], source_validation=c['validation']['source_binding'],
            statement=candidate['statement'], explanation=candidate['explanation'],
            supporting_ids=candidate['supporting_ids'], contrary_ids=candidate['contrary_ids'],
            qualifications=candidate['limitations'], replaces=finding['replaces'], superseded_by=finding['superseded_by'],
            ai_proposal=(candidate['ai']['validated'] if candidate['ai'] else None)))
        # All mandatory support qualifications are visible, including executive.
        for label in ('support', 'contrary'):
            for bundle in candidate[label]:
                add(label.title() + ' and mandatory qualifications', dict(
                    clauses=bundle['clauses'], qualifications=bundle['qualifications'],
                    interpretations=bundle['interpretations'], relationships=bundle['relationships']))
        if candidate['recommendations']:
            add('Recommended examinations — not performed', candidate['recommendations'])
    add('Recorded observations and deterministic interpretations',
        'No accepted factual clauses.' if not c['factual']['clauses'] else
        'Original fields and qualified interpretations below; no new inference is generated.')
    from forensic_assistant.investigation_ai.explanation import _fact_text
    for clause in c['factual']['clauses']:
        add('Deterministic interpretation' if clause['type'] == 'deterministic_interpretation' else 'Recorded observation',
            dict(id=clause['id'], text=_fact_text(clause), qualifications=clause['qualifications'],
                 support_refs=c['units'][clause['id']]['support_refs']))
    add('Historical coverage and limitations', dict(factual=c['factual']['coverage'],
        relationships=c['related']['coverage'], limitations=c['factual']['limitations'] + c['related']['limitations']))
    add('Outstanding recorded questions', c['factual']['unresolved_questions'] or 'None recorded; not a whole-case assessment.')
    if c['factual']['hypotheses']:
        add('Historical hypotheses — unverified', c['factual']['hypotheses'])
    if c['organization'] is not None:
        org = c['organization']
        add('Organization coverage and completion boundary', {k: org[k] for k in
            ('coverage', 'incomplete', 'processing_stops', 'finalization', 'limitations')})
    else:
        add('Organization', 'No C1/D1 organization contract recorded for this history; no retrospective organization is invented.')
        if c['historical_proposals']:
            add('Historical model proposals — unverified, not analyst accepted', c['historical_proposals'])
    for index, page in enumerate(c['explanation_pages'], 1):
        add('Explanation page '+str(index)+' coverage (not whole-case completeness)', {k: page[k] for k in
            ('counts', 'omissions', 'assembly_limit_omitted', 'assembly_exhausted', 'source_organization_incomplete')})
        for statement in page['statements']:
            if statement['classification'] not in ('recorded_observation', 'deterministic_interpretation'):
                add('Recorded explanation — '+statement['classification'], statement)
    if c['report_type'] != 'executive':
        add('Registered relationships and qualified chronology', {k: v for k, v in c['related'].items() if k != 'factual'})
        if w is not None:
            # The verified full event chain stays in projection.json. No raw
            # provider capsule or machine-local workspace path is rendered.
            decisions = [{k: e[k] for k in ('sequence', 'timestamp', 'actor', 'actor_authority', 'action', 'finding_id', 'hash')}
                         | {'decision': {k: v for k, v in e['payload'].items() if k != 'candidate'}} for e in w['history']]
            add('Analyst decision history — locally asserted identity', decisions)
    # Exact bounded support appendix is present for every view: concision must
    # not silently discard a qualification, original value or contrary premise.
    for ref, leaf in sorted(c['supports'].items()):
        add('Original support '+ref, leaf)
    for row in selected:
        for label in ('support', 'contrary'):
            for bundle in row['candidate'][label]:
                add('Finding '+label+' original evidence appendix', bundle)
    add('Display policy', c['policy'])
    return blocks


def render(projection):
    blocks = view(projection)
    chunks = []
    size = 0

    def write(value):
        nonlocal size
        raw = value.encode('utf-8')
        size += len(raw)
        if size > m.MAX_HTML:
            raise ValueError('RECORDED_REPORT_HTML_LIMIT')
        chunks.append(raw)

    def tree(value, depth=0):
        if depth > 32:
            raise ValueError('RECORDED_REPORT_RENDER_DEPTH')
        if isinstance(value, dict):
            write('<dl>')
            for key in sorted(value):
                write('<dt>'+html.escape(key, quote=True)+'</dt><dd>')
                tree(value[key], depth+1)
                write('</dd>')
            write('</dl>')
        elif isinstance(value, list):
            write('<ol>')
            for item in value:
                write('<li>'); tree(item, depth+1); write('</li>')
            write('</ol>' if value else '</ol><p>None recorded.</p>')
        else:
            text = 'Not recorded / unknown' if value is None else value if isinstance(value, str) else json.dumps(value, allow_nan=False)
            write('<span>'+html.escape(text, quote=True)+'</span>')

    title = 'Locard '+projection['content']['report_type']+' report'
    write('<!doctype html><html lang="en"><head><meta charset="utf-8">'
          '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
          '<meta name="viewport" content="width=device-width,initial-scale=1"><title>'+html.escape(title)+'</title>'
          '<style>body{font:16px system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:1rem;color:#181818;background:white}'
          'section{border-top:1px solid #ccc;margin-top:1.4rem}h2{font-size:1.15rem}dt{font-weight:bold}dd{margin:0 0 .5rem 1rem}'
          'span,dt,dd{overflow-wrap:anywhere;white-space:pre-wrap}li{margin-bottom:.4rem}'
          '@media print{body{margin:0;max-width:none;font-size:10pt}h2{break-after:avoid}section{break-inside:auto}}</style></head><body>')
    write('<h1>'+html.escape(title)+'</h1>')
    tree(dict(generation=projection['generation'], semantic_content_sha256=projection['content_digest']))
    for i, block in enumerate(blocks):
        write('<section id="section-'+str(i)+'"><h2>'+html.escape(block['title'], quote=True)+'</h2>')
        tree(block['value'])
        write('</section>')
    write('</body></html>')
    return b''.join(chunks)

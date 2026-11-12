"""Provider-free issue explanations over the existing bounded D2 preview."""
import re
from . import d2_wire, d2_quality

TECHNICAL = {'process_name','command_line','executable','filename','path','current_path','target_path','hostname','ip','url'}


def _exact(question, field):
    value=field.get('value');pointer=field.get('pointer','')
    if not isinstance(value,str) or not value or len(value)>1024:return False
    if pointer.rsplit('/',1)[-1] not in TECHNICAL:return False
    if len(value)<3:return ('"'+value+'"') in question or ("'"+value+"'") in question
    return re.search(r'(?<!\w)'+re.escape(value)+r'(?!\w)',question) is not None


def inspect(history, preview, model):
    """Add versioned UI metadata, without changing historical packet identities."""
    history._check()
    ctx=history._ctx;question=ctx.manifest['question']
    units={c['id']:c for c in ctx.factual['clauses']}
    units.update({r['id']:r for r in ctx.related['relationships']})
    terms=set(re.findall(r'[^\W_]+',question.casefold()))
    results={r['issue_id']:r for r in preview['issue_results']}
    packets={p['content']['issue']['id']:p for p in preview['packets']}
    rows=[]
    for issue in preview['issues']:
        seeded=[units[k] for k in issue['seeds']]
        support_units=seeded+[units[e] for unit in seeded for e in unit.get('endpoints',[]) if e in units]
        fields=[s.get('field',{}) for unit in support_units for s in unit.get('supports',[])]
        exact=any(_exact(question,f) for f in fields)
        words=set(re.findall(r'[^\W_]+',' '.join(str(f.get('value','')) for f in fields).casefold()))
        lexical=sorted(t for t in terms&words if len(t)>=2)
        relevance=('verified_typed_objective' if issue['kind']=='typed_objective' and issue['binding']=='resolved_within_declared_candidates'
                   else 'exact_technical_referent' if exact else 'contextual_lexical' if lexical else 'unresolved')
        contradiction=any(u.get('predicate')=='incompatible_recorded_field' for u in seeded)
        purpose='examine_recorded_contradiction' if contradiction else issue['purpose']
        row=dict(id=issue['id'],kind=issue['kind'],purpose=purpose,source=preview['source'],recorded_view=ctx.factual['evidence_state'],
                 seeds=issue['seeds'],objective_binding=issue['binding'],relevance=relevance,
                 ranking_reasons=[relevance,'recorded_conflict' if contradiction else 'existing_kind_priority','stable_issue_id'],
                 unavailable_purposes=['missing_discriminator','unresolved_source_relationship'],
                 coverage='Only validated recorded candidates; missing discriminator/source-link issues are not inferred from unsearched evidence.',
                 selection='selected_for_preview' if issue['id'] in results else 'deferred_not_evaluated',
                 feasibility=results.get(issue['id'],{}).get('status','not_evaluated'))
        if issue['id'] in packets:
            p=packets[issue['id']];row['request_bytes']=len(d2_wire.body(d2_quality.messages(p),model,d2_quality.SCHEMA))
            row['feasibility']='fits_complete_request' if row['request_bytes']<=5600 else 'complete_request_oversized'
        rows.append(row)
    order={'verified_typed_objective':0,'exact_technical_referent':1,'contextual_lexical':2,'unresolved':3}
    kind={'typed_objective':0,'interpretation':1,'relationship':2,'recorded_fields':3}
    rows.sort(key=lambda r:(order[r['relevance']],r['purpose']!='examine_recorded_contradiction',kind[r['kind']],r['id']))
    return dict(contract='d2-issue-review-v1',issues=rows,planning_stop=preview.get('planning_stop'),
                support_resolutions=preview.get('support_resolutions'),provider_requests=0,
                selection_policy='Review order only; execution requires an explicitly selected issue and fresh authorization.')

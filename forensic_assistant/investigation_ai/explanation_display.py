"""Lossless reference projection over D1a; canonical statements are never changed."""
from copy import deepcopy
import base64
import json
from . import explanation as e

CONTRACT='explanation-display-v1'
RULES='record-grouped-display-v1'


def _check(session):
    if type(session) is not e._Session or session.seal!=session._seal():
        raise ValueError('Validated explanation session changed')


def resolve(session, statement_id):
    """Structured drill-down; source validators, not display text, own authority."""
    _check(session)
    for candidate in session.candidates[:e.MAX_STATEMENTS]:
        statement=session._statement(*candidate)
        if statement['id']==statement_id:return statement
    raise ValueError('Unknown canonical statement')


def _qualifiers(texts, legend):
    refs=[]
    for text in texts:
        key=next((key for key,value in legend.items() if value==text),'Q'+str(len(legend)+1))
        legend[key]=text;refs.append(key)
    return refs


def _record_index(session):
    ids=sorted({c['supports'][0]['evidence_id'] for c in session.clauses.values()})
    labels={eid:'R'+str(n+1) for n,eid in enumerate(ids)}
    contexts={}
    for c in sorted(session.clauses.values(),key=lambda c:c['id']):
        s=c['supports'][0];f=s.get('field',{});pointer=f.get('pointer','')
        if pointer in ('/target_path','/current_path','/executable') or pointer.startswith('/objects/'):
            contexts.setdefault(s['evidence_id'],c)
    return labels,contexts


def _add_record(session,eid,labels,contexts,page):
    key=labels.get(eid)
    if key is None:
        # Record-only model citations can lack an admitted factual field.
        key='R'+e.digest(eid)[:12]
    if key in page['records']:return key
    clause=next((c for c in session.clauses.values() if c['supports'][0]['evidence_id']==eid),None)
    record={'evidence_id':eid,'family':clause['supports'][0]['source_type'] if clause else 'unresolved',
            'grouping':'same_original_evidence_id_only'}
    context=contexts.get(eid)
    if context:
        s=session._statement('observations',context['id'])
        record.update(context_value=context['arguments']['value'],context_label='Recorded object/executable/path',
            context_statement=s['id'],context_source_unit=context['id'],context_pointer=context['arguments']['pointer'],
            qualification_refs=_qualifiers(s['qualifications'],page['qualifications']))
    else:record['context_limitation']='No admitted exact path/object label; record identity retained.'
    page['records'][key]=record
    return key


def _project(session,section,identity,labels,contexts,page):
    s=session._statement(section,identity)
    refs=[]
    for dep in s['dependencies']:
        if 'evidence_id' not in dep:continue
        row={'record':_add_record(session,dep['evidence_id'],labels,contexts,page)}
        for key in ('value_digest','interpretation_id','request_id','packet_digest','alias','pointer'):
            if key in dep:row[key]=dep[key]
        if dep.get('field'):row['pointer']=dep['field']['pointer']
        refs.append(row)
    item=dict(statement_id=s['id'],source_units=s['source_units'],classification=s['classification'],
              section=section,text=s['text'],supports=refs,
              qualification_refs=_qualifiers(s['qualifications'],page['qualifications']),
              canonical_detail=s['id'])
    if identity in session.clauses:
        c=session.clauses[identity];support=c['supports'][0]
        item['record']=_add_record(session,support['evidence_id'],labels,contexts,page)
        if c['type']=='observation':
            field=c['arguments'];stamp=support.get('timestamp')
            label=field['label']
            if stamp:
                label=stamp.get('meaning') or stamp.get('type') or label
                item['timestamp_semantics']=stamp
            item['text']=str(label)+': '+e._quote(field['value'])
            item['pointer']=field['pointer']
    elif s['classification']=='validated_relationship':
        item['membership']=s['metadata']['membership']
        item['predicate']=s['metadata']['predicate']
        item['endpoints']=[]
        for cid in s['metadata']['endpoints']:
            clause=session.clauses[cid];support=clause['supports'][0]
            key=_add_record(session,support['evidence_id'],labels,contexts,page)
            stamp=support.get('timestamp') or {}
            label=stamp.get('meaning') or stamp.get('type') or clause['arguments'].get('label')
            item['endpoints'].append({'record':key,'source_unit':cid,'pointer':clause['arguments'].get('pointer'),
                                      'label':label,'value':clause['arguments'].get('value')})
        if item['predicate']=='recorded_time_before':
            item['text']='Recorded UTC comparison only: '+ ' → '.join(x['record']+' '+str(x['label'])+' '+e._quote(x['value']) for x in item['endpoints'])
        item['frontier_reference']=s['id']
    if s['classification'] not in ('recorded_observation','deterministic_interpretation','validated_relationship'):
        item['origin']=s['origin']
        for key in ('alternatives','alias_legend','support_granularity'):
            if s['metadata'].get(key):item[key]=s['metadata'][key]
        if s['metadata'].get('objective'):
            obj=s['metadata']['objective']
            item['objective_status']={'eligible':obj.get('eligible'),'unresolved':obj.get('unresolved'),
                                      'assessment':(s['metadata'].get('assessment') or {}).get('status','NOT_ASSESSABLE')}
    return item


def page(session,cursor=None):
    _check(session)
    labels,contexts=_record_index(session)
    # Same admission inventory as D1a; display order groups observations by original EID.
    candidates=list(session.candidates[:e.MAX_STATEMENTS])
    positions={}
    for eid in labels:
        clauses=[c for c in session.clauses.values() if c['supports'][0]['evidence_id']==eid]
        clauses.sort(key=lambda c:(0 if c['type']=='deterministic_interpretation' else
            1 if contexts.get(eid,{}).get('id')==c['id'] else 2,
            c['supports'][0].get('field',{}).get('pointer',''),c['id']))
        positions.update({c['id']:i for i,c in enumerate(clauses)})
    def rank(candidate):
        section,identity=candidate
        c=session.clauses.get(identity)
        return ((0 if c else 1),
                positions[identity] if c else list(e.SECTIONS).index(section),
                c['supports'][0]['evidence_id'] if c else '',
                c['supports'][0].get('field',{}).get('pointer','') if c else '',identity)
    candidates.sort(key=rank)
    binding={**session.binding,'display_contract':CONTRACT,'display_rules':RULES,'display_order':e.digest(candidates)}
    offset=0
    if cursor:
        if not isinstance(cursor,str) or len(cursor)>512:raise ValueError('Invalid display cursor')
        try:offset=json.loads(base64.urlsafe_b64decode(cursor+'='*(-len(cursor)%4)))['offset']
        except (ValueError,KeyError,TypeError):raise ValueError('Invalid display cursor') from None
        if type(offset) is not int or not 0<=offset<=len(candidates) or cursor!=e._cursor(binding,offset):raise ValueError('Stale display cursor')
    result=dict(contract=CONTRACT,rules=RULES,mode='retrospective',binding=binding,
        question=session.manifest['question'],s3_status=(session.original.get('original_assessment') or {}).get('status','NOT_ASSESSABLE'),
        answer_boundary='Presentation does not broaden the original assessment. Recorded observations, qualified relationships and unverified proposals remain distinct.',
        records={},items=[],qualifications={},summary=[],omissions=[],next_cursor=None,
        coverage={k:v for k,v in session.organization['coverage'].items() if type(v) in (int,bool)},
        chronology_limitations=session.organization['coverage'].get('source_clock_limitations',[]),
        relationship_coverage=session.organization['coverage'].get('relationship_coverage',{}),
        source_stops=session.organization.get('processing_stops',[]),
        pending=0,prior_candidates=offset,admission_limit_omitted=max(0,len(session.candidates)-len(candidates)))
    index=offset
    while index<len(candidates):
        trial=deepcopy(result)
        item=_project(session,*candidates[index],labels,contexts,trial)
        trial['items'].append(item)
        if offset==0 and item.get('record') and not any(x.get('record')==item['record'] for x in result['items']):
            trial['summary'].append(item['statement_id'])
        references={x['statement_id'] for x in trial['items']}|{r['context_statement'] for r in trial['records'].values() if 'context_statement' in r}
        trial['pending']=len(candidates)-index-1
        trial['next_cursor']=e._cursor(binding,index+1) if trial['pending'] else None
        if e._size(trial)>e.PAGE_BYTES or len(references)>e.PAGE_STATEMENTS or len(render(trial,check=False,expand_questions=True).encode('utf-8'))>e.PAGE_BYTES:
            if result['items']:break
            omission={'source_unit':candidates[index][1],'reason':'atomic_display_bundle_budget'}
            if e._size(result)+e._size(omission)>e.PAGE_BYTES-1024:break
            result['omissions'].append(omission);index+=1;continue
        result=trial;index+=1
    result['pending']=len(candidates)-index
    result['next_cursor']=e._cursor(binding,index) if result['pending'] else None
    if index==offset and result['pending']:raise ValueError('Display cannot advance within page budget')
    if e._size(result)>e.PAGE_BYTES:raise ValueError('Display envelope exceeds page budget')
    return result


def render(view,*,check=True,expand_questions=False):
    lines=['Integrated explanation — retrospective',e._safe(view['question']),
           'Original S3: '+view['s3_status'],view['answer_boundary']]
    def qrefs(refs):return ' ['+', '.join(refs)+']' if refs else ''
    byid={x['statement_id']:x for x in view['items']}
    if view['summary']:
        lines+=['','Summary — selected body observations, not a causal chain']
        for sid in view['summary']:
            item=byid[sid];lines.append('  '+item['record']+' '+e._safe(item['text'])+qrefs(item['qualification_refs']))
    for key,r in view['records'].items():
        items=[i for i in view['items'] if i.get('record')==key]
        lines+=['',key+' — '+e._safe(r['family'])+' record']
        if 'context_value' in r:lines.append('  '+r['context_label']+': '+e._safe(e._quote(r['context_value']))+qrefs(r['qualification_refs']))
        else:lines.append('  '+r['context_limitation'])
        for item in items:
            prefix='Security interpretation: ' if item['classification']=='deterministic_interpretation' else ''
            lines.append('  '+prefix+e._safe(item['text'])+qrefs(item['qualification_refs']))
    for section,title in e.SECTIONS.items():
        items=[i for i in view['items'] if i['section']==section and not i.get('record')]
        if not items:continue
        lines+=['',title]
        if section in ('current','historical'):lines+=['  Recorded timestamp coordinates only. Display adjacency creates no additional comparison or physical-event order.']
        shown=items if section!='questions' or expand_questions else items[:3]
        for item in shown:
            lines.append('  '+e._safe(item['text'])+qrefs(item['qualification_refs']))
            if item.get('alternatives'):lines.append('    Alternatives: '+e._safe(item['alternatives']))
            if item.get('alias_legend'):
                lines.append('    Request '+str(item['alias_legend'][0]['request_number'])+' aliases (request-local): '+', '.join(a['alias']+' = '+e._safe(a['label']) for a in item['alias_legend']))
        if len(shown)<len(items):lines.append('  '+str(len(items)-len(shown))+' additional distinct questions on this page; available in --json or --expand-questions. Not merged.')
    lines+=['','Qualifications — exact texts, applying to referenced items on this page']
    lines +=['  '+key+': '+e._safe(text) for key,text in sorted(view['qualifications'].items())]
    lines+=['','Coverage: '+e.encoded(view['coverage']),
            'Sparse comparison coverage: '+e.encoded(view['relationship_coverage']),
            'Clock/source limitations: '+e._safe(view['chronology_limitations']),
            'Source processing stops: '+e._safe(view['source_stops']),
            'This page: '+str(len(view['items']))+' items; '+str(view['pending'])+' pending; '+str(len(view['omissions']))+' omitted.',
            'Original support and lineage: --canonical --json. No new evidence or model requests.']
    if view['next_cursor']:lines+=['Next display page: --cursor '+view['next_cursor']]
    out='\n'.join(lines)
    if check and len(out.encode('utf-8'))>e.PAGE_BYTES:raise ValueError('Human display page budget exceeded')
    return out

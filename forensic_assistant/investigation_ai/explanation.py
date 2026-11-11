"""D1a: read-only, bounded explanation of validated recorded investigation state."""
import base64
import json
from . import synthesis as s1, relationships as s2, organization as org
from .state import encoded
from .transcript import load, digest

CONTRACT = 'integrated-explanation-v1'
STATEMENT = 'investigative-statement-v1'
SECTION = 'investigative-section-v1'
RULES = 'deterministic-explanation-v1'
PAGE_BYTES = 16 * 1024
PAGE_STATEMENTS = 64
MAX_STATEMENTS = 192
_TOKEN = object()
SECTIONS = {
    'observations':'Recorded evidence',
    'interpretations':'Deterministic interpretations',
    'current':'Current-final recorded relationships',
    'historical':'Earlier-frontier historical derivations',
    'hypotheses':'Possible connections and competing hypotheses — unverified',
    'objectives':'Objective assessments and answer boundaries',
    'questions':'Outstanding questions — unverified',
    'coverage':'Coverage and evidence limitations',
    'actions':'Recommended next investigative actions — unverified, not authorized',
}


def _size(value):
    return len(encoded(value).encode('utf-8'))


def _quote(value):
    return json.dumps(value, ensure_ascii=False)


def _safe(value):
    return _quote(str(value))[1:-1]


def _fact_text(clause):
    s1._validate_render_clause(clause)
    subject=s1.RULES[clause['predicate']][1]
    if subject=='The record':
        subject={'browser':'The browser record','registry':'The Registry record'}.get(clause['supports'][0]['source_type'],subject)
    if clause['type']=='deterministic_interpretation':return subject
    field=clause['arguments']
    return subject+' reports '+_quote(field['label'])+' as '+_quote(field['value'])+'.'


def _dependency(clause):
    support=clause['supports'][0]
    result=dict(contract=s1.CONTRACT,source_unit=clause['id'],evidence_id=support['evidence_id'],
                source_type=support['source_type'],provenance=support['provenance'],
                context=support['context'],lineage=clause['lineage'])
    if 'field' in support:
        result.update(field={k:v for k,v in support['field'].items() if k!='value'},
                      value_digest=digest(support['field']['value']),timestamp=support.get('timestamp'))
    else:
        result.update(interpretation_id=support['interpretation_id'],
                      premise_pointers=support['premise_pointers'],premises_digest=digest(support['premises']))
    return result


class _Session:
    """Only created after existing replay validators; not a cached JSON importer."""
    def __init__(self, token, manifest, factual, organization):
        if token is not _TOKEN:raise ValueError('Validated source session required')
        self.manifest=manifest;self.factual=factual;self.organization=organization
        if factual['evidence_state']!=organization['read_view']:raise ValueError('Cross-view explanation')
        self.clauses={c['id']:c for c in factual['clauses']}
        self.entities={e['id']:e for e in organization['entities']}
        for c in self.clauses.values():s1._validate_render_clause(c)
        for e in self.entities.values():
            if e['kind']=='finding':
                c=self.clauses.get(e['id'])
                if c is None or e['read_view']!=c['evidence_state'] or e['qualifications']!=c['qualifications']:
                    raise ValueError('Missing or changed original finding')
                if e['dependencies'][0]!=org._Sources(manifest)._dependency(c):
                    raise ValueError('Original support binding changed')
        self.original=next((e for e in self.entities.values() if e.get('role')=='original_question'),None)
        if self.original is None:raise ValueError('Original question unavailable')
        self.candidates=[]
        # Registered interpretation first; all observations remain in the body.
        for c in factual['clauses']:
            self.candidates.append(('interpretations' if c['type']=='deterministic_interpretation' else 'observations',c['id']))
        for e in self.entities.values():
            if e['kind']=='relationship':
                section=('current' if e['current_final'] else 'historical')
                if e['membership_frontier']!=organization['coverage'].get('relationship_frontier'):section='coverage'
            elif e.get('role')=='provisional_objective':section='objectives'
            elif e['kind']=='hypothesis' or e.get('role') in ('b2_group','b2_relationship_candidate'):section='hypotheses'
            elif e.get('role')=='b2_next_objective':section='actions'
            elif e['kind']=='question' and e.get('role')!='original_question':section='questions'
            else:continue
            self.candidates.append((section,e['id']))
        self.candidates.append(('coverage','coverage'))
        self.candidates.append(('objectives','original_assessment'))
        rank={'interpretations':0,'observations':1,'current':2,'historical':3,'hypotheses':4,
              'objectives':5,'questions':6,'coverage':7,'actions':8}
        self.candidates.sort(key=lambda x:(rank[x[0]],x[1]))
        self.binding=dict(contract=CONTRACT,rules=RULES,run_id=manifest['investigation_id'],
            read_view=organization['read_view'],source_frontier=manifest['chain'],
            organization_revision=organization['revision'],organization_digest=organization['state_digest'],
            ordering=digest(self.candidates))
        self.seal=self._seal()

    def _seal(self):
        # Hash bounded units independently; do not serialize another whole graph.
        return digest([digest(self.manifest),digest(self.factual['evidence_state']),
            [digest(c) for c in self.factual['clauses']],
            [digest(x) for x in self.organization['entities']],
            [digest(x) for x in self.organization['links']],
            digest(self.organization['coverage']),digest(self.organization['read_view']),self.organization['state_digest'],
            digest(self.objective_entities) if hasattr(self,'objective_entities') else None])

    def _statement(self, section, identity):
        deps=[];qualifications=[];metadata={};objective_ids=[]
        if identity in self.clauses:
            c=self.clauses[identity];text=_fact_text(c);deps=[_dependency(c)]
            classification='deterministic_interpretation' if c['type']=='deterministic_interpretation' else 'recorded_observation'
            origin=dict(contract=s1.CONTRACT,id=identity,rule=c['rule'])
            qualifications=c['qualifications']
        elif identity=='original_assessment':
            classification='unresolved_question';origin=dict(contract=org.CONTRACT,id=self.original['id'])
            text='Original question registered assessment: '+str((self.original.get('original_assessment') or {}).get('status','NOT_ASSESSABLE'))+'.'
            metadata={'original_assessment':self.original.get('original_assessment')}
            qualifications=['The original question is not replaced by provisional objectives.']
        elif identity=='coverage':
            classification='coverage_limitation';origin=dict(contract=org.CONTRACT,id=self.organization['state_digest'])
            coverage=self.organization['coverage']
            text=('The recorded investigation examined '+str(coverage.get('examined_references',0))+
                  ' of '+str(coverage.get('authorized_references',0))+' authorized references. '+
                  'This preview performs no additional evidence examination. Completed processing is not forensic completeness.')
            metadata={'coverage':{k:v for k,v in coverage.items() if type(v) in (int,bool,str)},
                      'organization_incomplete':self.organization['incomplete'],
                      'unassigned_findings':len(coverage.get('unassigned_findings',[]))}
            qualifications=self.organization['limitations']
        else:
            e=self.entities[identity];origin=e['introduced_by']
            if e['kind']=='relationship' and section!='coverage':
                endpoints=[self.clauses[k] for k in e['endpoints']]
                times={c['id']:s2._time(c) for c in endpoints}
                expected,reason=s2._compare(e['predicate'],*endpoints,times)
                if reason or expected['id']!=identity or expected['qualifications']!=e['qualifications']:
                    raise ValueError('Relationship support changed')
                labels=[_quote(c['arguments'].get('label',c['predicate']))+' '+_quote(c['arguments'].get('value')) for c in endpoints]
                wording={
                    'recorded_time_before':labels[0]+' precedes '+labels[1]+' in recorded UTC coordinates only.',
                    'exact_recorded_path':'The two records report the same exact path string: '+labels[0]+'.',
                    'exact_recorded_identifier':'The records have the same registered recorded identifier: '+labels[0]+'.',
                    'incompatible_recorded_field':'The registered comparison identifies incompatible recorded projections of one field occurrence.',
                }
                text=wording[e['predicate']];classification='validated_relationship'
                deps=[_dependency(c) for c in endpoints]
                qualifications=sorted(set(e['qualifications']+e['assumptions']))
                if section=='historical':qualifications+=['Earlier-frontier derivation; absence from the final sparse graph does not invalidate the recorded comparison.']
                metadata={k:e[k] for k in ('predicate','rule','endpoints','semantics','present_frontiers','membership','membership_frontier')}
            elif e.get('role')=='provisional_objective':
                classification='unresolved_question';objective_ids=[identity]
                text='Provisional objective: '+_quote(e['text'])+'. Registered assessment: '+str((e.get('assessment') or {}).get('status','NOT_ASSESSABLE'))+'.'
                metadata={k:e[k] for k in ('objective','assessment','limitations')}
                qualifications=['Provisional intent does not replace or answer the original question.']
            elif e['kind']=='relationship':
                classification='coverage_limitation';text='Relationship membership has not been updated to the latest organization frontier.'
                metadata={'relationship_id':identity}
            else:
                classification=('unverified_hypothesis' if e['kind']=='hypothesis' else
                    'recommended_action' if section=='actions' else 'unresolved_question' if section=='questions' else 'unverified_explanation')
                payload=e.get('text','')
                text=payload if isinstance(payload,str) else '; '.join(k+': '+str(v) for k,v in payload.items())
                metadata={k:e[k] for k in ('alternatives','alias_legend','binding','support_granularity','semantic_key','role','validated_relationship') if k in e}
                deps=e.get('dependencies',[])
                # B2 exact field references stay request-scoped; no extra evidence authority.
                if e.get('alias_legend'):deps=e['alias_legend']
                qualifications=['Model proposal is unverified; citations do not establish entailment or corroboration.']
                if classification=='recommended_action':qualifications+=['Suggestion only; not executed or authorized by this preview.']
        if classification in ('recorded_observation','deterministic_interpretation','validated_relationship'):
            for entity in getattr(self,'objective_entities',self.entities.values()):
                assessment=entity.get('assessment') or entity.get('original_assessment') or {}
                if any(identity in p.get(key,[]) for p in assessment.get('propositions',[]) for key in ('direct_clauses','direct_relationships')):
                    objective_ids.append(entity['id'])
        body=dict(contract=STATEMENT,rules=RULES,run_id=self.binding['run_id'],read_view=self.binding['read_view'],
                  classification=classification,source_units=[identity],origin=origin,dependencies=deps,
                  template=origin.get('rule',RULES),text=text,qualifications=qualifications,
                  objective_associations=objective_ids,metadata=metadata,status='included')
        return dict(body,id=digest(body))


def open_history(root, identity):
    """Existing replay is the authority boundary. No evidence database/provider access."""
    before,_=load(root,identity)
    organization=org.reconstruct(root,identity)
    factual=s1.reconstruct(root,identity)
    after,_=load(root,identity)
    if before!=after:raise ValueError('Investigation changed during explanation reconstruction')
    return _Session(_TOKEN,before,factual,organization)


def _cursor(binding, offset):
    return base64.urlsafe_b64encode(encoded({'binding':digest(binding),'offset':offset}).encode()).decode().rstrip('=')


def page(session, cursor=None):
    if type(session) is not _Session or session.seal!=session._seal():
        raise ValueError('Validated explanation session changed')
    offset=0
    if cursor is not None:
        if not isinstance(cursor,str) or len(cursor)>512:raise ValueError('Invalid explanation cursor')
        try:
            value=json.loads(base64.urlsafe_b64decode(cursor+'='*(-len(cursor)%4)))
            offset=value['offset']
        except (ValueError,KeyError,TypeError):raise ValueError('Invalid explanation cursor') from None
        if type(offset) is not int or not 0<=offset<=min(len(session.candidates),MAX_STATEMENTS) or cursor!=_cursor(session.binding,offset):
            raise ValueError('Stale explanation cursor')
    total=len(session.candidates);end=min(total,MAX_STATEMENTS)
    result=dict(contract=CONTRACT,rules=RULES,mode='retrospective',binding=session.binding,
        question=session.manifest['question'],original_assessment={
            'status':(session.original.get('original_assessment') or {}).get('status','NOT_ASSESSABLE'),
            'source_digest':digest(session.original.get('original_assessment'))},
        answer_boundary='Registered findings are partial support. Plan completion does not establish successful execution, causality or whole-case completeness.',
        summary=[],summary_omitted=0,sections=[],statements=[],omissions=[],
        counts={'total':total,'included':0,'omitted':max(0,total-end),'pending':end-offset,'prior_candidates':offset},
        limits={'page_bytes':PAGE_BYTES,'statement_references':PAGE_STATEMENTS,'admitted_statements':MAX_STATEMENTS},
        next_cursor=None,coverage_scope='Page counts exclude earlier pages; assembly omissions beyond 192 are reported separately')
    result['source_coverage']={k:session.organization['coverage'].get(k) for k in (
        'authorized_references','examined_references','observations','interpretations','relationships_current_final',
        'relationships_historical_only','accepted_b2_proposals','accepted_model_proposals','duplicate_proposals')}
    result['source_organization_stops']=session.organization.get('processing_stops',[])
    # Reserve cursor, section and count envelope before admission; all actual output checked below.
    if _size(result)>PAGE_BYTES-2048:raise ValueError('Question/assessment envelope exceeds explanation page budget')
    summary_bytes=0;index=offset
    while index<end and len(result['statements'])<PAGE_STATEMENTS:
        section,identity=session.candidates[index]
        statement=session._statement(section,identity)
        item=dict(contract=SECTION,id=section,title=SECTIONS[section],statement_ids=[statement['id']])
        existing=next((x for x in result['sections'] if x['id']==section),None)
        # No full collection of rendered statements: one bounded candidate at a time.
        if _size(statement)+_size(item)+_size({k:v for k,v in result.items() if k not in ('statements','sections')})>PAGE_BYTES-2048:
            omission={'source_unit':identity,'status':'omitted','reason':'atomic_statement_page_budget'}
            if _size(result)+_size(omission)>PAGE_BYTES-2048:break
            result['omissions'].append(omission);index+=1;continue
        if _size(result)+_size(statement)+_size(item)>PAGE_BYTES-2048:break
        result['statements'].append(statement)
        if existing:existing['statement_ids'].append(statement['id'])
        else:result['sections'].append(item)
        if offset==0 and statement['classification'] in ('recorded_observation','deterministic_interpretation'):
            cost=len((statement['text']+encoded(statement['qualifications'])).encode('utf-8'))
            if len(result['summary'])<4 and summary_bytes+cost<=2048:
                result['summary'].append(statement['id']);summary_bytes+=cost
            else:result['summary_omitted']+=1
        index+=1
    result['counts'].update(included=len(result['statements']),omitted=len(result['omissions'])+max(0,total-end),pending=end-index)
    result['summary_omitted']=max(0,len(session.clauses)-len(result['summary'])) if offset==0 else None
    if index<end:result['next_cursor']=_cursor(session.binding,index)
    result['assembly_exhausted']=index==end
    result['page_complete']=not result['omissions']
    result['assembly_limit_omitted']=max(0,total-end)
    result['source_organization_incomplete']=session.organization['incomplete']
    if _size(result)>PAGE_BYTES:raise ValueError('Explanation page budget exceeded')
    return result


def render(view):
    """Render a page produced by page(); no independent prose generation."""
    lines=['Integrated investigative explanation — '+view.get('mode','retrospective'),_safe(view['question']),
           'Original S3 assessment: '+str((view['original_assessment'] or {}).get('status','NOT_ASSESSABLE')),
           view['answer_boundary']]
    lines+=['Recorded scope: '+str(view['source_coverage']['examined_references'])+' examined / '+str(view['source_coverage']['authorized_references'])+' authorized references. No new lookups or model requests.']
    if view['source_organization_stops']:lines+=['Source organization processing limitations: '+_safe(view['source_organization_stops'])]
    byid={s['id']:s for s in view['statements']}
    def show(s):
        out=['  '+_safe(s['text'])]
        out+=['    Qualification: '+_safe(q) for q in s['qualifications']]
        if s['metadata'].get('alternatives'):out+=['    Alternatives: '+_safe(s['metadata']['alternatives'])]
        if s['metadata'].get('alias_legend'):
            out+=['    Request '+str(s['metadata']['alias_legend'][0]['request_number'])+' aliases (this request only):']
            out+=['      '+a['alias']+' = '+_safe(a['label']) for a in s['metadata']['alias_legend']]
        return out
    if view['summary']:
        lines+=['','Executive finding summary (body statements with qualifications)']
        for identity in view['summary']:lines+=show(byid[identity])
    for section in view['sections']:
        lines+=['',section['title']]
        for identity in section['statement_ids']:lines+=show(byid[identity])
    lines+=['','Page coverage: '+encoded(view['counts'])]
    if view['summary_omitted'] is not None:lines+=['Factual body items not included in the executive summary: '+str(view['summary_omitted'])]
    if view['next_cursor']:lines+=['Next page: --cursor '+view['next_cursor']]
    output='\n'.join(lines)
    if len(output.encode('utf-8'))>PAGE_BYTES:raise ValueError('Human explanation page budget exceeded')
    return output

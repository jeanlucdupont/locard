"""Canonical unverified analyst briefing; no evidence reads or search authority."""
import copy
import json
from forensic_assistant.investigation_ai.contracts import obj,array,string,enumeration,validate
from forensic_assistant.briefing_semantics import TECHNICAL,SEMANTIC,technical,occurrences
from forensic_assistant.briefing_sources import inventory

CATEGORIES = {
 'incident':'Incident description','when':'When','person':'Person','account':'Account',
 'systems':'Systems','user_experience':'User experience','user_actions':'User actions',
 'files':'Files','websites':'Websites','origin':'Origin','activity':'Processes and activity',
 'alerts':'Security alerts','indicators':'Other indicators','scope':'Scope',
 'response':'Response actions','records':'Available records','objectives':'Investigation objectives',
 'context':'Additional context'}
STATES=('provided','approximate','unknown','not_provided','not_applicable','conflicting','ambiguous')
TEXT={'type':'string','minLength':0,'maxLength':1000}
ITEM=obj({'status':enumeration(*STATES),'value':TEXT,'kind':enumeration(*(TECHNICAL+SEMANTIC)),
          'statement':string(2000),'note':TEXT,'polarity':enumeration('reported','negated','uncertain')},('status','value','kind','statement','note','polarity'))
SUMMARY=obj({'text':{'type':'string','minLength':0,'maxLength':1200},'status':enumeration('proposed','accepted','rejected','not_provided'),
             'statement':{'type':'string','minLength':0,'maxLength':2000}},('text','status','statement'))
DOCUMENT=obj({'format':{'type':'integer','minimum':1,'maximum':1},
              'categories':obj({key:array(ITEM,24) for key in CATEGORIES},tuple(CATEGORIES)),
              'summary':SUMMARY},('format','categories','summary'))
MAX_DOCUMENT=64*1024
TYPE_CATEGORY={'person':'person','account':'account','hostname':'systems','filename':'files',
 'windows_path':'files','registry_path':'indicators','domain':'websites','url':'websites','ipv4':'indicators',
 'ipv6':'indicators','hash':'indicators','date':'when','date_range':'when','timestamp':'when','ambiguous_time':'when',
 'timezone':'when','event_id':'alerts','activity':'activity','alert':'alerts','origin':'origin',
 'objective':'objectives','unknown':'context','relationship':'context'}


def empty():
    return {'format':1,'categories':{key:[] for key in CATEGORIES},
            'summary':{'text':'','status':'not_provided','statement':''}}


def validate_document(value,schema):
    """Closed fixed document schema; unlike tool arguments, empty fields are valid."""
    kind=schema['type']
    if kind=='object':
        if type(value) is not dict or set(value)!=set(schema['required']):raise ValueError('Invalid canonical object fields.')
        for key,item in value.items():validate_document(item,schema['properties'][key])
    elif kind=='array':
        if type(value) is not list or not schema['minItems']<=len(value)<=schema['maxItems']:raise ValueError('Invalid canonical array size.')
        if len({json.dumps(item,sort_keys=True) for item in value})!=len(value):raise ValueError('Duplicate canonical items.')
        for item in value:validate_document(item,schema['items'])
    elif kind=='string':
        if type(value) is not str or not schema.get('minLength',0)<=len(value)<=schema.get('maxLength',1000):raise ValueError('Invalid canonical string.')
        if 'enum' in schema and value not in schema['enum']:raise ValueError('Invalid canonical enum.')
    elif kind=='integer':
        if type(value) is not int or not schema['minimum']<=value<=schema['maximum']:raise ValueError('Invalid canonical version.')
    else:raise ValueError('Unsupported canonical schema type.')


def check(document):
    if len(json.dumps(document,ensure_ascii=True).encode())>MAX_DOCUMENT:raise ValueError('Canonical briefing exceeds 64 KiB.')
    validate_document(document,DOCUMENT)
    if sum(len(items) for items in document['categories'].values())>48:raise ValueError('At most 48 briefing entries.')
    for items in document['categories'].values():
        for item in items:
            if any('\0' in item[key] for key in ('value','statement','note')):raise ValueError('Invalid briefing text.')
            if item['status'] in ('provided','approximate','conflicting','ambiguous') and not item['value'].strip():raise ValueError('Supplied briefing entries require a value.')
            if item['status'] in ('unknown','not_provided','not_applicable') and item['value']:
                raise ValueError('Unknown/missing/inapplicable fields cannot supply a value.')
            if item['kind'] in TECHNICAL and item['value']:
                technical(item['kind'],item['value'])
            if item['value'] and item['value'] not in item['statement']:
                raise ValueError('Briefing value must occur exactly in its analyst statement.')
    summary=document['summary']
    if '\0' in summary['text'] or '\0' in summary['statement']:raise ValueError('Invalid summary text.')
    if summary['text'] and not summary['statement']:raise ValueError('Summary requires its source statement.')
    if summary['status']=='not_provided' and summary['text']:raise ValueError('Missing summary cannot have text.')
    return document


def provenance(document):
    """Editable statements are analyst input, never imported source/approval IDs."""
    inputs={}
    for category,items in document['categories'].items():
        for i,item in enumerate(items):inputs[f'canonical:{category}:{i}']=item['statement']
    if document['summary']['statement']:inputs['canonical:summary']=document['summary']['statement']
    units,coverage=inventory(inputs)
    if not coverage['complete']:raise ValueError('Canonical source-unit bound exceeded.')
    return {'inputs':inputs,'source_units':units}


def envelope(document, original=None):
    check(document)
    return {'format':1,'document':copy.deepcopy(document),'provenance':provenance(document),
            'original_provenance':copy.deepcopy(original or {}),'verification':'UNVERIFIED ANALYST INPUT'}


def check_envelope(value):
    if type(value) is not dict or set(value)!={'format','document','provenance','original_provenance','verification'}:
        raise ValueError('Invalid accepted briefing envelope.')
    check(value['document'])
    if value['format']!=1 or value['verification']!='UNVERIFIED ANALYST INPUT' or value['provenance']!=provenance(value['document']):
        raise ValueError('Invalid canonical provenance.')
    if len(json.dumps(value).encode())>256*1024:raise ValueError('Canonical provenance bound exceeded.')
    if type(value['original_provenance']) is not dict:raise ValueError('Invalid canonical provenance.')
    return value


def build(packet):
    from .briefing_review import category as normalize_category
    document=copy.deepcopy(packet.get('accepted_canonical') or empty());used=set()
    original=copy.deepcopy(packet.get('accepted_canonical_provenance') or {})
    refs=original.setdefault('references',{});origins=original.setdefault('classification_origins',{})
    normalizations=[]
    for key,items in document['categories'].items():
        for i in range(len(items)):origins.setdefault(f'{key}:{i}','legacy_unspecified')
    def present(category,item):
        return any(all(existing[k]==item[k] for k in ('status','value','kind','polarity')) for existing in document['categories'][category])
    for candidate in packet.get('ai_candidates',[]):
        category,normalized=normalize_category(candidate,TYPE_CATEGORY[candidate['type']])
        status=candidate.get('status') or ('unknown' if candidate['type']=='unknown' else
                 'ambiguous' if candidate['polarity']=='uncertain' else 'provided')
        if any(l.get('conflicted') and l['id']==candidate.get('lead_id') for l in packet.get('leads',[])):status='conflicting'
        if candidate['type']=='ambiguous_time' and status=='provided':status='approximate'
        cited={u['id']:u for u in packet.get('source_units',[])}
        span=candidate['occurrences'][0]
        relevant=sorted((cited[sid] for sid in candidate['source_ids'] if sid in cited and cited[sid]['source']==span['source'] and cited[sid]['start']<span['end'] and cited[sid]['end']>span['start']),key=lambda u:u['start'])
        statement=''.join(u['text'] for u in relevant)
        item={'status':status,'value':candidate['literal'] if status not in ('unknown','not_provided','not_applicable') else '',
              'kind':candidate['type'],'statement':statement,'polarity':candidate['polarity'],'note':candidate['description']+' '+candidate['uncertainty']}
        if len(item['note'])>1000:raise ValueError('Canonical note bound exceeded.')
        if present(category,item):
            if candidate.get('lead_id'):used.add(candidate['lead_id'])
            continue
        if sum(len(items) for items in document['categories'].values())>=48 or len(document['categories'][category])>=24:
            packet['limitations'].append('Canonical capacity reached; additional AI candidates remain in --details.')
            continue
        document['categories'][category].append(item)
        key=f'{category}:{len(document["categories"][category])-1}'
        refs[key]={k:candidate[k] for k in ('source_ids','occurrences')}
        origins[key]='ai_classification'
        if normalized:
            refs[key]['category_normalization']=normalized
            normalizations.append({**normalized,'entry':key})
        if candidate.get('lead_id'):used.add(candidate['lead_id'])
    for lead in packet.get('leads',[]):
        if sum(len(items) for items in document['categories'].values())>=48:
            packet['limitations'].append('Canonical 48-item bound reached; review remaining technical leads with --details.')
            break
        if lead['id'] in used:continue
        kind='account' if lead['type']=='username' else lead['type']
        if kind not in TECHNICAL:continue
        value=lead['occurrences'][0]['original']
        try:technical(kind,value)
        except ValueError:continue
        category=TYPE_CATEGORY[kind]
        status='conflicting' if lead.get('conflicted') else 'ambiguous' if lead['classification'] in ('ambiguous','partial') else 'approximate' if kind=='ambiguous_time' else 'provided'
        if any(item['value']==value and item['kind']==kind and item['polarity']==('negated' if lead['negated'] else 'reported') for item in document['categories'][category]):continue
        if len(document['categories'][category])>=24:
            packet['limitations'].append('Canonical category bound reached; further technical references remain in --details.')
            continue
        document['categories'][category].append({'status':status,'value':value,'kind':kind,'statement':value,'polarity':'negated' if lead['negated'] else 'reported',
            'note':'Deterministically validated technical reference; semantic role unverified.'})
        key=f'{category}:{len(document["categories"][category])-1}'
        refs[key]={'occurrences':lead['occurrences']};origins[key]='deterministic_reference'
    proposed=packet.get('proposed_summary')
    if proposed:
        document['summary']={'text':proposed['text']+'\nUncertainty: '+proposed['uncertainty'],'status':'proposed','statement':proposed['source_text']}
        refs['summary']={'source_ids':proposed['source_ids']};origins['summary']='ai_summary'
    from .briefing_completion import summary_diagnostic,synthesize
    summary_state=summary_diagnostic(packet)
    if not document['summary']['text'] and document['summary']['status']=='not_provided':
        fallback=synthesize(document,CATEGORIES)
        if fallback:
            document['summary']=fallback['document'];refs['summary']=fallback['references']
            origins['summary']='deterministic_synthesis'
            summary_state.update(fallback='deterministic_synthesis',included=fallback['included'],total=fallback['total'])
    check(document)
    # Retain prior source inventories: old entry references must remain resolvable.
    original['inputs']={**original.get('inputs',{}),**packet['inputs']}
    units={u['id']:u for u in original.get('source_units',[])}
    units.update({u['id']:u for u in packet.get('source_units',[])})
    original['source_units']=list(units.values())
    original['review_diagnostics']={'rejected_items':copy.deepcopy(packet.get('ai_error',{}).get('rejected_items',[])),
                                  'source_coverage':packet.get('ai_source_coverage'), 'normalizations':normalizations,
                                  'summary':summary_state,
                                  'narrative_retained':bool(packet.get('source_narrative_retained') or any(packet['inputs'].get(k) for k in ('original','narrative')) or original.get('review_diagnostics',{}).get('narrative_retained'))}
    return {'document':document,'original_provenance':original,'accepted':False,
             'coverage':packet.get('semantic_coverage','limited_deterministic_technical_only')}


def render(value):
    from forensic_assistant.interactive.console import safe
    from .briefing_review import assess
    from .briefing_completion import unknown_label
    document=value['document'];original=value.get('original_provenance',{})
    assessment=assess(document,original.get('review_diagnostics'))
    origins=original.get('classification_origins',{})
    lines=['CASE BRIEFING - unverified analyst input',
        'Accepted for use - assertions and derived interpretations remain unverified' if value.get('accepted') else 'Proposed representation - not yet accepted','', 'Information collected and gaps']
    def multiline(text,indent=''):
        lines.extend(indent+safe(line) for line in text.splitlines())
    for category,label in CATEGORIES.items():
        lines.append('  '+label)
        items=document['categories'][category];gap=assessment['categories'][category]
        if not items:
            if category=='incident' and original.get('review_diagnostics',{}).get('narrative_retained'):
                lines.append('    Original analyst narrative retained; no separate incident entry extracted.')
            elif gap['state']=='assigned_elsewhere':
                lines.append('    Related information represented under '+', '.join(CATEGORIES[k] for k in gap['related_categories'])+'; duplication is not required.')
            else:lines.append('    Not provided in this representation (extraction may have omitted it).')
            if gap['state']=='validation_rejected':
                lines.append('    Candidate rejected during validation: '+', '.join(gap['rejection_rules'])+'.')
            elif gap['state']=='possible_classification_gap':
                lines.append('    Possible classification gap; review '+', '.join(CATEGORIES[k] for k in gap['related_categories'])+'.')
        for i,item in enumerate(items):
            display=item['value'] or unknown_label(item)+': '+item['status'].replace('_',' ').capitalize()
            multiline(display,'    ')
            lines.append('      ['+item['status']+'; '+item['polarity']+'; '+safe(origins.get(f'{category}:{i}','origin not recorded'))+']')
            if item['value'] and item['note']:multiline(item['note'],'      ')
    summary=document['summary']
    heading='Deterministic synthesis of analyst-reported entries - not an AI conclusion' if origins.get('summary')=='deterministic_synthesis' else 'Proposed incident summary - unverified'
    lines.extend(['',heading+' ('+summary['status']+')'])
    diagnostic=original.get('review_diagnostics',{}).get('summary',{})
    if diagnostic and diagnostic['state']!='accepted':
        lines.append('AI summary: '+safe(diagnostic['state'])+' ('+safe(diagnostic['stage'])+').')
    multiline(summary['text'] or 'Not provided; no summary was fabricated.')
    for check in assessment['summary_checks']:
        if check['rule']=='possible_summary_entity_omission':
            lines.append('Summary review: possible omission of '+CATEGORIES[check['category']]+'.')
        else:lines.append('Summary review: check coverage of '+CATEGORIES[check['category']]+'.')
    if assessment['source_coverage'] and not assessment['source_coverage'].get('complete'):
        lines.append('Extraction coverage incomplete: not all source text was exposed to AI.')
    lines.append('Source support is not verification. Missing fields are not negative observations.')
    return '\n'.join(lines)


def review(value,read):
    """Bounded edits to a proposal; caller alone persists explicit acceptance."""
    from forensic_assistant.briefing_workflow import read_answer
    document=copy.deepcopy(value['document']);original=copy.deepcopy(value.get('original_provenance',{}))
    for _ in range(48):
        print(render({**value,'document':document,'original_provenance':original}))
        choice=read_answer(read,'Accept, correct, move, add, reject-summary, or finish? [finish]: ').strip().lower()
        if choice in ('','finish'):return None
        if choice=='accept':
            check(document)
            if document['summary']['status']=='proposed':document['summary']['status']='accepted'
            original['acceptance']='accepted_for_use_not_verified'
            return envelope(document,original)
        if choice=='reject-summary':document['summary']['status']='rejected';continue
        if choice=='move':
            from .briefing_review import move_metadata
            source=read_answer(read,'Current category key: ').strip()
            number=read_answer(read,'Item number (1-based): ').strip()
            target=read_answer(read,'Destination category key: ').strip()
            if source not in CATEGORIES or target not in CATEGORIES or source==target or not number.isdecimal() or not 1<=int(number)<=len(document['categories'][source]):
                print('Invalid category move; proposal preserved.');continue
            index=int(number)-1;trial=copy.deepcopy(document)
            trial['categories'][target].append(trial['categories'][source].pop(index))
            try:check(trial)
            except ValueError:print('Invalid category move; proposal preserved.');continue
            move_metadata(original,source,index,target,len(trial['categories'][target])-1)
            document=trial;continue
        if choice not in ('correct','add'):continue
        print('Categories: '+', '.join(CATEGORIES)+', summary')
        category=read_answer(read,'Category key (or summary): ').strip()
        if category=='summary':
            text=read_answer(read,'Replacement summary (analyst assertion): ')
            trial=copy.deepcopy(document)
            trial['summary']={'text':text,'statement':text,'status':'proposed' if text else 'not_provided'}
            try:check(trial)
            except ValueError:print('Invalid summary; previous proposal preserved.');continue
            document=trial
            original.setdefault('classification_origins',{})['summary']='analyst_summary'
            original.setdefault('references',{}).pop('summary',None)
            continue
        if category not in CATEGORIES:
            print('Categories: '+', '.join(CATEGORIES));continue
        items=document['categories'][category]
        index=len(items)
        if choice=='correct':
            number=read_answer(read,'Item number (1-based): ')
            if not number.isdecimal() or not 1<=int(number)<=len(items):print('Invalid item number.');continue
            index=int(number)-1
        status=read_answer(read,'Status: ').strip()
        kind=read_answer(read,'Kind (person, hostname, filename, activity, unknown, etc.): ').strip()
        text=read_answer(read,'Exact analyst statement/value: ')
        item={'status':status,'kind':kind,'value':'' if status in ('unknown','not_provided','not_applicable') else text,
              'statement':text,'polarity':items[index]['polarity'] if choice=='correct' else 'reported','note':'Analyst review correction/addition; unverified.'}
        trial=copy.deepcopy(document)
        if choice=='correct':trial['categories'][category][index]=item
        else:trial['categories'][category].append(item)
        try:check(trial)
        except ValueError:print('Invalid item; previous proposal preserved.');continue
        document=trial
        key=f'{category}:{index}'
        original.setdefault('classification_origins',{})[key]='analyst_correction' if choice=='correct' else 'analyst_addition'
        original.setdefault('references',{}).pop(key,None)
    raise ValueError('Briefing review step bound reached; no acceptance saved.')


def exchange(args):
    """Explicit JSON exchange; no editable revision IDs or search approvals."""
    import os
    import tempfile
    from pathlib import Path
    from .briefing_store import Store,content,FIELDS
    from .briefing_workflow import read_answer,view
    from .investigation_ai.storage import local_path,DirectoryGuard
    from .investigation_ai.contracts import loads
    store=Store(args.db);state=store.load();revision=state['revisions'][-1] if state else None
    current=revision['content'] if revision else content(dict.fromkeys(FIELDS,''),'')
    if args.export_json:
        document=current.get('canonical',{}).get('document') or empty()
        target=local_path(Path(args.export_json).absolute())
        from .output import validate_destination
        if target.is_relative_to(store.root):raise ValueError('Export cannot target internal briefing storage.')
        validate_destination(target,args)
        with DirectoryGuard(target.parent):
            if target.exists():raise ValueError('Export destination already exists; no overwrite.')
            fd,name=tempfile.mkstemp(prefix='.briefing-export-',dir=target.parent)
            try:
                with os.fdopen(fd,'wb') as stream:
                    stream.write(json.dumps(document,ensure_ascii=False,indent=2).encode('utf-8'));stream.flush();os.fsync(stream.fileno())
                validate_destination(target,args)
                os.link(name,target)
            finally:
                if os.path.exists(name):os.unlink(name)
        return {'kind':'saved_briefing','message':'Editable briefing JSON exported.'+(' Empty template: no accepted canonical briefing yet.' if not current.get('canonical') else '')}
    path=local_path(args.import_json)
    if not path.is_file() or path.stat().st_nlink!=1:raise ValueError('Import requires a regular, non-linked file.')
    with path.open('rb') as stream:raw=stream.read(MAX_DOCUMENT+1)
    if len(raw)>MAX_DOCUMENT:raise ValueError('Briefing import exceeds 64 KiB.')
    document=loads(raw.decode('utf-8-sig'),max_bytes=MAX_DOCUMENT);check(document)
    read=getattr(args,'_confirm',None)
    if read is None:raise ValueError('Briefing import requires interactive confirmation.')
    print(render({'document':document,'accepted':False}))
    if read_answer(read,'Replace accepted briefing with this unverified analyst document? [y/N]: ').strip().lower() not in ('y','yes'):
        return {'kind':'saved_briefing','message':'Import cancelled; saved briefing unchanged.'}
    value=copy.deepcopy(current);value['canonical']=envelope(document)
    return view(store.save(value,revision['digest'] if revision else None))

"""Typed AI candidates: exact analyst provenance, deterministic value validation.

This module never reads evidence, calls a provider, or authorizes a search.
"""
import hashlib
import ipaddress
import json
import re
from forensic_assistant.investigation_ai.contracts import obj, array, string, enumeration

TECHNICAL = ('account','hostname','filename','windows_path','registry_path','domain',
             'url','ipv4','ipv6','hash','date','date_range','timestamp','ambiguous_time','timezone','event_id')
SEMANTIC = ('person','activity','alert','origin','objective','unknown','relationship')
CANDIDATE = obj({'type':enumeration(*(TECHNICAL+SEMANTIC)),
                 'literal':string(500), 'source_ids':array(string(48),6,1),
                 'description':string(300), 'polarity':enumeration('reported','negated','uncertain'),
                 'uncertainty':string(300),
                 'category':enumeration('incident','when','person','account','systems','user_experience','user_actions','files','websites','origin','activity','alerts','indicators','scope','response','records','objectives','context'),
                 'status':enumeration('provided','approximate','unknown','not_provided','not_applicable','conflicting','ambiguous')},
                ('type','literal','source_ids','description','polarity','uncertainty'))
MAX_CANDIDATES=24


def occurrences(literal, cited, inputs):
    """Locate exact text only within contiguous cited units of one source."""
    groups=[]
    for unit in sorted(cited,key=lambda u:(u['source'],u['start'])):
        if groups and groups[-1][0]==unit['source'] and groups[-1][2]==unit['start']:
            groups[-1]=(unit['source'],groups[-1][1],unit['end'])
        else:groups.append((unit['source'],unit['start'],unit['end']))
    result=[]
    for source,start,end in groups:
        cursor=start
        while len(result)<16:
            at=inputs[source].find(literal,cursor,end)
            if at<0:break
            result.append(dict(source=source,start=at,end=at+len(literal),original=literal))
            cursor=at+len(literal)
    return result


def technical(kind,value):
    """Validate a whole supplied value; never guess its boundary in prose."""
    if any(ord(c)<32 for c in value) or len(value.encode('utf-8'))>1024:
        raise ValueError('invalid_technical_value')
    if kind=='url':
        from urllib.parse import urlsplit
        parsed=urlsplit(value)
        parsed.port  # Validate an explicit port without making a request.
        if parsed.scheme not in ('http','https') or not parsed.hostname or any(c.isspace() for c in value):raise ValueError('invalid_technical_value')
        try:ipaddress.ip_address(parsed.hostname)
        except ValueError:
            from .briefing_entities import valid_host
            if not valid_host(parsed.hostname):raise ValueError('invalid_technical_value')
        return value
    if kind in ('ipv4','ipv6'):
        address=ipaddress.ip_address(value)
        if address.version!=int(kind[-1]):raise ValueError('invalid_technical_value')
        return str(address)
    if kind=='hash':
        if not re.fullmatch(r'(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})',value):raise ValueError('invalid_technical_value')
        return value.lower()
    if kind in ('domain','hostname'):
        from .briefing_entities import valid_host
        if not valid_host(value) or not any(c.isalpha() for c in value) or (kind=='domain' and ('.' not in value or not value.rsplit('.',1)[1].isalpha())):
            raise ValueError('invalid_technical_value')
        return value.casefold()
    if kind=='filename':
        if (not value.strip() or value!=value.strip() or any(c in value for c in '\\/:*?"<>|') or
            value.endswith(('.', ' ')) or not re.fullmatch(r'.+\.[A-Za-z0-9]{1,16}',value)):
            raise ValueError('invalid_technical_value')
        return value.casefold()
    if kind=='windows_path':
        if not re.match(r'^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+)',value) or any(c in value for c in '*?"<>|'):
            raise ValueError('invalid_technical_value')
        if ':' in value[2:] or value!=value.strip():raise ValueError('invalid_technical_value')
        from .artifacts.paths import normalize_path
        return normalize_path(value)['normalized']
    if kind=='registry_path':
        if not re.fullmatch(r'(?i)(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\r\n]+',value):raise ValueError('invalid_technical_value')
        return value.casefold()
    if kind=='account':
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}(?:\\[A-Za-z0-9_.-]{1,64}|@[A-Za-z0-9.-]+)?',value):raise ValueError('invalid_technical_value')
        return value
    if kind=='event_id':
        if not value.isdecimal() or not 0<=int(value)<=65535:raise ValueError('invalid_technical_value')
        return int(value)
    if kind=='timestamp':
        from .retrieval.queries import required_time
        return required_time(value)
    if kind=='date_range':
        from datetime import date
        match=re.fullmatch(r'(\d{4}-\d{2}-\d{2}) to (\d{4}-\d{2}-\d{2})',value)
        if not match or date.fromisoformat(match[1])>date.fromisoformat(match[2]):raise ValueError('invalid_technical_value')
        return value
    if kind=='date':
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}|[A-Za-z]+ \d{1,2},? \d{4}',value):raise ValueError('invalid_technical_value')
        from .retrieval.temporal_scope import resolve
        parsed=resolve('on '+value)
        if parsed.get('kind')!='explicit':raise ValueError('invalid_technical_value')
        return parsed['start'][:10]
    if kind=='ambiguous_time':
        match=re.fullmatch(r'(?i)(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s*(AM|PM))?',value)
        if not match or int(match[1])>23 or int(match[2])>59 or (match[3] and int(match[3])>59) or (match[4] and not 1<=int(match[1])<=12):raise ValueError('invalid_technical_value')
        return value
    if kind=='timezone':
        if not re.fullmatch(r'(?:UTC|GMT)(?:[+-](?:0\d|1[0-4]):[0-5]\d)?|[A-Z]{2,5}',value):raise ValueError('invalid_technical_value')
        return value  # Abbreviations never imply a unique UTC offset.
    raise ValueError('invalid_technical_value')


def reconcile(packet, candidates, units):
    exposed={u['id']:u for u in units};rejected=[];accepted=[];seen={}
    for index,candidate in enumerate(candidates):
        rule=None
        cited=[exposed[s] for s in candidate['source_ids'] if s in exposed]
        spans=occurrences(candidate['literal'],cited,packet['inputs'])
        kind=candidate['type'];value=candidate['literal']
        if len(cited)!=len(candidate['source_ids']):rule='unknown_source_id'
        elif not spans:rule='unsupported_candidate_literal'
        if (kind=='person' and candidate.get('category')=='account') or (kind=='account' and candidate.get('category')=='person'):rule='incompatible_candidate_category'
        if spans and kind in TECHNICAL:
            # Reject a substring cut out of a longer technical token, or a known
            # complete quoted path/filename. Spaces still require model review.
            from .briefing_boundaries import candidates as boundaries
            for span in spans:
                text=packet['inputs'][span['source']];a=span['start'];b=span['end']
                if (a and re.match(r'[\w\\]',text[a-1])) or (b<len(text) and re.match(r'[\w\\]',text[b])):
                    rule=rule or 'incomplete_candidate_literal'
                if kind in ('filename','windows_path'):
                    paths,files=boundaries(text)
                    if any(c.start<=a and b<=c.end and (a,b)!=(c.start,c.end) for c in paths+files):
                        rule=rule or 'incomplete_candidate_literal'
        unspecified=candidate.get('status') in ('unknown','not_provided','not_applicable')
        try:normalized=technical(kind,value) if kind in TECHNICAL and not unspecified else value
        except ValueError:rule=rule or 'invalid_technical_value';normalized=value
        from .briefing_literals import unsupported,claims_proof
        if rule is None and (claims_proof(candidate['description']) or unsupported(candidate['description'],packet['inputs'],cited)):
            rule='unsupported_candidate_description'
        if rule:
            rejected.append({'item_index':index,'rule':rule,'component':'candidate','candidate_type':kind,'category':candidate.get('category')})
            continue
        key=(kind,str(normalized),candidate['polarity'])
        if key in seen:
            prior=seen[key]
            prior['source_ids']=list(dict.fromkeys(prior['source_ids']+candidate['source_ids']))
            prior['occurrences']=[dict(t) for t in {tuple(o.items()):o for o in prior['occurrences']+spans}.values()]
            prior.setdefault('additional_interpretations',[]).append({'description':candidate['description'],'uncertainty':candidate['uncertainty']})
            for lead in packet['leads']:
                if lead['id']==prior.get('lead_id'):lead['occurrences']=prior['occurrences'][:16]
            continue
        identity='C-'+hashlib.sha256(json.dumps(key).encode()).hexdigest()[:12]
        entry={**candidate,'id':identity,'normalized':normalized,'occurrences':spans,
               'origin':'ai_semantic_classification','verification':'UNVERIFIED ANALYST INPUT',
               'technical_validation':'passed' if kind in TECHNICAL and not unspecified else 'not_applicable',
               'semantic_entailment':'not_verified'}
        accepted.append(entry);seen[key]=entry
        if kind not in TECHNICAL or unspecified:continue
        # Names/accounts, local times and timezones are context, not search filters.
        target='username' if kind=='account' else kind
        negated=candidate['polarity']=='negated'
        # Preserve deterministic negation even if a model incorrectly says reported.
        for span in spans:
            before=packet['inputs'][span['source']][max(0,span['start']-120):span['start']]
            before=re.split(r'[.!?;\n]',before)[-1]
            negated=negated or bool(re.search(r'(?i)\b(?:not|ruled out|exclude|ignore)\b',before))
        classification='ambiguous' if candidate['polarity']=='uncertain' or candidate.get('status') in ('ambiguous','conflicting') else 'exact'
        if kind in ('account','date','timestamp','ambiguous_time','timezone'):classification='contextual'
        matching=next((r for r in packet['leads'] if r['type']==target and str(r['normalized'])==str(normalized) and r['negated']==negated and r['classification'] not in ('invalid','partial','ambiguous') and classification!='ambiguous'),None)
        if matching:
            matching.setdefault('semantic_candidates',[]).append(identity)
            entry['lead_id']=matching['id']
        else:
            if len(packet['leads'])>=128:
                packet['limitations'].append('Lead bound reached; remaining AI candidates retained as context only.')
                continue
            lead_key=(target,str(normalized),classification,negated)
            lead_id='L-'+hashlib.sha256(json.dumps(lead_key).encode()).hexdigest()[:12]
            lead=dict(id=lead_id,type=target,normalized=normalized,classification=classification,negated=negated,
                      origin='ai_validated_literal',verification='UNVERIFIED ANALYST INPUT',occurrences=spans,
                      semantic_candidates=[identity],technical_validation='passed')
            if kind=='hostname':lead['hostname_basis']='ai_source_literal'
            if kind=='windows_path':lead['boundary_source_literal']=True
            packet['leads'].append(lead);entry['lead_id']=lead_id
    # Keep disagreements visible; do not select one assertion as authoritative.
    for lead in packet['leads']:
        alternatives=[r for r in packet['leads'] if r['type']==lead['type'] and r['normalized']==lead['normalized']]
        if len({r['negated'] for r in alternatives})>1:
            lead['conflicted']=True
            note='Conflicting positive and negative analyst references retained; review before discovery.'
            if note not in packet['conflicts']:packet['conflicts'].append(note)
    for entry in accepted:
        types=sorted({c['type'] for c in accepted if c['literal']==entry['literal']})
        if len(types)>1:entry['alternative_classifications']=types
    packet['ai_candidates']=accepted
    packet['semantic_coverage']='bounded_ai_classification' if accepted else 'no_semantic_candidates_accepted'
    return rejected

"""Allowlisted structural diagnostics only; never retain validator messages or values."""
import re
KEYWORDS=frozenset('required type enum const additionalProperties uniqueItems minItems maxItems minimum maximum minLength maxLength pattern anyOf oneOf allOf'.split())
PHASES=frozenset(('pre_translation','post_translation','canonical'))

def names():
    from forensic_assistant.investigation_ai.contracts import schema, TOOLS
    from forensic_assistant.interactive.advisory import SCHEMA
    result={'proposal'}
    def walk(node):
        if not isinstance(node,dict):return
        for k,v in node.get('properties',{}).items():result.add(k);walk(v)
        walk(node.get('items'))
        for key in ('oneOf','anyOf','allOf'):
            for v in node.get(key,[]):walk(v)
    walk(schema(list(TOOLS)));walk(SCHEMA)
    return result

def path(parts):
    allowed=names();result='$'
    for part in list(parts)[:24]:
        if type(part) is int and 0<=part<=1000000:result+='['+str(part)+']'
        elif type(part) is str and part in allowed:result+='.'+part
        else:return result+'.<redacted>'
    return result

def safe(value):
    if type(value) is not dict:return {}
    result={}
    for key,allowed in {'phase':PHASES,'provider_structured_validation':{'passed','failed','not_checked'},
                        'translation_status':{'success','failed','not_attempted'},
                        'canonical_validation':{'failed','not_checked'},
                        'translation_rule':{'canonical_tool_shape','translation_structure'}}.items():
        if type(value.get(key)) is str and value[key] in allowed:result[key]=value[key]
    count=value.get('error_count')
    if type(count) is int and 0<=count<=1000000:result['error_count']=count
    errors=[]
    for item in value.get('errors',[])[:5] if type(value.get('errors')) is list else []:
        if type(item) is not dict or type(item.get('validator_keyword')) is not str or item['validator_keyword'] not in KEYWORDS:continue
        candidate=item.get('canonical_path')
        if type(candidate) is not str or len(candidate)>512:continue
        parts=re.findall(r'\.([A-Za-z_][A-Za-z_0-9]*)|\[(\d+)\]|(\.<redacted>)',candidate[1:])
        rebuilt='$'+''.join('.'+a if a else '['+b+']' if b else c for a,b,c in parts)
        if rebuilt!=candidate or any(a and a not in names() for a,b,c in parts):continue
        errors.append({'error_index':len(errors)+1,'validator_keyword':item['validator_keyword'],'canonical_path':candidate})
    if errors:result['errors']=errors
    return result

def extract(contract,value,phase):
    # Select a uniquely discriminated branch for diagnostics only. Acceptance still
    # uses the complete original schema in response_contract.validate.
    if isinstance(value,dict) and 'oneOf' in contract.schema:
        matches=[]
        for branch in contract.schema['oneOf']:
            props=branch.get('properties',{})
            if props.get('action',{}).get('enum')==[value.get('action')] and (
                value.get('action')=='final' or props.get('tool',{}).get('enum')==[value.get('tool')]):matches.append(branch)
        if len(matches)==1:contract=contract.evolve(schema=matches[0])
    count=0;errors=[]
    for error in contract.iter_errors(value):
        count+=1
        if len(errors)<5:
            errors.append({'validator_keyword':error.validator,'canonical_path':path(error.absolute_path)})
    return safe({'phase':phase,'error_count':count,'errors':errors})

"""OpenAI wire representation only. Canonical investigation contracts stay unchanged."""
import copy
import json


def investigation(schema):
    """Recognize only an exact Locard-generated schema, including browser restriction."""
    if type(schema) is not dict or set(schema) != {'oneOf'} or type(schema['oneOf']) is not list:
        return False
    from forensic_assistant.investigation_ai import contracts
    try:
        names=[v['properties']['tool']['enum'][0] for v in schema['oneOf'][:-1]]
        if len(names)!=len(set(names)) or any(n not in contracts.TOOLS for n in names):
            return False
        return any(schema==contracts.schema(names,browser) for browser in (False,True))
    except (KeyError,IndexError,TypeError):
        return False


def _wire(node):
    result=copy.deepcopy(node)
    # Uniqueness is still mandatory in canonical validation after decoding.
    result.pop('uniqueItems',None)
    if result.get('type')=='object':
        required=set(node.get('required',[]))
        result['properties']={key:(_wire(value) if key in required else
            {'anyOf':[_wire(value),{'type':'null'}]}) for key,value in node['properties'].items()}
        result['required']=list(node['properties'])
    elif result.get('type')=='array':
        result['items']=_wire(node['items'])
    return result


def request_schema(provider, canonical):
    if provider!='openai' or not investigation(canonical):
        return canonical
    return {'type':'object','additionalProperties':False,'required':['proposal'],
            'properties':{'proposal':{'anyOf':[_wire(v) for v in canonical['oneOf']]}}}


def instruct(messages):
    result=copy.deepcopy(messages)
    instruction=('Transport format: return exactly one top-level JSON object with the required '
                 'property "proposal". Place the requested tool or final action object inside '
                 '"proposal". Set unused optional argument fields to null; do not invent values. '
                 'The action/tool discriminators must identify exactly one proposal.')
    if result and result[0].get('role')=='system' and isinstance(result[0].get('content'),str):
        result[0]['content']+='\n'+instruction
    else:
        result.insert(0,{'role':'system','content':instruction})
    return result


def _decode(value, canonical):
    if canonical.get('type')=='object':
        required=set(canonical['required'])
        return {key:_decode(item,canonical['properties'][key]) for key,item in value.items()
                if item is not None or key in required}
    if canonical.get('type')=='array':
        return [_decode(item,canonical['items']) for item in value]
    return value


def response(provider,text,canonical):
    from .response_contract import validate
    from .provider_diagnostics import ProviderFailure
    wire=request_schema(provider,canonical)
    if wire is canonical:
        validate(text,canonical)
        return text
    value=validate(text,wire)['proposal']
    matches=[v for v in canonical['oneOf'] if
             v['properties']['action']['enum']==[value.get('action')] and
             (value.get('action')=='final' or v['properties']['tool']['enum']==[value.get('tool')])]
    if len(matches)!=1:
        raise ProviderFailure('structured_validation','structured_validation')
    result=json.dumps(_decode(value,matches[0]),ensure_ascii=True)
    validate(result,canonical)
    return result

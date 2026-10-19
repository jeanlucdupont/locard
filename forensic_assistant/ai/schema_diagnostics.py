"""Content-free bounded schema shape diagnostics. No property/enum values emitted."""
COUNTS=('property_count','required_count','optional_property_count','nesting_depth',
        'array_count','object_count','enum_count','anyOf_count','oneOf_count','allOf_count',
        'nullable_union_count','ref_count','additionalProperties_false_count',
        'pattern_properties_count','min_max_constraint_count','unique_items_count')
NAMES=('handshake','advisory','investigation_proposal','structured_response')
TYPES=('object','array','string','number','integer','boolean','null','union','unspecified')
RULES=('root_object_required','all_properties_required','additional_properties_false_required',
       'unsupported_oneOf','unsupported_uniqueItems','unsupported_allOf','unsupported_patternProperties')


def profile(schema,name='structured_response'):
    result={key:0 for key in COUNTS}
    result['schema_name']=name if name in NAMES else 'structured_response'
    kind=schema.get('type') if isinstance(schema,dict) else None
    result['top_level_type']=kind if isinstance(kind,str) and kind in TYPES else 'union' if isinstance(schema,dict) and ('oneOf' in schema or 'anyOf' in schema) else 'unspecified'
    def walk(node,depth):
        if type(node) is not dict or depth>64:return
        result['nesting_depth']=max(result['nesting_depth'],depth)
        props=node.get('properties',{})
        if type(props) is dict:
            result['property_count']+=len(props)
            required=node.get('required',[])
            required=required if type(required) is list else []
            result['required_count']+=len(required)
            result['optional_property_count']+=sum(k not in required for k in props)
            for item in props.values():walk(item,depth+1)
        for kind in ('array','object'):
            result[kind+'_count']+=node.get('type')==kind
        result['enum_count']+='enum' in node
        result['ref_count']+='$ref' in node
        result['additionalProperties_false_count']+=node.get('additionalProperties') is False
        result['pattern_properties_count']+='patternProperties' in node
        result['unique_items_count']+='uniqueItems' in node
        result['min_max_constraint_count']+=sum(k in node for k in ('minimum','maximum','minLength','maxLength','minItems','maxItems','minProperties','maxProperties','exclusiveMinimum','exclusiveMaximum'))
        result['nullable_union_count']+=isinstance(node.get('type'),list) and 'null' in node['type']
        for key in ('anyOf','oneOf','allOf'):
            variants=node.get(key,[])
            if type(variants) is list and key in node:
                result[key+'_count']+=1
                result['nullable_union_count']+=any(type(v) is dict and v.get('type')=='null' for v in variants)
                for item in variants:walk(item,depth+1)
        walk(node.get('items'),depth+1)
    walk(schema,1)
    return safe_profile(result)


def safe_profile(value):
    if type(value) is not dict:return {}
    result={k:value[k] for k in COUNTS if type(value.get(k)) is int and 0<=value[k]<=100000}
    for key,allowed in (('schema_name',NAMES),('top_level_type',TYPES)):
        if type(value.get(key)) is str and value[key] in allowed:result[key]=value[key]
    return result


def rule(message):
    if type(message) is not str or len(message)>4096:return None
    text=message.lower()
    # Emit only fixed rule labels, never the matched text, schema paths or property names.
    if 'required' in text and ('all properties' in text or 'every key' in text):return 'all_properties_required'
    if 'additionalproperties' in text and 'false' in text:return 'additional_properties_false_required'
    if ('root' in text or 'schema must be' in text) and 'object' in text:return 'root_object_required'
    for keyword in ('oneOf','uniqueItems','allOf','patternProperties'):
        if keyword.lower() in text and any(p in text for p in ('not permitted','not supported','unsupported')):
            return 'unsupported_'+keyword
    return None


def profiles(provider, schema):
    from .openai_schema import investigation, request_schema
    name = 'investigation_proposal' if investigation(schema) else 'structured_response'
    if isinstance(schema, dict):
        fields = set(schema.get('properties', {}))
        if fields == {'goal', 'assessment', 'steps', 'cautions'}:
            name = 'advisory'
        elif fields in ({'status'}, {'status', 'message'}):
            name = 'handshake'
    return {'schema_profile': profile(schema, name),
            'provider_schema_profile': profile(request_schema(provider, schema), name)}

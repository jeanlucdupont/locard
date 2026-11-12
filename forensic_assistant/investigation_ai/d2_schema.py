"""Packet-specific wire restrictions; canonical d2q1 authority is unchanged."""
import copy
import re

POLICY = 'd2-typed-reference-schema-v1'


def _aliases(values, prefix, maximum):
    if (type(values) is not list or len(values)>maximum
            or values!=[prefix+str(i+1) for i in range(len(values))]):
        raise ValueError('D2_REFERENCE_SCHEMA')
    return values


def build(originals, interpretations):
    from .d2_quality import SCHEMA
    originals=_aliases(originals,'O',12)
    interpretations=_aliases(interpretations,'I',4)
    if not originals:raise ValueError('D2_REFERENCE_SCHEMA')
    schema=copy.deepcopy(SCHEMA)
    fields=schema['properties']['a']['items']['properties']
    for key,aliases in (('e',originals),('c',originals),('i',interpretations)):
        # Exact enums imply the canonical alias length bounds. Empty namespace
        # permits no items, not an invented sentinel or an invalid empty enum.
        fields[key]['items']={'type':'string','enum':list(aliases)} if aliases else {'type':'string'}
        if not aliases:fields[key]['maxItems']=0
    return schema


def from_packet(packet):
    body=packet['content']
    return build([s['alias'] for s in body['supports']], [s['alias'] for s in body['interpretations']])


def from_view(view):
    if view.get('wire_version')!='d2q1':raise ValueError('D2_REFERENCE_SCHEMA')
    return build([s[0] for s in view['supports']], [s['alias'] for s in view['interpretations']])


def recognized(schema):
    try:
        fields=schema['properties']['a']['items']['properties']
        originals=fields['e']['items']['enum']
        interpretations=fields['i']['items'].get('enum',[])
        return schema==build(originals,interpretations)
    except (KeyError,TypeError,ValueError,AttributeError):return False


def reference_detail(path, value, packet):
    """Closed diagnostic vocabulary; never return the rejected reference."""
    if (len(path)==3 and path[0]=='a' and path[2]=='i'
            and not packet['content']['interpretations'] and type(value) is list and value):
        path=path+[0];value=value[0]
    if (len(path)!=4 or path[0]!='a' or type(path[1]) is not int
            or not 0<=path[1]<2 or path[2] not in ('e','c','i') or type(path[3]) is not int):return None
    expected='I' if path[2]=='i' else 'O'
    match=re.fullmatch(r'([OIECPDRV])([1-9][0-9]*)',value) if type(value) is str else None
    reason=('malformed_reference' if match is None else
            'wrong_namespace' if match[1]!=expected else 'not_in_current_packet')
    body=packet['content']
    namespaces={s['alias'] for s in body['supports']+body['interpretations']+body['relationships']}
    for key in ('records','clauses','sources','lineages'):namespaces.update(body[key])
    namespaces.add('V1')
    return dict(pointer='/a/'+str(path[1])+'/'+path[2],reference_namespace=expected,
                reference_reason=reason,other_namespace_member=type(value) is str and value in namespaces)

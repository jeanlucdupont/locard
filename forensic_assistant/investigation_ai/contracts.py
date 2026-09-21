"""Closed forensic vocabulary and strict JSON validation; no dynamic dispatch."""
import ipaddress
import json
import re
from forensic_assistant.retrieval.queries import required_time
from forensic_assistant.correlation.models import time_ns

VERSION='1'
EID=re.compile(r'(?:(?:EVTX|MFT):[a-f0-9]{64}:Offset:[0-9]+|PREFETCH:[a-f0-9]{64}:File|REGISTRY:[a-f0-9]{64}:(?:KeyOffset|ValueOffset):[0-9]+)\Z')

def string(maximum=1024):return {'type':'string','minLength':1,'maxLength':maximum}
def integer(lo,hi):return {'type':'integer','minimum':lo,'maximum':hi}
def enumeration(*values):return {'type':'string','enum':list(values)}
def obj(properties,required=()):return {'type':'object','additionalProperties':False,'properties':properties,'required':list(required)}
def array(items,maximum=8,minimum=0):return {'type':'array','items':items,'maxItems':maximum,'minItems':minimum,'uniqueItems':True}

FILTERS={'artifact':enumeration('evtx','mft','prefetch','registry'),**{k:string() for k in ('hostname','username','process','path','ip')},
         'event_id':integer(0,65535),'start':string(40),'end':string(40)}
ANCHOR={'evidence_id':string(160)}
TOOLS={
 'search_evidence':('Search case metadata using exact SQL filters.',obj({**FILTERS,'limit':integer(1,50)})),
 'semantic_search':('Find candidates; similarity establishes no relationship or confidence.',obj({'query':string(1000),**FILTERS,'limit':integer(1,20)},('query',))),
 'show_evidence':('Inspect a known original evidence record; bounded fields only.',obj(ANCHOR,('evidence_id',))),
 'timeline':('Read timestamp observations with their original meanings.',obj({**FILTERS,'limit':integer(1,50)},('start','end'))),
 'around':('Same-host neighbors; choose a timestamp slot if ambiguous.',obj({**ANCHOR,'timestamp_slot':string(128),'seconds':integer(0,3600),'direction':enumeration('before','after','around'),'limit':integer(1,50)},('evidence_id',))),
 'process_tree':('Existing EVTX process relationships; preserve engine uncertainty.',obj({**ANCHOR,'seconds':integer(1,3600),'max_nodes':integer(1,50),'max_depth':integer(1,6)},('evidence_id',))),
 'session':('Existing session from a successful-logon anchor; no invented identity.',obj({**ANCHOR,'max_hours':integer(1,24),'limit':integer(1,50)},('evidence_id',))),
 'detections':('Evaluate one installed deterministic rule; not proof of compromise.',obj({'rule_id':string(64),'start':string(40),'end':string(40),'hostname':string(),'username':string(),'limit':integer(1,25)},('rule_id',))),
 'investigate_evidence':('Bounded existing cross-artifact investigation; preserve statuses.',obj({**ANCHOR,'timestamp_slot':string(128),'seconds':integer(0,3600),'limit':integer(1,50)},('evidence_id',))),
}
# Heterogeneous compact records retain artifact-specific fields. The shared
# envelope is closed; source-owned record projection defines the nested fields.
OUTPUT_SCHEMA = {
 'type':'object','additionalProperties':False,
 'required':['tool','behavior','records','relationships','detections','limitations','returned_count','truncated','semantic_candidates','label'],
 'properties':{
  'tool':{'type':'string'},'behavior':{'enum':['deterministic','semantic']},
  'records':{'type':'array','maxItems':50,'items':{'type':'object','required':['id'],'properties':{'id':string(160)}}},
  'relationships':{'type':'array','maxItems':100,'items':{'type':'object','required':['relationship_id','relationship','status','evidence_ids']}},
  'detections':{'type':'array','maxItems':25,'items':{'type':'object','required':['detection_id','rule_id','evidence_ids']}},
  'limitations':{'type':'array','items':{'type':'string'}},'returned_count':integer(0,50),
  'truncated':{'type':'boolean'},'semantic_candidates':{'type':'array','maxItems':20},
  'label':{'const':'UNTRUSTED FORENSIC EVIDENCE'},
  'plan':{'type':'object'},'semantic_used':{'type':'boolean'},
 }}

def catalog():
    return {name:{'name':name,'description':description,'input_schema':schema,'output_schema':OUTPUT_SCHEMA,
             'requires_semantic_index':name=='semantic_search',
             'behavior':'semantic' if name=='semantic_search' else 'deterministic',
             'maximum_records':50,'semantics':description}
            for name,(description,schema) in TOOLS.items()}

def validate_output(result):
    if type(result) is not dict or not set(OUTPUT_SCHEMA['required'])<=result.keys() or not result.keys()<=OUTPUT_SCHEMA['properties'].keys():
        raise ValueError('Invalid forensic result envelope')
    if result['label']!='UNTRUSTED FORENSIC EVIDENCE' or type(result['truncated']) is not bool:
        raise ValueError('Invalid forensic result labeling')
    for name,maximum in (('records',50),('relationships',100),('detections',25),('semantic_candidates',20)):
        if type(result[name]) is not list or len(result[name])>maximum:raise ValueError('Forensic output count exceeded')
    ids=[]
    for record in result['records']:
        eid=record.get('id') if type(record) is dict else None
        if type(eid) is not str or len(eid)>160 or not EID.fullmatch(eid):raise ValueError('Invalid original evidence ID in result')
        ids.append(eid)
    if len(set(ids))!=len(ids) or type(result['returned_count']) is not int or result['returned_count']!=len(ids):
        raise ValueError('Forensic result count/identity mismatch')
    for section in ('relationships','detections'):
        key='relationship_id' if section=='relationships' else 'detection_id'
        for item in result[section]:
            if type(item) is not dict or type(item.get(key)) is not str or type(item.get('evidence_ids')) is not list or any(type(eid) is not str for eid in item['evidence_ids']) or not set(item['evidence_ids'])<=set(ids):
                raise ValueError('Forensic object has missing supporting evidence')
FINAL=obj({
 'observed':array(obj({'evidence_id':string(160),'field':string(256)},('evidence_id','field')),3),
 'relationships':array(string(80),3),
 'detections':array(string(160),3),
 'hypotheses':array(obj({'statement':string(400),'evidence_ids':array(string(160),8,1),'alternatives':array(string(200),3)},('statement','evidence_ids','alternatives')),3),
 'unknowns':array(string(200),3),
},('observed','relationships','detections','hypotheses','unknowns'))

def validate(value,schema,path='request'):
    kind=schema['type']
    types={'object':dict,'array':list,'string':str,'integer':int}
    if type(value) is not types[kind]:raise ValueError(path+': wrong type')
    if kind=='object':
        if not set(schema['required'])<=value.keys():raise ValueError(path+': missing parameter')
        if not value.keys()<=schema['properties'].keys():raise ValueError(path+': unknown parameter')
        for key,item in value.items():validate(item,schema['properties'][key],path+'.'+key)
    elif kind=='array':
        if not schema.get('minItems',0)<=len(value)<=schema['maxItems']:raise ValueError(path+': invalid item count')
        if len({json.dumps(v,sort_keys=True) for v in value})!=len(value):raise ValueError(path+': duplicate items')
        for item in value:validate(item,schema['items'],path+'[]')
    elif kind=='string':
        if '\x00' in value or not value.strip() or len(value.encode('utf-8'))>schema.get('maxLength',1024):raise ValueError(path+': invalid string length/content')
    elif not schema['minimum']<=value<=schema['maximum']:raise ValueError(path+': value outside bounds')
    if 'enum' in schema and value not in schema['enum']:raise ValueError(path+': unsupported value')

def loads(text):
    if not isinstance(text,str) or len(text.encode())>16384:raise ValueError('Model response exceeds content limit')
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('Duplicate JSON key')
            result[key]=value
        return result
    def reject(value):raise ValueError('Nonfinite JSON value')
    try:return json.loads(text,object_pairs_hook=pairs,parse_constant=reject)
    except (RecursionError,json.JSONDecodeError) as exc:raise ValueError('Malformed structured response') from exc

def arguments(name,args):
    if name not in TOOLS:raise ValueError('Unknown forensic tool')
    validate(args,TOOLS[name][1]);args=dict(args)
    if 'evidence_id' in args and not EID.fullmatch(args['evidence_id']):raise ValueError('Malformed evidence ID')
    for k in ('start','end'):
        if k in args:args[k]=required_time(args[k])
    if 'ip' in args:args['ip']=str(ipaddress.ip_address(args['ip']))
    if 'start' in args and 'end' in args:
        span=time_ns(args['end'])-time_ns(args['start'])
        if not 0<=span<=86400*10**9:raise ValueError('Time window exceeds 24 hours or is reversed')
    if name=='search_evidence' and not any(k in args for k in FILTERS):raise ValueError('Search needs at least one scope filter')
    defaults={'limit':20}
    if name=='process_tree':defaults={'seconds':300,'max_nodes':20,'max_depth':4}
    if name=='around':defaults.update(seconds=120,direction='around')
    if name=='session':defaults['max_hours']=24
    if name=='investigate_evidence':defaults['seconds']=120
    if name=='show_evidence':defaults={}
    if name=='semantic_search':defaults['limit']=10
    return {**defaults,**args}

def request(text,advertised):
    value=loads(text)
    if not isinstance(value,dict):raise ValueError('Response must be an object')
    if value.get('action')=='final':
        validate(value,obj({'action':enumeration('final'),'answer':FINAL},('action','answer')))
        return value
    name=value.get('tool')
    if type(name) is not str or name not in TOOLS or name not in advertised:raise ValueError('Tool is unknown or not applicable')
    validate(value,obj({'action':enumeration('tool'),'tool':enumeration(name),'arguments':TOOLS[name][1],'reason':string(256)},('action','tool','arguments','reason')))
    value['arguments']=arguments(value['tool'],value['arguments'])
    return value

def schema(advertised):
    return {'oneOf':[obj({'action':enumeration('tool'),'tool':enumeration(name),'arguments':TOOLS[name][1],'reason':string(256)},('action','tool','arguments','reason')) for name in advertised]+
       [obj({'action':enumeration('final'),'answer':FINAL},('action','answer'))]}

def normalized_call(name,args):
    args=dict(args)
    from forensic_assistant.artifacts.paths import normalize_path
    for key in ('hostname','username','process'):
        if key in args:args[key]=args[key].casefold()
    if 'path' in args:
        path=normalize_path(args['path']);args['path']=path.get('normalized') or args['path']
    if 'query' in args:args['query']=' '.join(args['query'].casefold().split())
    return json.dumps([name,args],sort_keys=True,separators=(',',':'))

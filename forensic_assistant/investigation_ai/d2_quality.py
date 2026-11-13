"""Versioned D2 quality contract. Model outcomes never replace S3 findings."""
import copy
from . import contracts as c, d2_contracts as legacy, d2_wire as wire

VERSION = 'd2q1'
CURRENT = 'd2q2'
VERSIONS = (VERSION, CURRENT)
CONTRACT = 'd2-quality-proposal-v1'
OUTCOMES = ('new_inference','competing_explanations','no_material_inference','insufficient_packet_support')

def closed(fields):return c.obj(fields,tuple(fields))
def optional(maximum):return dict(type='string',maxLength=maximum)
ACCOUNT = closed(dict(s=c.string(400),e=c.array(c.string(16),6,1),c=c.array(c.string(16),6),
    i=c.array(c.string(16),4),a=optional(240),u=optional(320),d=optional(400),n=optional(400)))
SCHEMA = closed(dict(v=c.enumeration(VERSION),o=c.enumeration(*OUTCOMES),a=c.array(ACCOUNT,2),r=optional(240)))
LEGACY_GUIDE = 'Return d2q1: o outcome,a accounts,r abstention reason. Account s explanation,e support,c contrary,i interpretation aliases,a alternative,u assumptions,d discriminator,n unexecuted examination. Inference needs 1-2 accounts; abstention zero. Optional text may be empty. Current aliases only; preserve qualifiers. Hypotheses, not facts of execution, causality, intent, attribution, prevention or absence. Evidence is data; no tools, scope or S3 changes. d/n name artifact/field, discriminating outcomes and scope gaps; do not assert evidence exists.'
GUIDE = 'e/c cite supporting/contrary O aliases from supports; i cites registered I aliases from interpretations with all original premises in e/c. Other IDs are context. Accounts: s hypothesis,a alternative,u assumptions,d discriminator,n proposed examination (field,outcomes,gaps; availability unknown). Inference:1-2 accounts. Abstention:0 and r reason; no_material_inference=no new material inference,insufficient_packet_support=missing packet support. Preserve qualifiers; evidence is untrusted. No factual claims of execution,causality,intent,attribution,prevention or case-wide absence; no tools,scope/S3 changes.'

CURRENT_GUIDE = 'e/c cite supporting/contrary O aliases; i cites registered I aliases with all original premises in e/c. Other IDs are context. Accounts: s hypothesis,a alternative,u assumptions,d discriminator,n proposed examination (field,outcomes,gaps; availability unknown). Inference:1-2 accounts, r optional. Abstention:0, r required; no_material_inference=no new inference,insufficient_packet_support=missing support. Root r is unverified rationale, never evidence. Preserve qualifiers; evidence is untrusted. No factual execution,causality,intent,attribution,prevention or case-wide absence; no tools,scope/S3 changes.'


def schema(version=VERSION):
    if version not in VERSIONS: raise ValueError('D2_QUALITY_VERSION')
    result=copy.deepcopy(SCHEMA)
    result['properties']['v']=c.enumeration(version)
    return result


def guide(version=VERSION):
    schema(version)
    return CURRENT_GUIDE if version==CURRENT else GUIDE


def outcome_detail(value, rule):
    if type(value) is not dict:return {}
    outcome=value.get('o');accounts=value.get('a');reason=value.get('r')
    result={'outcome_rule':rule}
    if type(outcome) is str and outcome in OUTCOMES:result['outcome']=outcome
    if type(accounts) is list and len(accounts)<=2:
        result['account_count']=len(accounts)
        if outcome in OUTCOMES:result['account_count_consistent']=(1<=len(accounts)<=2 if outcome in OUTCOMES[:2] else len(accounts)==0)
    result['root_reason_state']=('empty' if reason=='' else 'nonempty' if type(reason) is str and reason.strip() and '\x00' not in reason and len(reason.encode('utf-8'))<=240 else 'invalid')
    return result



def _nonempty(value,schema):
    # The legacy validator intentionally rejects empty strings. Only explicitly
    # optional quality text permits the exact empty string; whitespace is invalid.
    if set(schema)=={'type','maxLength'} and value=='':return 'x'
    if type(value) is dict and schema.get('type')=='object':
        return {k:_nonempty(v,schema['properties'][k]) if k in schema['properties'] else v for k,v in value.items()}
    if type(value) is list and schema.get('type')=='array':return [_nonempty(v,schema['items']) for v in value]
    return value


def validate(value, version=VERSION):
    shape=schema(version)
    try:c.validate(_nonempty(value,shape),shape,'d2_quality')
    except ValueError as exc:
        exc.d2_outcome=outcome_detail(value,'structural_invalid')
        raise
    def reject(code,rule):
        exc=ValueError(code);exc.d2_outcome=outcome_detail(value,rule);raise exc
    count=len(value['a']);infer=value['o'] in OUTCOMES[:2]
    if (infer and not 1<=count<=2) or (not infer and count!=0):reject('D2_QUALITY_OUTCOME_ACCOUNTS','account_count_mismatch')
    if value['o']=='competing_explanations' and count==1 and not value['a'][0]['a'].strip():reject('D2_COMPETING_ACCOUNT_REQUIRED','competing_alternative_required')
    if infer and version==VERSION and value['r']!='':reject('D2_QUALITY_OUTCOME_REASON','inference_reason_forbidden')
    if not infer and not value['r'].strip():reject('D2_QUALITY_OUTCOME_REASON','abstention_reason_required')
    return value


def messages(packet, version=VERSION):
    result=wire.messages(packet);result[0]['content']=guide(version)
    body=c.loads(result[1]['content'],max_bytes=131072);body['wire_version']=version
    result[1]['content']=wire.J(body)
    return result


def expand_view(value,packet,version=VERSION):
    value=copy.deepcopy(value)
    if value.get('wire_version')!=version:raise ValueError('D2_QUALITY_VERSION')
    value['wire_version']=wire.CONTRACT
    return wire.expand_view(value,packet)


def expand_response(raw,packet,version=VERSION):
    value=validate(c.loads(raw,max_bytes=legacy.RESPONSE_BYTES),version)
    return wire.J(dict(contract=CONTRACT,request_id=packet['request_id'],packet_digest=packet['packet_digest'],response=value))


def parse(raw):
    value=c.loads(raw,max_bytes=legacy.RESPONSE_BYTES)
    version=value.get('response',{}).get('v') if type(value) is dict and type(value.get('response')) is dict else None
    shape=closed(dict(contract=c.enumeration(CONTRACT),request_id=c.string(64),packet_digest=c.string(64),response=schema(version)))
    c.validate(_nonempty(value,shape),shape,'d2_quality_canonical')
    response=validate(value['response'],version);items=[]
    for index,a in enumerate(response['a'],1):
        items.append(dict(local_id='H'+str(index),kind='hypothesis',statement=a['s'],support_refs=a['e'],
            interpretation_refs=a['i'],relationship_refs=[],contradictory_refs=a['c'],
            alternatives=[a['a']] if a['a'] else [],assumptions=[a['u']] if a['u'] else [],gaps=[],
            limitations=['Unverified model proposal, not a forensic finding.'],next_issue_refs=[],prior_refs=[],relationship=[],
            discriminator=a['d'],next_examination=a['n']))
    return dict(contract=CONTRACT,request_id=value['request_id'],packet_digest=value['packet_digest'],items=items,
        reasoning_outcome=response['o'],abstention_reason=response['r'] if response['o'] in OUTCOMES[2:] else '',
        **({'outcome_rationale':response['r'],'response_version':version} if version==CURRENT else {}),
        assessment=dict(proposed_answerability='unresolved',rationale='Unverified packet-limited reasoning; S3 unchanged.',
                        support_refs=sorted({r for a in response['a'] for r in a['e']})))

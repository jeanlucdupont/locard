"""Explicitly approved synthetic native-tool diagnostic; no case inputs."""
import json
from .contracts import catalog
from forensic_assistant.ai.provider_diagnostics import ProviderFailure

STAGES=('connection','native_tools','arguments','round_trip','catalog','final_response')
TOOL={'type':'function','function':{'name':'synthetic_echo','description':'Return the supplied synthetic token; no external operations.',
    'parameters':{'type':'object','properties':{'token':{'type':'string','enum':['locard-test']}},'required':['token'],'additionalProperties':False}}}

def run(config,*,authorized=False,client=None):
    if authorized is not True:raise ValueError('Conversational diagnostic requires explicit approval for up to three billable synthetic requests; no case data is sent')
    from forensic_assistant.ai.backend import ModelBackend
    value=dict(diagnostic_level='conversation',provider=config['provider'],model=config['model'],overall='failed',**{s:'not reached' for s in STAGES})
    if config['provider']!='openai':return {**value,'reason':'Conversational provider unsupported; no fallback'}
    client=client or ModelBackend(config=config,timeout=30)
    phase='native_tools'
    messages=[{'role':'system','content':'Synthetic compatibility diagnostic only. Call synthetic_echo with token locard-test. After its result, reply with the token in a short natural-language sentence.'},
              {'role':'user','content':'Run the harmless synthetic tool now.'}]
    try:
        first=client.converse(messages,[TOOL],timeout=30,output_tokens=512,tool_choice='required')
        value['connection']='ready'
        if len(first['tool_calls'])!=1:raise ValueError('Expected exactly one synthetic tool call')
        value['native_tools']='ready';phase='arguments';call=first['tool_calls'][0]
        if call['name']!='synthetic_echo' or call['arguments']!={'token':'locard-test'}:raise ValueError('Synthetic arguments differ')
        value['arguments']='ready';phase='round_trip'
        messages += [{'role':'assistant','content':first['text'] or None,'tool_calls':[{'id':call['id'],'type':'function','function':{'name':call['name'],'arguments':json.dumps(call['arguments'])}}]},
                     {'role':'tool','tool_call_id':call['id'],'content':'{"token":"locard-test"}'}]
        final=client.converse(messages,[TOOL],timeout=30,output_tokens=512,tool_choice='none')
        if final['tool_calls'] or 'locard-test' not in final['text'] or len(final['text'].strip())<=len('locard-test'):raise ValueError('Synthetic final response failed')
        value['round_trip']=value['final_response']='ready';phase='catalog'
        result=client.converse([{'role':'user','content':'Synthetic catalog compatibility check. Do not call tools or inspect evidence. Reply with the sentence: Catalog accepted.'}],catalog(),timeout=30,output_tokens=512,tool_choice='none')
        if result['tool_calls'] or not result['text'].strip():raise ValueError('Catalog response failed')
        value['catalog']='ready';value['overall']='ready'
    except ProviderFailure as exc:
        value.update(failed_phase=phase,category=exc.category,stage=exc.stage,reason=str(exc),metadata=exc.metadata)
    except (ValueError,TypeError,KeyError) as exc:
        from forensic_assistant.ai.provider_diagnostics import record
        logged=record('openai',config['model'],'response_parse','conversation_envelope',operation='conversation',metadata={'conversation':{'location':'diagnostic'}})
        value.update(failed_phase=phase,category='conversation_envelope',reason='Synthetic round-trip contract failed.'+(' See ai logs.' if logged else ' Provider diagnostic log unavailable.'))
    return value

def render(value):
    from forensic_assistant.terminal import safe_span_text
    labels={'provider':'Provider','model':'Model','connection':'Connection','native_tools':'Native tool calling','arguments':'Tool argument decoding',
            'round_trip':'Tool-result round trip','catalog':'Production tool catalog','final_response':'Final conversational response','overall':'Overall status','failed_phase':'Failed phase','category':'Category','reason':'Reason'}
    return 'AI conversational compatibility\n'+'\n'.join('  '+label+': '+safe_span_text(str(value[key])) for key,label in labels.items() if key in value)

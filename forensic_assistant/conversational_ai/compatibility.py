"""Explicitly approved synthetic native-tool diagnostic; no case inputs."""
import json
from .contracts import catalog
from .provider import assistant_message
from forensic_assistant.ai.provider_diagnostics import ProviderFailure

STAGES=('connection','native_tools','arguments','round_trip','catalog','final_response','multi_call','successive_rounds')
TOOL={'type':'function','function':{'name':'synthetic_echo','description':'Return the supplied synthetic token; no external operations.',
    'parameters':{'type':'object','properties':{'token':{'type':'string','enum':['locard-test']}},'required':['token'],'additionalProperties':False}}}

def run(config,*,authorized=False,client=None):
    if authorized is not True:raise ValueError('Conversational diagnostic requires explicit approval for up to four billable synthetic requests; no case data is sent')
    from forensic_assistant.ai.backend import ModelBackend
    value=dict(diagnostic_level='conversation',provider=config['provider'],model=config['model'],overall='failed',**{s:'not reached' for s in STAGES})
    if config['provider']!='openai':return {**value,'reason':'Conversational provider unsupported; no fallback'}
    client=client or ModelBackend(config=config,timeout=30)
    phase='native_tools'
    messages=[{'role':'system','content':'Synthetic compatibility diagnostic only. Call synthetic_echo six times independently with token locard-test. No real evidence or external operations are involved.'},
              {'role':'user','content':'Run the harmless synthetic tool now.'}]
    try:
        first=client.converse(messages,[TOOL],timeout=30,output_tokens=2048,tool_choice='required')
        value['connection']='ready'
        if not first['tool_calls']:raise ValueError('Expected synthetic tool calls')
        value['returned_calls']=len(first['tool_calls'])
        value['multi_call']='ready' if len(first['tool_calls'])>4 else 'not demonstrated: provider returned fewer than five calls'
        value['native_tools']='ready';phase='arguments'
        def append_results(response):
            messages.append(assistant_message(response))
            for call in response['tool_calls']:
                if call['name']!='synthetic_echo' or call['arguments']!={'token':'locard-test'}:raise ValueError('Synthetic arguments differ')
                messages.append({'role':'tool','tool_call_id':call['id'],'content':'{"token":"locard-test"}'})
        append_results(first)
        value['arguments']='ready';phase='round_trip'
        messages.append({'role':'user','content':'Now call synthetic_echo once more with the same token to test a successive tool round.'})
        second=client.converse(messages,[TOOL],timeout=30,output_tokens=2048,tool_choice='required')
        if not second['tool_calls']:raise ValueError('Successive tool round not demonstrated')
        append_results(second);value['successive_rounds']='ready'
        final=client.converse(messages,[TOOL],timeout=30,output_tokens=512,tool_choice='none')
        if final['tool_calls'] or 'locard-test' not in final['text'] or len(final['text'].strip())<=len('locard-test'):raise ValueError('Synthetic final response failed')
        value['round_trip']=value['final_response']='ready';phase='catalog'
        result=client.converse([{'role':'user','content':'Synthetic catalog compatibility check. Do not call tools or inspect evidence. Reply with the sentence: Catalog accepted.'}],catalog(),timeout=30,output_tokens=512,tool_choice='none')
        if result['tool_calls'] or not result['text'].strip():raise ValueError('Catalog response failed')
        value['catalog']='ready';value['overall']='ready' if value['multi_call']=='ready' else 'partial: multi-call coverage not demonstrated'
    except ProviderFailure as exc:
        value.update(failed_phase=phase,category=exc.category,stage=exc.stage,reason=str(exc),metadata=exc.metadata)
    except (ValueError,TypeError,KeyError) as exc:
        from forensic_assistant.ai.provider_diagnostics import record
        logged=record('openai',config['model'],'response_parse','conversation_envelope',operation='conversation',metadata={'conversation':{'location':'diagnostic'}})
        value.update(failed_phase=phase,category='conversation_envelope',reason='Synthetic round-trip contract failed.'+(' See ai logs.' if logged else ' Provider diagnostic log unavailable.'))
    return value

def render(value):
    from forensic_assistant.terminal import safe_span_text
    labels={'multi_call':'More-than-four tool calls','successive_rounds':'Successive tool rounds','returned_calls':'First returned call count','provider':'Provider','model':'Model','connection':'Connection','native_tools':'Native tool calling','arguments':'Tool argument decoding',
            'round_trip':'Tool-result round trip','catalog':'Production tool catalog','final_response':'Final conversational response','overall':'Overall status','failed_phase':'Failed phase','category':'Category','reason':'Reason'}
    return 'AI conversational compatibility\n'+'\n'.join('  '+label+': '+safe_span_text(str(value[key])) for key,label in labels.items() if key in value)

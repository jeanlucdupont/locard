import copy
import json
from types import SimpleNamespace as NS
import pytest
from forensic_assistant.ai import anthropic_strategy as a, readiness
from forensic_assistant.ai.provider_diagnostics import ProviderFailure, safe_metadata
from forensic_assistant.ai.response_contract import validate
from forensic_assistant.investigation_ai import contracts
from forensic_assistant.ai.schema_diagnostics import profile

C=contracts.schema(list(contracts.TOOLS))

@pytest.mark.parametrize('name',list(contracts.TOOLS))
def test_per_tool_schemas(name):
    before=copy.deepcopy(C)
    selector,variants=a.stages(C)
    validate(json.dumps({'selection':name}),selector)
    part=a.payload_schema(variants[name])
    assert part['properties']['arguments']==variants[name]['properties']['arguments']
    assert set(part['properties'])=={'arguments','reason'}
    assert profile(part)['optional_property_count']<=10
    assert profile(part)['nullable_union_count']==0
    assert C==before


def run(replies,timeout=10):
    calls=[]
    iterator=iter(replies)
    def transport(messages,schema,**kw):
        calls.append((messages,schema,kw))
        response=next(iterator)
        if isinstance(response,Exception):raise response
        return {'text':json.dumps(response),'usage':{'prompt_tokens':3,'completion_tokens':2}}
    result=a.generate(NS(_cloud_request=transport),[{'role':'user','content':'bounded context'}],C,timeout,False)
    return result,calls


def test_exact_assembly_and_usage():
    result,calls=run([{'selection':'search_evidence'},{'arguments':{'path':'loot.zip'},'reason':'Inspect candidate'}])
    assert json.loads(result['text'])=={'action':'tool','tool':'search_evidence','arguments':{'path':'loot.zip'},'reason':'Inspect candidate'}
    assert result['usage']=={'prompt_tokens':6,'completion_tokens':4}
    assert len(calls)==2 and calls[1][2]['timeout']<=calls[0][2]['timeout']
    assert calls[0][0][0]==calls[1][0][0]=={'role':'user','content':'bounded context'}
    assert result['anthropic_strategy']['canonical_validation']=='passed'
    assert 'loot.zip' not in json.dumps(safe_metadata(result))

@pytest.mark.parametrize('payload',[
 {'arguments':{'artifact':'loot.zip'},'reason':'x'},
 {'arguments':{'limit':999},'reason':'x'},
 {'arguments':{},'reason':'x','tool':'timeline'},
 {'arguments':{'bad':'value'},'reason':'x'},
 {'arguments':{}},
])
def test_invalid_second_stage(payload):
    with pytest.raises(ProviderFailure):run([{'selection':'search_evidence'},payload])


def test_unknown_selection():
    with pytest.raises(ProviderFailure):run([{'selection':'execute_shell'}])


def test_final():
    answer={'observed':[],'relationships':[],'detections':[],'hypotheses':[],'unknowns':[]}
    result,calls=run([{'selection':'final'},{'answer':answer}])
    assert json.loads(result['text'])=={'action':'final','answer':answer}
    assert set(calls[1][1]['properties'])=={'answer'}

@pytest.mark.parametrize('stage',[1,2])
def test_stage_timeout_no_retry(stage):
    replies=[ProviderFailure('timeout','timeout')] if stage==1 else [{'selection':'search_evidence'},ProviderFailure('timeout','timeout')]
    with pytest.raises(ProviderFailure) as e:run(replies)
    assert e.value.category=='timeout'
    assert e.value.metadata['anthropic_strategy']['stage'+str(stage)+'_status']=='timeout'


def test_cache_is_provider_specific(monkeypatch):
    old={p:readiness.cache_key({'provider':p,'model':'synthetic'}) for p in ('anthropic','openai','deepseek','gemini')}
    monkeypatch.setattr(a,'VERSION',a.VERSION+1)
    for p,key in old.items():assert (readiness.cache_key({'provider':p,'model':'synthetic'})!=key)==(p=='anthropic')


def test_restricted_allowlist():
    selector,_=a.stages(contracts.schema(['search_evidence']))
    assert selector['properties']['selection']['enum']==['search_evidence','search_evidence_content','final']
    with pytest.raises(ProviderFailure):validate('{"selection":"show_evidence"}',selector)



def test_final_duplicates_rejected():
    answer={'observed':[],'relationships':[],'detections':[],'hypotheses':[],'unknowns':['same','same']}
    with pytest.raises(ProviderFailure):run([{'selection':'final'},{'answer':answer}])


def test_shared_deadline_no_second_request(monkeypatch):
    clock=[0.0]
    monkeypatch.setattr(a.time,'monotonic',lambda:clock[0])
    calls=[]
    def transport(*args,**kwargs):
        calls.append(kwargs)
        clock[0]=11.0
        return {'text':'{"selection":"search_evidence"}','usage':{}}
    with pytest.raises(ProviderFailure) as error:a.generate(NS(_cloud_request=transport),[],C,10,False)
    assert error.value.category=='timeout' and len(calls)==1


def test_raw_stage_label():
    from forensic_assistant.ai import raw_diagnostics as raw
    raw.clear()
    raw.enabled=True
    raw.capture({'kind':'raw_model_output','text':'synthetic','stage':'stage2'})
    assert 'anthropic_stage2_raw_model_output' in raw.display()
    raw.clear()


def test_content_alternative_stays_within_provider_bounds_and_canonical_tool():
    selector, variants = a.stages(C)
    for branch in variants.values():
        part = a.payload_schema(branch)
        assert profile(part)['optional_property_count'] <= 10
        assert profile(part)['nullable_union_count'] == 0
    args = dict(artifact='evtx', start='2026-01-01T00:00:00Z', end='2026-01-02T00:00:00Z', evtx_text='baje.ps1')
    result, calls = run([{'selection':'search_evidence_content'}, {'arguments':args,'reason':'Inspect original recorded fields'}])
    assert json.loads(result['text']) == dict(action='tool',tool='search_evidence',arguments=args,reason='Inspect original recorded fields')
    assert result['anthropic_strategy']['selected_tool']=='search_evidence'
    with pytest.raises(ProviderFailure):
        run([{'selection':'search_evidence_content'}, {'arguments':{'evtx_text':'x'},'reason':'Narrow'}])

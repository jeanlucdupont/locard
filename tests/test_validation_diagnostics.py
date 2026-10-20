import json
import pytest
from forensic_assistant.ai import openai_schema, provider_diagnostics as pd, settings
from forensic_assistant.ai.response_contract import validate
from forensic_assistant.investigation_ai import contracts

@pytest.mark.parametrize('schema,value,rule,path',[
    ({'type':'object','properties':{'tool':{'enum':['allowed']}}},{'tool':'SECRET'},'enum','$.tool'),
    ({'type':'object','required':['tool']},{},'required','$'),
    ({'type':'object','additionalProperties':False},{'SECRET':'SECRET'},'additionalProperties','$'),
    ({'type':'object','properties':{'unknowns':{'type':'array','uniqueItems':True}}},{'unknowns':['SECRET','SECRET']},'uniqueItems','$.unknowns')])
def test_rule_path_only(schema,value,rule,path):
    with pytest.raises(pd.ProviderFailure) as caught:validate(json.dumps(value),schema)
    detail=caught.value.metadata['validation_diagnostics']
    assert detail['error_count']==1
    assert detail['errors']==[{'error_index':1,'validator_keyword':rule,'canonical_path':path}]
    assert 'SECRET' not in json.dumps(caught.value.metadata)


def test_total_count_and_five_error_cap():
    schema={'type':'array','items':{'type':'integer'}}
    with pytest.raises(pd.ProviderFailure) as caught:validate(json.dumps(['SECRET']*8),schema)
    detail=caught.value.metadata['validation_diagnostics']
    assert detail['error_count']==8 and len(detail['errors'])==5


def test_openai_post_translation_unique_diagnostic(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    schema=contracts.schema([])
    proposal={'action':'final','answer':{'observed':[],'relationships':[],'detections':[],'hypotheses':[],'unknowns':['PRIVATE-EVIDENCE']*2}}
    with pytest.raises(pd.ProviderFailure) as caught:openai_schema.response('openai',json.dumps({'proposal':proposal}),schema)
    detail=caught.value.metadata['validation_diagnostics']
    assert detail['provider_structured_validation']=='passed'
    assert detail['translation_status']=='success' and detail['canonical_validation']=='failed'
    assert detail['phase']=='post_translation'
    assert detail['errors'][0]['validator_keyword']=='uniqueItems'
    assert detail['errors'][0]['canonical_path']=='$.answer.unknowns'
    pd.record('openai','synthetic','structured_validation','structured_validation_failed',metadata=caught.value.metadata)
    raw=(settings.root()/'provider.log').read_text()
    assert 'PRIVATE-EVIDENCE' not in raw and 'uniqueItems' in pd.render(raw)
    proposal['answer']['unknowns']=[]
    assert json.loads(openai_schema.response('openai',json.dumps({'proposal':proposal}),schema))==proposal


def test_pre_translation_and_translation_failure_separate(monkeypatch):
    schema=contracts.schema([])
    with pytest.raises(pd.ProviderFailure) as caught:openai_schema.response('openai','{"proposal":{}}',schema)
    assert caught.value.metadata['validation_diagnostics']['translation_status']=='not_attempted'
    proposal={'action':'final','answer':{'observed':[],'relationships':[],'detections':[],'hypotheses':[],'unknowns':[]}}
    def broken(*a):raise ValueError('PRIVATE-EVIDENCE')
    monkeypatch.setattr(openai_schema,'_decode',broken)
    with pytest.raises(pd.ProviderFailure) as caught:openai_schema.response('openai',json.dumps({'proposal':proposal}),schema)
    detail=caught.value.metadata['validation_diagnostics']
    assert detail['translation_status']=='failed' and detail['canonical_validation']=='not_checked'
    assert 'PRIVATE-EVIDENCE' not in str(caught.value)+json.dumps(detail)


def test_untrusted_paths_rejected():
    from forensic_assistant.ai.validation_diagnostics import safe
    result=safe({'errors':[{'validator_keyword':'enum','canonical_path':'$.PRIVATE_SECRET'}], 'message':'SECRET'})
    assert result=={}

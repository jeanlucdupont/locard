"""Final-only output allowances; synthetic SDK and controller, no cloud calls."""
import json
from types import SimpleNamespace as N
import pytest
from test_assessment_handoff import saved
from test_investigation_finalization import run_sequence, answer
from test_v4_controller import Scripted
from forensic_assistant.ai import cloud_worker, settings
from forensic_assistant.ai.output_budget import final_output, output_tokens
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from forensic_assistant.investigation_ai import contracts
from forensic_assistant.investigation_ai.transcript import load


@pytest.mark.parametrize('provider', ['openai','anthropic','gemini','deepseek','xai'])
def test_final_parameter_and_ordinary_unchanged(provider, monkeypatch):
    monkeypatch.setenv(settings.PROVIDERS[provider][1], 'synthetic')
    req=dict(provider=provider,model='synthetic',messages=[],schema=contracts.schema([]),timeout=45)
    normal=cloud_worker.request_kwargs(req)
    assert normal['max_tokens']==1024 and 'max_completion_tokens' not in normal
    final=cloud_worker.request_kwargs({**req,'final_only':True})
    key='max_completion_tokens' if provider=='openai' else 'max_tokens'
    assert final[key]==4096 and final['num_retries']==0 and final['drop_params'] is False
    assert ('max_tokens' not in final) if provider=='openai' else ('max_completion_tokens' not in final)
    assert cloud_worker.request_kwargs({**req,'handshake':True,'final_only':True}) == cloud_worker.request_kwargs({**req,'handshake':True})


class SizedSDK:
    def __init__(self, text, always_truncate=False):self.text=text;self.calls=0;self.always_truncate=always_truncate
    def completion(self, **kwargs):
        self.calls+=1
        limit=kwargs.get('max_completion_tokens',kwargs.get('max_tokens'))
        truncated=self.always_truncate or limit<4096
        return N(choices=[N(finish_reason='length' if truncated else 'stop',message=N(content='' if truncated else self.text))],
                 usage=N(prompt_tokens=1000,completion_tokens=limit if truncated else 1200,total_tokens=1000+(limit if truncated else 1200)))


def test_budget_driven_envelope_failure_then_complete():
    sdk=SizedSDK('{"answer":"synthetic"}')
    with pytest.raises(ProviderFailure) as failure:
        cloud_worker.complete({'max_tokens':1024,'custom_llm_provider':'openai'},sdk)
    detail=failure.value.metadata['response_envelope']
    assert detail['output_token_limit']==detail['completion_tokens']==1024
    assert detail['envelope_received'] and detail['json_parse']==detail['canonical_validation']=='not_attempted'
    assert cloud_worker.complete({'max_completion_tokens':4096,'custom_llm_provider':'openai'},sdk)['text']=='{"answer":"synthetic"}'
    assert sdk.calls==2  # Two explicit test invocations, not an automatic retry.


@pytest.mark.parametrize('truncated',[False,True])
def test_controller_budget_final_only_and_no_retry(saved,tmp_path,monkeypatch,truncated):
    allowances=[];original=Scripted.complete
    def tracked(self,*args,**kwargs):
        allowances.append(output_tokens());return original(self,*args,**kwargs)
    monkeypatch.setattr(Scripted,'complete',tracked)
    def finish(messages):
        value=answer(messages)
        sdk=SizedSDK(json.dumps(value),truncated)
        returned=cloud_worker.complete({'max_completion_tokens':output_tokens(),'custom_llm_provider':'openai'},sdk)
        assert sdk.calls==1
        return json.loads(returned['text'])
    result,client=run_sequence(saved,tmp_path,finish)
    assert allowances==[1024,1024,1024,1024,4096] and output_tokens()==1024
    assert result['termination']==('MODEL_FAILURE' if truncated else 'ANSWER_SUPPORTED')
    assert len(client.calls)==5 and max(result['metrics']['prompt_bytes'])<=5600
    if truncated:
        assert any('Final AI response truncated' in s for s in result['limitations'])
        from forensic_assistant.investigation_ai.presentation import termination_label
        assert termination_label(result) == 'Final AI response truncated at the configured output-token limit.'
        _,events=load(tmp_path/'runs',result['investigation_id'])
        failure=next(e['data']['provider_failure'] for e in events if e['kind']=='rejected')
        assert failure['requested_output_tokens']==4096
        assert failure['response_envelope']['completion_tokens']==4096
        assert failure['grounding_validation']=='not_attempted'
        assert result['answer_origin']=='deterministic_disclosed_observations_only'


def test_context_restored_on_exception():
    with pytest.raises(RuntimeError):
        with final_output(True):
            assert output_tokens()==4096
            raise RuntimeError()
    assert output_tokens()==1024



def test_concise_structured_final_fits_existing_byte_bound():
    value = {'action':'final','answer':{
        'observed':[{'evidence_id':'EVTX:'+'a'*64+':Offset:1', 'field':f'/original_event_data/{i}/value'} for i in range(12)],
        'relationships':[], 'detections':[], 'hypotheses':[], 'interpretations':[],
        'unknowns':['Successful execution remains unresolved.', 'Coverage is incomplete.', 'Causality is not established.'],
        'answer_status':'partial'}}
    raw = json.dumps(value)
    assert len(raw.encode()) < 4096
    assert contracts.request(raw, []) == value


def test_final_flag_crosses_cloud_worker_boundary(monkeypatch):
    import importlib.util
    from forensic_assistant.ai import backend as backend_module
    monkeypatch.setenv('OPENAI_API_KEY','synthetic')
    monkeypatch.setattr(importlib.util,'find_spec',lambda name: object())
    sent=[]
    class Process:
        pid=1;returncode=0
        def communicate(self,raw,timeout):
            sent.append(json.loads(raw));return b'{"text":"{}","usage":{}}',None
        def poll(self):return 0
        def wait(self,timeout):return 0
    monkeypatch.setattr(backend_module.subprocess,'Popen',lambda *a,**k:Process())
    monkeypatch.setattr(backend_module,'WorkerJob',lambda pid:N(close=lambda:None))
    config={**settings.defaults(),'provider':'openai','model':'synthetic','cloud_acknowledged':True}
    backend=backend_module.ModelBackend(config=config)
    with final_output(True):backend._cloud_request([],contracts.schema([]))
    backend._cloud_request([],contracts.schema(['show_evidence']))
    assert [r['final_only'] for r in sent]==[True,False]
    assert cloud_worker.request_kwargs(sent[0])['max_completion_tokens']==4096
    assert cloud_worker.request_kwargs(sent[1])['max_tokens']==1024

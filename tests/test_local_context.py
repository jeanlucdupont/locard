"""Synthetic tokenizer fixtures, never llama.cpp parity or real-model acceptance."""
import json
import pytest
from forensic_assistant.conversational_ai import local_context as ctx
from forensic_assistant.conversational_ai.local import configuration
from forensic_assistant.conversational_ai.contracts import catalog
from forensic_assistant.ai.provider_diagnostics import ProviderFailure
from scripts.diagnose_local_provider import fixture_prompt,fixture_tokens


@pytest.fixture(autouse=True)
def private(tmp_path,monkeypatch):monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))

@pytest.fixture
def measured(monkeypatch):
    calls=[]
    def auxiliary(config,path,body,timeout):
        calls.append((path,body))
        if path=='/props':return {'chat_template':'mock fixture','default_generation_settings':{'n_ctx':32768}}
        if path=='/apply-template':return {'prompt':fixture_prompt(body)}
        return {'tokens':list(range(fixture_tokens(body['content'])))}
    monkeypatch.setattr(ctx,'auxiliary',auxiliary)
    return calls


def messages(size=10,tool=False):
    value=[{'role':'system','content':'Synthetic authorization'}, {'role':'user','content':'x'*size}]
    if tool:value.extend([{'role':'assistant','content':None,'tool_calls':[{'id':'c1','type':'function','function':{'name':'memory','arguments':'{"kind":"state"}'}}]}, {'role':'tool','tool_call_id':'c1','content':'{"synthetic":true}'}])
    return value


def run(meter,value,limit=256*1024,before=lambda *a:None):return meter.measure(value,catalog(),2048,limit,10,before)


@pytest.mark.parametrize('tool',[False,True])
def test_token_byte_separation_and_usage_parity(measured,tool):
    meter=ctx.ContextMeter(configuration('http://127.0.0.1:1','synthetic'),'session-a')
    first=run(meter,messages(tool=tool));assert first['method']=='byte_fallback'
    meter.observe(first,{'prompt_tokens':first['input_tokens']})
    second=run(meter,messages(40000,tool))
    assert second['request_bytes']>32768 and second['input_tokens']<32768
    assert second['fits'] and second['method']=='template_tokenizer'
    assert second['remaining_tokens']==second['measured_remaining_tokens']
    assert not run(meter,messages(140000,tool))['fits']
    assert run(meter,messages(140000,tool))['reason']=='model_tokens'
    count=len(measured)
    assert run(meter,messages(40000,tool),limit=10000)['reason']=='request_bytes'
    assert len(measured)==count


def test_no_hidden_completion_and_auxiliary_accounting(measured):
    meter=ctx.ContextMeter(configuration('http://127.0.0.1:1','synthetic'),'s');attempts=[]
    result=run(meter,messages(),before=lambda p,b:attempts.append((p,b)))
    assert len(attempts)==len(measured)==4
    assert [p for p,b in attempts]==['/props','/apply-template','/apply-template','/tokenize']
    assert attempts[-1][1]['add_special'] is True and attempts[-1][1]['parse_special'] is True
    assert result['parity']=='unverified'
    assert 'prompt' not in result and 'content' not in result


def test_mismatch_and_server_change_invalidate_counts(measured,monkeypatch):
    meter=ctx.ContextMeter(configuration('http://127.0.0.1:1','synthetic'),'s')
    first=run(meter,messages());meter.observe(first,{'prompt_tokens':first['input_tokens']+1})
    later=run(meter,messages(40000));assert not later['fits'] and later['capability']=='parity_mismatch'
    assert meter.disabled


@pytest.mark.parametrize('mode',['unsupported','malformed','timeout','network','partial'])
def test_safe_fallback(mode,monkeypatch):
    def auxiliary(config,path,body,timeout):
        if mode=='unsupported':raise ProviderFailure('request_rejected',metadata={'http_status':404})
        if mode in ('timeout','network'):raise ProviderFailure('timeout' if mode=='timeout' else 'network_error')
        if path=='/props':return {'chat_template':'fixture'}
        if path=='/apply-template':return {'prompt':'missing tools'} if mode=='partial' else {'prompt':fixture_prompt(body)}
        return {'tokens':[True]}
    monkeypatch.setattr(ctx,'auxiliary',auxiliary)
    meter=ctx.ContextMeter(configuration('http://127.0.0.1:1','synthetic'),'s')
    result=run(meter,messages());assert result['method']=='byte_fallback' and result['input_tokens'] is None
    assert meter.disabled and result['capability']!='unknown'


def test_cancellation_and_audit_failure_propagate(measured):
    meter=ctx.ContextMeter(configuration('http://127.0.0.1:1','synthetic'),'s')
    def interrupt(*a):raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):run(meter,messages(),before=interrupt)
    from forensic_assistant.conversational_ai.service import Paused
    def budget(*a):raise Paused('DISCLOSURE_LIMIT')
    with pytest.raises(Paused,match='DISCLOSURE_LIMIT'):run(meter,messages(),before=budget)
    assert not measured


def test_receipt_binds_exact_request_and_configuration(measured):
    config=configuration('http://127.0.0.1:1','synthetic');meter=ctx.ContextMeter(config,'s')
    value=messages();run(meter,value)
    assert meter.receipt(config,value,catalog(),2048,'auto')
    assert not meter.receipt(config,messages(20),catalog(),2048,'auto')
    assert not meter.receipt({**config,'model':'other'},value,catalog(),2048,'auto')


def test_local_selection_preserves_exchange_and_auxiliary_has_no_authority(tmp_path,measured):
    from test_conversational_ai import setup
    from forensic_assistant.ai.backend import ModelBackend
    from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
    from forensic_assistant.conversational_ai.service import Session,Paused
    path,_,old=setup(tmp_path,[]);provider=ModelBackend.local_conversation('http://127.0.0.1:1','synthetic')
    scope=authorize(path,old['source_ids'],old['start'],old['end'],FAMILIES,'local','synthetic',{'output_tokens':2048},local=provider.conversation_binding())
    session=Session(scope,provider,lambda _:True)
    try:
        # Warm parity with harmless fixtures, as naturally returned usage would.
        small=messages(tool=True);r=run(session.context_meter,small);session.context_meter.observe(r,{'prompt_tokens':r['input_tokens']})
        block=small[-2:];block[-1]['content']='x'*40000
        session.turns=[[{'role':'user','content':'Current synthetic objective'}],block]
        selected,_=session.messages()
        assert selected[-2:]==block and session.last_capacity['fits']
        assert session.used['requests']==0 and session.used['auxiliary_requests']>0
        assert not session.disclosed and not session.observations
        import copy
        older=copy.deepcopy(block);older[-1]['content']='OLDER'*20000
        older[0]['tool_calls'][0]['id']='older';older[-1]['tool_call_id']='older'
        session.turns=[session.turns[0],older,block]
        selected,_=session.messages()
        assert selected[-2:]==block and older[-1] not in selected
        assert session.used['context_consolidations']>0
        assert session.last_capacity['history_omitted']==1
        # An oversized indivisible latest exchange pauses, never silently loses originals.
        block[-1]['content']='x'*200000
        with pytest.raises(Paused,match='CONTEXT_CAPACITY'):session.messages()
        assert session.last_capacity['blocking_component']=='latest_required_exchange'
        assert session.used['context_consolidation_attempts']>0
    finally:session.close()
    assert provider._context_meter is None

def test_full_tokenizer_protocol_harness():
    from scripts.diagnose_local_provider import MockEndpoint,wire,tokenization_probe,successful
    from test_conversational_ai import reply
    from forensic_assistant.ai.backend import ModelBackend
    def respond(body):
        result=wire(reply('Synthetic acknowledgement.'))
        incoming=fixture_tokens(fixture_prompt(body))
        result['usage']={'prompt_tokens':incoming,'completion_tokens':5,'total_tokens':incoming+5}
        return result
    with MockEndpoint(respond,tokenizer=True) as server:
        result=tokenization_probe(ModelBackend.local_conversation(server.endpoint,'synthetic'))
        assert successful(result) and len(server.calls)==2
        assert all(r['parity']['difference']==0 for r in result['rows'])
        assert len(server.auxiliary)>2
        assert not any('prompt' in a for a in result['auxiliary'])

def test_tokenizer_timeout_contains_child(monkeypatch):
    import time
    import scripts.diagnose_local_provider as diagnostic
    from forensic_assistant.conversational_ai import local
    processes=[];original=local.subprocess.Popen
    def track(*a,**k):
        process=original(*a,**k);processes.append(process);return process
    monkeypatch.setattr(local.subprocess,'Popen',track)
    def slow(text):time.sleep(2);return 1
    monkeypatch.setattr(diagnostic,'fixture_tokens',slow)
    with diagnostic.MockEndpoint(lambda b:{},tokenizer=True) as server:
        with pytest.raises(ProviderFailure,match='timed out'):
            local.auxiliary(configuration(server.endpoint,'synthetic'),'/tokenize',{'content':'synthetic'},.3)
    assert processes and all(p.poll() is not None for p in processes)

def test_server_identity_change_resets_parity(measured,monkeypatch):
    meter=ctx.ContextMeter(configuration('http://127.0.0.1:1','synthetic'),'s')
    first=run(meter,messages());meter.observe(first,{'prompt_tokens':first['input_tokens']})
    original=ctx.auxiliary
    def changed(config,path,body,timeout):
        result=original(config,path,body,timeout)
        if path=='/props':result['chat_template']='changed fixture'
        return result
    monkeypatch.setattr(ctx,'auxiliary',changed)
    value=run(meter,messages(40000))
    assert value['method']=='byte_fallback' and not value['fits'] and not meter.parity

def test_auxiliary_disclosure_budget_prevents_transport(tmp_path,measured):
    from test_conversational_ai import setup
    from forensic_assistant.ai.backend import ModelBackend
    from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
    from forensic_assistant.conversational_ai.service import Session,Paused
    path,_,old=setup(tmp_path,[]);provider=ModelBackend.local_conversation('http://127.0.0.1:1','synthetic')
    scope=authorize(path,old['source_ids'],old['start'],old['end'],FAMILIES,'local','synthetic',{'disclosure_bytes':1},local=provider.conversation_binding())
    session=Session(scope,provider,lambda _:True)
    try:
        session.turns=[[{'role':'user','content':'Synthetic investigation'}]]
        with pytest.raises(Paused,match='DISCLOSURE_LIMIT'):session.messages()
        assert [p for p,b in measured]==['/props']
        assert session.used['requests']==0 and not session.disclosed
    finally:session.close()

def test_verified_large_request_dispatch_receipt_is_single_use(measured,monkeypatch):
    from forensic_assistant.conversational_ai import local
    from test_conversational_ai import reply
    config=configuration('http://127.0.0.1:1','synthetic');meter=ctx.ContextMeter(config,'s')
    initial=run(meter,messages());meter.observe(initial,{'prompt_tokens':initial['input_tokens']})
    value=messages(40000);result=run(meter,value);assert result['fits']
    calls=[]
    monkeypatch.setattr(local,'run_client',lambda *a:calls.append(a) or reply('synthetic'))
    local.dispatch(config,value,catalog(),10,2048,measurement=meter)
    assert len(calls)==1 and meter.last is None
    with pytest.raises(ProviderFailure):local.dispatch(config,value,catalog(),10,2048,measurement=meter)
    assert len(calls)==1

def test_tokenizer_cancellation_contains_child(monkeypatch):
    from forensic_assistant.conversational_ai import local
    from forensic_assistant.investigation_ai import lifecycle
    events=[]
    class Child:
        pid=123;returncode=None
        def communicate(self,*a,**k):raise KeyboardInterrupt()
        def poll(self):return self.returncode
        def kill(self):events.append('kill');self.returncode=-1
        def wait(self,timeout):events.append('wait');return self.returncode
    class Job:
        def __init__(self,pid):pass
        def close(self):events.append('job')
    monkeypatch.setattr(local.subprocess,'Popen',lambda *a,**k:Child())
    monkeypatch.setattr(lifecycle,'WorkerJob',Job)
    with pytest.raises(KeyboardInterrupt):local.auxiliary(configuration('http://127.0.0.1:1','synthetic'),'/tokenize',{'content':'synthetic'},10)
    assert 'kill' in events and 'wait' in events

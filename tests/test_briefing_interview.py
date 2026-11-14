"""Fake-model interview tests; no live endpoints or real cases."""
import copy
import json
import pytest
from forensic_assistant import briefing_interview as interview, briefing_store as store, briefing_workflow as workflow
from forensic_assistant import briefing
from test_briefing_persistence import store as case_store, args


def current():return store.content(dict.fromkeys(store.FIELDS,''),'')

def ask(topic='time',question='When did this happen?'):
    return {'action':'ask','topic':topic,'question':question}


def finish():return {'action':'finish','topic':'objective','question':'Ready for review.'}


class Fake:
    provider_name='local'
    def __init__(self,results):self.results=iter(results);self.calls=[]
    def complete(self,messages,schema):
        self.calls.append((messages,schema));result=next(self.results)
        if isinstance(result,Exception):raise result
        return json.dumps(result)


def run(answers,results,old=None):
    reader=iter(answers);fake=Fake(results);metrics={}
    result=interview.interview(old or current(),lambda prompt:next(reader),client_factory=lambda:fake,metrics=metrics)
    return result,fake,metrics


def test_adaptive_interview_and_provenance():
    result,fake,metrics=run(['Suspicious invoice download; determine execution.','2026-10-20','done','save'],[ask(),finish()])
    assert len(fake.calls)==2 and metrics['calls']==2
    session=result['interviews'][0]
    assert session['turns'][0]['question']=='Tell me what happened?'
    assert session['turns'][1]['question_origin']=='ai'
    inputs=store.sources({'content':result})
    assert list(inputs.values())==['Suspicious invoice download; determine execution.','2026-10-20']
    assert 'When did this happen?' not in inputs.values()
    packet=briefing.extract_inputs(inputs)
    for unit in packet['source_units']:assert inputs[unit['source']][unit['start']:unit['end']]==unit['text']
    assert metrics['assembly_seconds']>=0 and metrics['local_seconds']>=0


def test_detailed_initial_answer_finish_and_continue():
    result,fake,_=run(['On 2026-10-20 host LAB-01 ran sample.ps1. Determine initial access.','Also reported uncertainty.','done','save'],[finish()])
    assert len(fake.calls)==1 and len(result['interviews'][0]['turns'])==2


@pytest.mark.parametrize('unknown',["I don't know.",'skip',''])
def test_unknown_not_negative_and_no_repeat(unknown):
    result,fake,_=run(['Something suspicious happened.',unknown,'done','save'],[ask(),ask(question='At what time was it noticed?')])
    assert len(fake.calls)==2
    turn=result['interviews'][0]['turns'][1]
    assert turn['answer']==(unknown if unknown not in ('skip','') else '')
    if unknown in ('skip',''):assert turn['answer_status']=='skipped'


def test_early_done_cancel_no_provider():
    result,fake,_=run(['done'],[])
    assert result is None and not fake.calls
    with pytest.raises(KeyboardInterrupt):run(['cancel'],[])
    with pytest.raises(KeyboardInterrupt):run(['Reported activity','cancel'],[finish()])


@pytest.mark.parametrize('failure',[RuntimeError('SECRET raw payload'),{'invalid':'model object'},ask('time','run SECRET.exe?')])
def test_failure_keeps_answers_sanitized(failure,capsys):
    result,fake,_=run(['Suspicious activity','done','save'],[failure])
    assert result['interviews'][0]['turns'][0]['answer']=='Suspicious activity'
    output=capsys.readouterr().out
    assert ('AI questioning has stopped' in output or 'AI question was not usable' in output) and 'SECRET' not in output and len(fake.calls)==1


def test_review_correction_no_more_calls():
    result,fake,_=run(['First account','done','correct','1','Corrected account','save'],[finish()])
    assert len(fake.calls)==1
    turns=result['interviews'][0]['turns']
    assert turns[0]['answer']=='First account' and turns[1]['supersedes']==1
    assert turns[1]['answer']=='Corrected account'


def test_existing_content_supplement_and_revision():
    old=current();old['answers']['people']='Analyst supplied person';old['narrative']='Original narrative'
    result,fake,_=run(['revise','The previous narrative date is uncertain.','done','save'],[finish()],old)
    assert result['answers']==old['answers'] and result['narrative']==old['narrative']
    assert result['interviews'][0]['purpose']=='revision'
    second,_,_=run(['supplement','Additional info','done','save'],[finish()],result)
    assert second['interviews'][0]==result['interviews'][0]


def test_context_and_call_limits():
    old=current();old['narrative']='x'*13000
    result,fake,metrics=run(['supplement','Suspicious activity','done','save'],[],old)
    assert not fake.calls and metrics['calls']==0 and metrics['request_bytes'][0]>interview.MAX_CONTEXT
    topics=['time','people','systems','alerts','objective','discovery']
    questions=['When did it happen?','Who was involved?','Which systems were involved?','Were any alerts reported?','What do you want to establish?','How was the incident noticed?']
    result,fake,metrics=run(['Initial description']+['unknown']*7+['save'],[ask(t,q) for t,q in zip(topics,questions)])
    assert len(fake.calls)==interview.MAX_CALLS and len(result['interviews'][0]['turns'])==8


def test_cloud_consent_no_key_inference():
    fake=Fake([finish()]);fake.provider_name='openai';fake.config={'provider':'openai','cloud_acknowledged':False}
    reader=iter(['Reported activity','done','save'])
    result=interview.interview(current(),lambda p:next(reader),client_factory=lambda:fake)
    assert result and not fake.calls
    fake.config['cloud_acknowledged']=True
    reader=iter(['Reported activity','done','save'])
    assert interview.interview(current(),lambda p:next(reader),client_factory=lambda:fake)
    assert len(fake.calls)==1


def test_save_revision_analyze_and_editor_preserves(case_store,monkeypatch):
    from forensic_assistant import briefing_cli
    old=current();old['narrative']='Earlier narrative'
    first=case_store.save(old,None)['revisions'][-1]
    result,_,_=run(['supplement','Please investigate sample.ps1','done','save'],[finish()],old)
    saved=case_store.save(result,first['digest'])
    assert len(saved['revisions'])==2 and case_store.load()==saved
    packet=briefing_cli.run(args(case_store,'analyze','--deterministic'))
    assert packet['interview_provenance']==result['interviews']
    assert packet['analyst_source_relations'][0]['purpose']=='supplement'
    assert 'original analyst responses' in workflow.render(workflow.view(saved))
    replies=iter(['']*9+['yes'])
    assert workflow.wizard(result,lambda p:next(replies))['interviews']==result['interviews']
    with pytest.raises(ValueError,match='changed'):case_store.save(current(),first['digest'])


def test_contract_output_budget_unchanged():
    from forensic_assistant.ai.cloud_worker import request_kwargs
    from forensic_assistant.ai import openai_schema
    assert openai_schema.request_schema('openai',interview.SCHEMA)==interview.SCHEMA
    assert not openai_schema.briefing(interview.SCHEMA)


def test_previously_supplied_date_not_asked_again(capsys):
    result,fake,_=run(['On 2026-10-20 something happened.','done','save'],[ask()])
    assert len(fake.calls)==1
    assert 'Locard: When did this happen?' not in capsys.readouterr().out
    assert result['interviews'][0]['turns'][0]['answer'].startswith('On 2026')


def test_oversize_answer_can_finish_without_losing_previous():
    result,fake,_=run(['Initial report','x'*4097,'done','save'],[ask()])
    assert len(result['interviews'][0]['turns'])==1 and len(fake.calls)==1


def test_cancel_preserves_saved_case(case_store,monkeypatch):
    from forensic_assistant import briefing_cli
    first=case_store.save(current(),None);before=case_store.path.read_bytes()
    a=args(case_store,'interview');a._confirm=lambda p:'cancel'
    monkeypatch.setattr(briefing,'discover',lambda *a:pytest.fail('unexpected search'))
    with pytest.raises(KeyboardInterrupt):briefing_cli.run(a)
    assert case_store.path.read_bytes()==before


def test_tampered_sessions_rejected_and_questions_excluded():
    result,_,_=run(['A report','done','save'],[finish()])
    bad=copy.deepcopy(result);bad['interviews'][0]['turns'][0]['question_origin']='analyst'
    with pytest.raises(ValueError):store.content(bad['answers'],bad['narrative'],bad['interviews'])
    assert all('Tell me what happened?' not in value for value in store.sources({'content':result}).values())


@pytest.mark.parametrize('provider',['openai','anthropic','gemini','deepseek','xai'])
def test_interview_wire_budget_and_validation(provider,monkeypatch):
    from forensic_assistant.ai import cloud_worker,settings,response_contract
    monkeypatch.setenv(settings.PROVIDERS[provider][1],'synthetic')
    kwargs=cloud_worker.request_kwargs(dict(provider=provider,model='synthetic',schema=interview.SCHEMA,messages=[],timeout=30,handshake=False))
    assert kwargs['max_tokens']==1024 and kwargs['num_retries']==0 and kwargs['stream'] is False
    assert response_contract.validate(json.dumps(finish()),interview.SCHEMA)==finish()


def test_budget_exhaustion_before_request_and_response_bound():
    fake=Fake([finish()]);metrics={'request_bytes':[],'calls':0,'model_seconds':interview.MAX_MODEL_SECONDS}
    session={'id':'a'*32,'created':store.now(),'purpose':'supplement','turns':[]}
    with pytest.raises(ValueError,match='time_limit'):interview.decision(fake,current(),session,metrics)
    assert not fake.calls
    class Oversized(Fake):
        def complete(self,*a):self.calls.append(a);return 'x'*4097
    fake=Oversized([]);reader=iter(['Reported activity','done','save'])
    result=interview.interview(current(),lambda p:next(reader),client_factory=lambda:fake)
    assert result and len(fake.calls)==1


def test_cli_interview_persists_and_no_search(case_store,monkeypatch):
    from forensic_assistant import briefing_cli
    from forensic_assistant.ai.backend import ModelBackend
    monkeypatch.setattr(ModelBackend,'complete',lambda *a:json.dumps(finish()))
    monkeypatch.setattr(ModelBackend,'__init__',lambda self,**kw:setattr(self,'provider_name','local'))
    monkeypatch.setattr(briefing,'discover',lambda *a:pytest.fail('unexpected discovery'))
    before=case_store.case.read_bytes()
    reader=iter(['Reported script activity; establish timing.','done','save'])
    a=args(case_store,'interview');a._confirm=lambda p:next(reader)
    result=briefing_cli.run(a)
    assert result['revision']['revision']==1
    assert case_store.case.read_bytes()==before
    assert result['revision']['content']['interviews'][0]['turns'][0]['answer'].startswith('Reported script')

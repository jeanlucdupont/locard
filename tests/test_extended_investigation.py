"""Extended sessions: synthetic records and scripted providers only."""
from copy import deepcopy
from dataclasses import asdict
import json
import pytest
from forensic_assistant.investigation_ai import autonomous as a, extended as x, context_inspection as c, follow_up as f
from forensic_assistant.investigation_ai.state import Budget, ContextBudget, ExtendedBudget, execution_budget
from forensic_assistant.investigation_ai.transcript import load
from test_packet_capacity import row, grant, discovery_grant, envelope, answer, Scripted


def session(tmp_path, failure=None, count=12, exhaust=False):
    path=tmp_path/'case.db';path.touch();calls=[];closed=[];retained={};rounds=[];anchors=set()
    seeds=[row('evtx' if exhaust else ['browser','evtx','mft'][n%3],n+1) for n in range(count)]
    for n,r in enumerate(seeds):
        if r['id'].startswith('MFT:'):
            for key in ('provider','channel','event_id','command_line','original_event_data'):r.pop(key,None)
            r.update(source_type='mft',objects=['C:/synthetic/document.dat'])
        if 'command_line' in r:r['command_line']='neutral.exe'
        if 'url_chain' in r:r['url_chain']=[]
        r['source_context']={'source_ids':['source-test']}
        r['timestamps'][0]['utc']=f'2026-09-30T12:{n:02d}:00Z'
    g=discovery_grant(grant(path,seeds))
    g.update(contract=c.CAPACITY_CONTRACT,context_inspection=deepcopy(c.LIMITS),tools=['show_evidence','follow_up','inspect_context'])
    g['limits']['prompt_bytes']=24576;g=x.authorize(g);g['expires']=g['issued']+900
    view=dict(contract='sqlite-read-view-v1',view_id='a'*32,file_identity=dict(device=1,inode=1))
    class Worker:
        def __init__(self,config):pass
        def close(self):closed.append(True)
        def call(self,name,args=None,**kw):
            calls.append((name,args))
            if name in ('initial','check'):result=envelope([])
            elif name=='show_evidence':result=envelope([next(r for r in seeds if r['id']==args['evidence_id'])])
            elif name=='inspect_context':
                r=deepcopy(retained[args['evidence_id']]);r['context_category']=args['category']
                ordinal=10+['actor','object','process','event'].index(args['category'])
                r['original_event_data']=[dict(name={'actor':'SubjectUserName','object':'ObjectName','process':'ProcessName','event':'Message'}[args['category']],ordinal=ordinal,value='SyntheticValue',truncated=False)]
                result=envelope([r]);result.update(tool=name,truncated=True,plan=dict(contract=c.CONTRACT,**args,selected_ordinals=[ordinal],retained_fields=14,omitted_fields=13,limitations=['Synthetic incomplete field coverage']))
            else:
                rows=[row(args['family'],100+len(calls)*3+i) for i in range(3)]
                window=f.record_window(g,args,retained)
                for r in rows:
                    r['command_line']='neutral.exe'
                    r['source_context']={'source_ids':['source-test']};r['timestamps'][0]['utc']=window['anchor']
                result=envelope(rows);result['plan']=dict(window,returned_ids=[r['id'] for r in rows],complete=False)
            result=deepcopy(result)
            if len(calls)==9 and failure=='source':result['records'][0]['source_context']['source_ids']=['not-authorized']
            if len(calls)==9 and failure=='time':result['records'][0]['timestamps']=[dict(utc='2030-01-01T00:00:00Z')]
            retained.update((r['id'],r) for r in result['records'])
            return dict(result=result,evidence_state={**view,'view_id':'b'*32} if len(calls)==9 and failure=='view' else view,database_changes=0,schema=5,fingerprint=None)
    def model(messages):
        body=json.loads(messages[1]['content']);rounds.append(body);n=len(rounds)
        if failure in ('provider','cancel','citation') and n==8:
            if failure=='cancel':raise KeyboardInterrupt()
            if failure=='citation':return dict(action='final',answer={**answer(body['UNTRUSTED FORENSIC EVIDENCE']),'observed':[dict(evidence_id=seeds[0]['id'],field='/invented')]})
            raise ValueError('Synthetic provider failure')
        packet=body['UNTRUSTED FORENSIC EVIDENCE']
        if exhaust and (n-1)%6<4:
            return dict(action='tool',tool='inspect_context',arguments=dict(evidence_id=calls[-1][1]['evidence_id'],category=['actor','object','process','event'][(n-1)%6]),reason='Inspect a distinct original context category')
        if not exhaust and n in (1,7,13) and count>1:
            family='browser' if n==13 else 'evtx'
            eid,pointer,value=next((r['id'],o[1],o[2]) for r in packet['records'] for o in r['observations'] if o[1].startswith('/timestamps/') and o[1].endswith('/utc') and (family,o[2][:19]) not in anchors)
            anchors.add((family,value[:19]))
            return dict(action='tool',tool='follow_up',arguments=dict(evidence_id=eid,field=pointer,family=family),reason='Examine a different recorded neighborhood')
        result=answer(packet);result['interpretations']=[];result['hypotheses']=[]
        result['unknowns']=['Causality and successful execution remain unestablished.']
        return dict(action='final',answer=result)
    client=Scripted([model]*18);client.provider_name='openai';client.model_name='synthetic'
    result=a.run(dict(case_path=str(path),_stage_a=g),g['objective'],tmp_path/'runs',client=client,worker_factory=Worker)
    assert closed and path.read_bytes()==b''
    return result,calls,rounds


def test_three_batches_retain_findings_and_replay(tmp_path):
    result,calls,rounds=session(tmp_path)
    assert len(result['work_batches'])==3, (result['termination'],result.get('failure_diagnostic'))
    assert result['metrics']['ai_requests']==15
    assert result['validated_batches']==12
    assert result['termination']=='NO_FURTHER_AUTHORIZED_LEADS'
    assert [v['totals']['ai_requests'] for v in result['work_batches']]==[6,12,15]
    assert len({args['evidence_id'] for name,args in calls if name=='show_evidence'})==12
    assert rounds[6]['incremental']['previous_unresolved_unverified']
    one=a.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert one==a.reconstruct(tmp_path/'runs',result['investigation_id'])
    assert one['findings']==result['findings']
    m,e=load(tmp_path/'runs',result['investigation_id']);x.validate_checkpoints(m,e)
    forged=deepcopy(e);next(v for v in forged if v['kind']=='work_batch_checkpoint')['data']['totals']['ai_requests']+=1
    with pytest.raises(ValueError):x.validate_checkpoints(m,forged)


@pytest.mark.parametrize('failure',['provider','cancel','citation'])
def test_second_batch_failure_retains_first(tmp_path,failure):
    result,calls,rounds=session(tmp_path,failure)
    assert len(rounds)==8
    assert result['validated_batches']>=5
    assert result['work_batches'][0]['totals']['ai_requests']==6
    assert result['termination'] in ('PROVIDER_FAILURE','ANALYST_CANCELLED','VALIDATION_FAILURE')
    assert a.reconstruct(tmp_path/'runs',result['investigation_id'])['findings']==result['findings']


def test_early_stop_no_filler_requests(tmp_path):
    result,calls,rounds=session(tmp_path,count=1)
    assert len(rounds)==1 and len(result['work_batches'])==1
    assert result['termination']=='NO_FURTHER_AUTHORIZED_LEADS'


def test_old_budget_cannot_authorize_extension():
    with pytest.raises(ValueError):ContextBudget(calls=18,seconds=900)
    assert Budget().seconds==300 and ContextBudget().calls==6


def blocking_child(connection,gate,request):
    import time
    from forensic_assistant.investigation_ai import supervision
    class Provider:
        provider_name='openai';model_name='synthetic'
        def complete(self,*args,**kwargs):time.sleep(30)
    supervision.LocalClient=lambda *args:Provider()
    supervision._child(connection,gate,request)


@pytest.mark.parametrize('cancel',[False,True])
def test_extended_parent_deadline_and_cancel_containment(tmp_path,monkeypatch,cancel):
    import time
    import test_supervised_context_budget as startup
    from forensic_assistant.investigation_ai import supervision
    from forensic_assistant.llm.client import LocalClient
    saved=startup.saved.__wrapped__(tmp_path);config=startup.configured(saved)
    config['_stage_a']=x.authorize(config['_stage_a']);config['_stage_a']['expires']=config['_stage_a']['issued']+900
    # A shortened parent deadline tests containment without waiting 15 minutes.
    # The child retains sufficient authorization lifetime to enter the mock call.
    config['_stage_a_deadline']=time.monotonic()+30
    monkeypatch.setattr(supervision,'_child',blocking_child)
    def status(phase):
        if phase=='model' and cancel:raise KeyboardInterrupt()
    if not cancel:
        # Model deadline clamps dispatch timeout, and the parent has its own bound.
        config['_stage_a_deadline']=time.monotonic()+23
    start=time.monotonic()
    result=supervision.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=LocalClient(),status=status)
    assert time.monotonic()-start<12
    assert result['termination'] in (('ANALYST_CANCELLED',) if cancel else ('OVERALL_RESOURCE_EXHAUSTED','MAX_SECONDS','STARTUP_TIMEOUT','MODEL_PHASE_TIMEOUT'))
    assert result['startup_diagnostic']['cleanup_confirmed']


def test_grant_limits_expiry_and_approval_clock(tmp_path,monkeypatch):
    import test_supervised_context_budget as startup
    from forensic_assistant.investigation_ai import autonomous_policy as policy,supervision
    saved=startup.saved.__wrapped__(tmp_path);config=startup.configured(saved)
    g=x.authorize(config['_stage_a']);g['expires']=g['issued']+900
    policy.validate(g,config['case_path'])
    assert type(execution_budget({'_stage_a':g},serialized=asdict(ExtendedBudget()))) is ExtendedBudget
    for key,value in [('requests',19),('tool_calls',19),('seconds',901),('prompt_bytes',24577)]:
        invalid=deepcopy(g);invalid['limits'][key]=value
        with pytest.raises(ValueError):policy.validate(invalid,config['case_path'])
    expired=deepcopy(g);expired['issued']-=901;expired['expires']-=901
    with pytest.raises(ValueError,match='AUTHORIZATION_EXPIRED'):policy.validate(expired,config['case_path'])
    monkeypatch.setattr(a,'prepare',lambda *args,**kwargs:(g,{}))
    captures=[];approvals=[]
    monkeypatch.setattr(supervision,'run',lambda config,*args,**kwargs:captures.append((config,kwargs)))
    a.start(config['_stage_a_handoff'],saved[1],object(),lambda grant:approvals.append(grant) or True,follow_up=True,extended=True)
    assert len(approvals)==1 and len(captures)==1
    actual,kwargs=captures[0]
    assert actual['_stage_a_deadline']-actual['_stage_a_started']==900
    assert actual['_stage_a']['expires']-actual['_stage_a']['issued']==900
    assert type(kwargs['budget']) is ExtendedBudget


def test_cli_opt_in_and_missing_followup_rejected():
    from forensic_assistant.cli import build_parser
    from forensic_assistant.investigation_workflow import run
    args=build_parser().parse_args('investigation run latest --follow-up --extended'.split())
    assert args.follow_up and args.extended
    with pytest.raises(ValueError,match='requires --follow-up'):
        run('not-opened',read=lambda _:pytest.fail('approval'),extended=True)


def test_extended_authorization_display_is_single_and_explicit(tmp_path,monkeypatch,capsys):
    import test_supervised_context_budget as startup
    from forensic_assistant import assessment_handoff_cli
    saved=startup.saved.__wrapped__(tmp_path);config=startup.configured(saved)
    g=x.authorize(config['_stage_a']);questions=[]
    monkeypatch.setattr('forensic_assistant.ai.backend.backend',lambda:object())
    def start(handoff,assessment,client,confirm,**kwargs):
        assert kwargs['follow_up'] and kwargs['extended']
        assert confirm(g)
        return {'synthetic':True}
    monkeypatch.setattr(a,'start',start)
    assessment_handoff_cli.execute(saved[0],saved[1]['id'],'Inspect recorded activity',autonomous=True,
        follow_up=True,extended=True,read=lambda prompt:questions.append(prompt) or 'y')
    output=capsys.readouterr().out
    assert len(questions)==1
    for text in ('18 AI requests','900 seconds','24576 UTF-8','442368','880 seconds','Ctrl+C'):
        assert text in output
    assert 'expires after 5 minutes' not in output


def test_overall_exhaustion_is_not_completion(tmp_path):
    result,calls,rounds=session(tmp_path,exhaust=True)
    assert len(rounds)==18, (result['termination'],result.get('failure_diagnostic'))
    assert result['state']['accepted_calls']==18
    assert result['termination']=='OVERALL_RESOURCE_EXHAUSTED'
    assert len(result['work_batches'])==3 and result['work_batches'][-1]['pending_ids']
    assert result['answer_assessment']['status']=='PARTIAL'
    assert len({(args['evidence_id'],args['category']) for name,args in calls if name=='inspect_context'})==12
    assert a.reconstruct(tmp_path/'runs',result['investigation_id'])['findings']==result['findings']


@pytest.mark.parametrize('failure',['source','time','view'])
def test_second_batch_scope_and_view_failure(tmp_path,failure):
    result,calls,rounds=session(tmp_path,failure)
    assert len(rounds)==7
    assert result['validated_batches']==5
    assert result['termination'] not in ('NO_FURTHER_AUTHORIZED_LEADS','AUTHORIZED_PLAN_EXHAUSTED')
    assert result['work_batches'][0]['totals']['ai_requests']==6
    assert a.reconstruct(tmp_path/'runs',result['investigation_id'])['findings']==result['findings']


def test_actual_spawn_retains_readview_across_batch_boundary(tmp_path,monkeypatch):
    import test_supervised_context_budget as startup
    from forensic_assistant.investigation_ai import supervision
    from forensic_assistant.llm.client import LocalClient
    real_case=startup.case
    monkeypatch.setattr(startup,'case',lambda path:real_case(path,count=8))
    saved=startup.saved.__wrapped__(tmp_path)
    config=startup.configured(saved)
    config['_stage_a']=x.authorize(config['_stage_a'])
    config['_stage_a']['expires']=config['_stage_a']['issued']+900
    before=saved[0].read_bytes();progress=[];phases=[]
    monkeypatch.setattr(supervision,'_child',startup.synthetic_child)
    result=supervision.run(config,config['_stage_a']['objective'],tmp_path/'runs',client=LocalClient(),
                          status=phases.append,batch_progress=progress.append)
    assert result['validated_batches']==8, result
    assert len(progress)==2 and progress==result['work_batches']
    assert result['metrics']['ai_requests']==8
    assert result['startup_diagnostic']['cleanup_confirmed']
    manifest,events=load(tmp_path/'runs',result['investigation_id'])
    assert sum(e['kind']=='initial' for e in events)==1
    assert all(e['data']['response']['evidence_state']==manifest['evidence_state'] for e in events if e['kind']=='result')
    assert saved[0].read_bytes()==before
    assert a.reconstruct(tmp_path/'runs',result['investigation_id'])['findings']==result['findings']

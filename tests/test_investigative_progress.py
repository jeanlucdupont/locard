"""Deterministic operational progress, real synthetic worker, no inference service."""
import io,json,hashlib
import pytest
from forensic_assistant.conversational_ai.service import Session,Paused
from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
from forensic_assistant.conversational_ai.provider import ScriptedProvider
from forensic_assistant.conversational_ai.progress import PREFIX,Progress
from forensic_assistant.conversational_ai.operation_diagnostics import operation_trace
from forensic_assistant.conversational_ai.workspace import reconstruct
from test_conversational_ai import reply,call,last
from scripts.diagnose_investigative_memory import synthetic_case

SIGNAL={'artifact':'evtx','category':'recorded','candidate_limit':100,'limit':5,'offset':0}
def signal():return reply(calls=[call('discover_security_signals',dict(SIGNAL))])
def notices(messages):return [json.loads(m['content'][len(PREFIX):]) for m in messages if m.get('role')=='user' and m.get('content','').startswith(PREFIX)]

def session_for(tmp_path,steps,limits=None):
    path,sid,before=synthetic_case(tmp_path)
    client=ScriptedProvider(steps)
    scope=authorize(path,[sid],'2020-01-01T00:00:00Z','2020-01-02T00:00:00Z',FAMILIES,'openai','scripted',limits)
    return Session(scope,client,lambda _:True),path,before


def test_repeat_recovery_and_reconstruction(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    def recover(messages):
        p=notices(messages)[-1]
        assert p['state']=='nonproductive_repeat' and p['search_complete'] and p['exhausted']
        assert p['previous_operation'] and p['new_coverage'] is False
        assert [x['artifact'] for x in p['alternatives']]==['evtx']
        assert 'progress' not in last(messages) and last(messages)['records']==[]
        return reply(calls=[call('search_evidence',{'artifact':'evtx','limit':1})])
    session,path,before=session_for(tmp_path,[signal(),signal(),recover,reply('Scoped partial assessment.')])
    try:result=session.submit('Broad synthetic investigation',intent='broad')
    finally:session.close()
    trace=operation_trace(session.journal.path)
    rows=trace['operations'];assert [r['progress']['state'] for r in rows]==['productive','nonproductive_repeat','productive']
    assert rows[1]['progress_feedback_sent_request']==3
    assert rows[1]['progress_subsequent_operations'][0]['tool']=='search_evidence'
    assert result['completion_assessment']['records_retrieved']==1
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before
    assert session.worker.process.poll() is not None
    a=reconstruct(session.journal.path,tmp_path/'replay-a');b=reconstruct(session.journal.path,tmp_path/'replay-b')
    assert a==b


def test_persistent_repeat_pauses_after_delivered_opportunities(tmp_path):
    session,path,before=session_for(tmp_path,[signal() for _ in range(6)])
    try:
        with pytest.raises(Paused,match='NONPRODUCTIVE_REPETITION'):session.submit('Investigate',intent='broad')
    finally:session.close('NONPRODUCTIVE_REPETITION')
    assert session.used['requests']==4 and session.used['successful_operations']==4 and session.used['failed_operations']==0
    rows=operation_trace(session.journal.path)['operations']
    assert rows[-1]['progress_feedback_sent_request'] is None
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before


@pytest.mark.parametrize('recover',[True,False])
def test_completion_challenge_is_bounded_and_counted(tmp_path,recover):
    def after(messages):
        assert notices(messages)[-1]['contract']=='completion-recovery-v1'
        return reply(calls=[call('search_evidence',{'artifact':'evtx','limit':1})]) if recover else reply('Cannot proceed.')
    session,_,_=session_for(tmp_path,[signal(),signal(),signal(),reply('Should I try another approach?'),after,reply('Partial result.')])
    try:
        if recover:result=session.submit('Broad investigation',intent='broad');assert result['completion_assessment']['records_retrieved']
        else:
            with pytest.raises(Paused,match='INCONCLUSIVE_NO_PROGRESS'):session.submit('Broad investigation',intent='broad')
    finally:session.close('COMPLETED' if recover else 'INCONCLUSIVE_NO_PROGRESS')
    assert session.used['completion_challenges']==1 and session.used['requests']==(6 if recover else 5)


def test_narrow_final_not_forced_and_budget_cannot_be_borrowed(tmp_path):
    root=tmp_path/'narrow';root.mkdir()
    session,_,_=session_for(root,[signal(),signal(),signal(),reply('No recorded Defender alerts in this query.')])
    try:session.submit('Recorded Defender alerts only',intent='narrow')
    finally:session.close()
    assert session.used['completion_challenges']==0
    root=tmp_path/'budget';root.mkdir()
    session,_,_=session_for(root,[signal(),signal(),reply('Stop.')],{'requests':3})
    try:
        with pytest.raises(Paused,match='RESOURCE_LIMIT'):session.submit('Broad investigation',intent='broad')
    finally:session.close('RESOURCE_LIMIT')
    assert session.used['requests']==3 and session.used['completion_challenges']==0


def test_pages_revisits_memory_and_analyst_reconsideration(tmp_path):
    def inspect(messages):return reply(calls=[call('show_evidence',dict(evidence_id=last(messages)['records'][0]['evidence_id'],limit=40))])
    session,_,_=session_for(tmp_path,[reply(calls=[call('search_evidence',dict(artifact='evtx',limit=1,offset=0))]),reply(calls=[call('search_evidence',dict(artifact='evtx',limit=1,offset=1))]),inspect,reply('Partial.'),signal(),reply('Scoped result.')])
    try:
        session.submit('Inspect pages')
        session.submit('Analyst reconsideration')
    finally:session.close()
    rows=operation_trace(session.journal.path)['operations']
    assert all(r['progress']['state']=='productive' for r in rows)
    assert rows[0]['progress']['continuation_available']


def test_unknown_progress_and_changed_memory(tmp_path):
    session,_,_=session_for(tmp_path,[])
    try:
        p=Progress(session.workspace,session.scope,session.view,1)
        first=p.assess('A1','search_evidence',{'artifact':'evtx'},{'records':[]})
        assert first['state']=='unknown'
        a=p.assess('A2','memory',{'kind':'notes'},{'items':[]})
        session.event('operation_progress',a)
        b=p.assess('A3','memory',{'kind':'notes'},{'items':[{'text':'New unverified note'}]})
        assert b['state']=='productive'
        c=p.assess('A4','memory',{'kind':'notes'},{'items':[]},consolidated=True)
        assert c['state']=='unknown'
        revisit=p.assess('A5','show_evidence',{'evidence_id':'synthetic'},{'fields':[]},consolidated=True)
        assert revisit['state']=='productive'
        other=Progress(session.workspace,session.scope,dict(session.view,synthetic_epoch='changed'),1)
        assert other.assess('A6','memory',{'kind':'notes'},{'items':[]})['previous_operation'] is None
    finally:session.close()


def test_progress_sink_no_values_or_stdout(capsys):
    from forensic_assistant.conversational_ai.progress_display import ProgressDisplay
    import sys
    sink=ProgressDisplay(sys.stderr)
    sink({'kind':'interpretation','text':'PRIVATE'})
    sink({'kind':'progress','operation':'Waiting for the AI investigator','status':'started'})
    sink({'kind':'investigative_progress','request_sequence':1,'last_operation':'search_evidence','successful':1,'failed':0,'records':0,'verifications':0,'nonproductive':0,'checkpoints':1,'value':'PRIVATE'})
    captured=capsys.readouterr();assert not captured.out and 'PRIVATE' not in captured.err
    assert 'request=1' in captured.err and 'records=0' in captured.err


def test_empty_authorized_scope_can_finish(tmp_path,monkeypatch):
    from forensic_assistant.database.db import connect
    from forensic_assistant.database import sources
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))
    path=tmp_path/'empty.db';db=connect(path);sid=sources.create(db);db.commit();db.close()
    scope=authorize(path,[sid],'2020-01-01T00:00:00Z','2020-01-02T00:00:00Z',FAMILIES,'openai','scripted')
    session=Session(scope,ScriptedProvider([reply('Authorized scope has no eligible records.')]),lambda _:True)
    emitted=[];session.emit=emitted.append
    try:result=session.submit('Broad investigation',intent='broad')
    finally:session.close()
    assert result['completion_assessment']['coverage']=='authorized_scope_empty'
    assert session.status()['completion_assessment']==result['completion_assessment']
    assert any(e.get('kind')=='activity' and 'Objective completion is not established' in e.get('text','') for e in emitted)
    assert not session.used['completion_challenges']


def test_exhausted_page_and_unknown_inventory(tmp_path):
    session,_,_=session_for(tmp_path,[])
    try:
        p=Progress(session.workspace,session.scope,session.view,1)
        result={'records':[],'has_more':False,'offset':8,'next_offset':None,'truncated':True}
        a=p.assess('A1','search_evidence',{'artifact':'evtx','offset':8},result)
        session.event('operation_progress',a)
        b=p.assess('A2','search_evidence',{'artifact':'evtx','offset':8},result)
        assert a['state']=='productive' and b['state']=='nonproductive_repeat'
        assert b['exhausted'] and not b['search_complete'] # exhausted tail != whole population examined
        p.available={}
        assert p.completion(retrieved=0,inspected=0,verified=0,repetitions=3,intent='broad',challenge_used=False)['coverage']=='partial_or_unknown'
    finally:session.close()


def test_progress_log_matches_stderr_and_is_fresh(tmp_path):
    from forensic_assistant.conversational_ai.progress_display import ProgressDisplay
    stream=io.StringIO();path=tmp_path/'progress.txt'
    display=ProgressDisplay(stream,clock=lambda:1,log_path=path)
    display({'kind':'checkpoint','count':3});display.close()
    assert path.read_text()==stream.getvalue() and 'checkpoints=3' in stream.getvalue()
    with pytest.raises(FileExistsError):ProgressDisplay(stream,log_path=path)


def test_completed_scope_and_changed_authorization_not_shared(tmp_path):
    session,_,_=session_for(tmp_path,[])
    try:
        p=Progress(session.workspace,session.scope,session.view,1)
        a=p.assess('A1','search_evidence',{'artifact':'evtx','offset':0},{'records':[],'has_more':False,'next_offset':None})
        session.event('operation_progress',a)
        reconsider=Progress(session.workspace,session.scope,session.view,2).assess('A2','search_evidence',{'artifact':'evtx','offset':0},{'records':[],'has_more':False,'next_offset':None})
        assert reconsider['state']=='unknown' and reconsider['reason']=='analyst_turn_reconsideration' and not reconsider['new_coverage']
        other=Progress(session.workspace,dict(session.scope,start='2020-01-01T01:00:00Z'),session.view,1)
        assert other.assess('A3','search_evidence',{'artifact':'evtx','offset':0},{'records':[],'has_more':False,'next_offset':None})['state']=='productive'
    finally:session.close()

"""6.176: synthetic transport shapes and real disposable read-view operations."""
import copy
import json
from types import SimpleNamespace as N
import pytest
from test_conversational_ai import setup,reply,call
from forensic_assistant.conversational_ai import provider as p
from forensic_assistant.conversational_ai.service import Session,Paused,notebook
from forensic_assistant.conversational_ai.contracts import DEFAULTS,authorize

@pytest.fixture(autouse=True)
def private(tmp_path,monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))

def calls(n,name='search_evidence'):
    return [dict(id='c'+str(i),name=name,arguments={'artifact':'evtx','offset':i}) for i in range(n)]

@pytest.mark.parametrize('n',[1,4,5,6,16,128])
def test_legitimate_multiple_calls(n):
    value=reply('I will inspect independent candidates.',calls(n))
    assert p.validate(value)==value
    assert len(p.assistant_message(value)['tool_calls'])==n

@pytest.mark.parametrize('code,change',[
 ('RESPONSE_TYPE_INVALID',lambda v:[]),
 ('RESPONSE_FIELDS_INVALID',lambda v:{**v,'unexpected':True}),
 ('ASSISTANT_CONTENT_INVALID',lambda v:{**v,'text':{}}),
 ('TOOL_CALL_STRUCTURE_INVALID',lambda v:{**v,'tool_calls':{}}),
 ('TOOL_CALL_COUNT_EXCEEDED',lambda v:reply(calls=calls(129))),
 ('TOOL_CALL_ID_INVALID',lambda v:reply(calls=[dict(id=None,name='note',arguments={})])),
 ('TOOL_CALL_ID_DUPLICATE',lambda v:reply(calls=calls(1)*2)),
 ('TOOL_CALL_NAME_INVALID',lambda v:reply(calls=[dict(id='x',name='',arguments={})])),
 ('TOOL_CALL_ARGUMENTS_INVALID',lambda v:reply(calls=[dict(id='x',name='note',arguments=[])])),
 ('FINISH_REASON_INVALID',lambda v:{**v,'finish_reason':'unexpected-private-text'}),
 ('FINISH_REASON_TOOL_MISMATCH',lambda v:{**v,'finish_reason':'tool_calls'}),
 ('USAGE_INVALID',lambda v:{**v,'usage':{'total_tokens':-1}}),
 ('COST_INVALID',lambda v:{**v,'cost':0}),
 ('CONTINUATION_FORMAT_INVALID',lambda v:{**v,'continuation':{}}),
 ('CONTINUATION_SIZE_EXCEEDED',lambda v:{**v,'continuation':dict(format='litellm-openai-history-v1',payload='x'*(p.MAX_CONTINUATION+1))}),
 ('CONTINUATION_JSON_INVALID',lambda v:{**v,'continuation':dict(format='litellm-openai-history-v1',payload='{')}),
 ('CONTINUATION_FIELDS_INVALID',lambda v:{**v,'continuation':dict(format='litellm-openai-history-v1',payload='{}')}),
 ('CONTINUATION_CONTENT_MISMATCH',lambda v:{**v,'continuation':dict(format='litellm-openai-history-v1',payload=json.dumps({'role':'assistant','content':'private'}))}),
 ('CONTINUATION_TOOL_BINDING_MISMATCH',lambda v:{**v,'continuation':dict(format='litellm-openai-history-v1',payload=json.dumps({'role':'assistant','content':'','tool_calls':[{'id':'other','type':'function','function':{'name':'note','arguments':'{}'}}]}))}),
])
def test_specific_rules(code,change):
    from forensic_assistant.conversational_ai.diagnostics import detail,safe
    with pytest.raises(p.ValidationError) as exc:p.validate(change(reply()))
    assert exc.value.code==code
    assert safe(detail('validation',exc.value))['failed_rule']==code
    assert 'private' not in json.dumps(detail('validation',exc.value))

def test_provider_shape_is_sanitized(monkeypatch):
    from forensic_assistant.ai import settings
    from forensic_assistant.ai.provider_diagnostics import ProviderFailure
    monkeypatch.setattr(settings,'key',lambda _: 'private-secret')
    raw=[N(id='duplicate',type='function',function=N(name='note',arguments='{"text":"PRIVATE_EVIDENCE"}'))]*6
    sdk=N(completion=lambda **kw:N(choices=[N(finish_reason='tool_calls',message=N(content='PRIVATE_EVIDENCE',tool_calls=raw))],usage=None))
    with pytest.raises(ProviderFailure) as caught:p.generate(dict(provider='openai',model='synthetic',messages=[],timeout=1,conversation={'tools':[],'output_tokens':8192}),sdk)
    d=caught.value.metadata['conversation']
    assert d['returned_tool_call_count']==6 and d['failed_rule']=='TOOL_CALL_ID_DUPLICATE'
    assert d['assistant_content_type']=='str' and d['assistant_content_bytes']==16
    assert 'PRIVATE_EVIDENCE' not in json.dumps(d) and 'private-secret' not in json.dumps(d)

def test_default_absent_budgets_and_authorization(tmp_path):
    from forensic_assistant.conversational_ai.cli import authorization_text
    path,client,scope=setup(tmp_path,[])
    assert all(scope['limits'][k] is None for k in ('requests','operations','tokens','records','disclosure_bytes','active_seconds'))
    assert scope['expires'] is None
    text=authorization_text(scope)
    assert 'No session limit' in text and 'No cumulative disclosure budget' in text
    assert 'identity' not in text and 'issued' not in text
    assert scope['limits']['tool_seconds'] is None and scope['limits']['provider_seconds']==180
    for invalid in ({'requests':0},{'tool_seconds':0},{'output_tokens':32769}):
        with pytest.raises(ValueError):authorize(path,scope['source_ids'],scope['start'],scope['end'],scope['families'],'openai','scripted',invalid)

def test_extended_session_real_operations(tmp_path):
    # 33 provider rounds, 66 real retrievals, >200K tokens; no former ceilings.
    steps=[]
    for i in range(32):
        item=reply(calls=[dict(id=f'c{i}-{j}',name='search_evidence',arguments={'artifact':'evtx','offset':j}) for j in range(2)])
        item['usage']={'prompt_tokens':5000,'completion_tokens':2000,'total_tokens':7000}
        steps.append(item)
        steps.append(reply('Coverage remains limited; cause unresolved.'))
    path,client,scope=setup(tmp_path,steps)
    before=path.read_bytes();session=Session(scope,client,lambda _:True)
    try:
        for i in range(32):session.submit('Investigate independently, turn '+str(i))
        assert session.used['requests']==64 and session.used['operations']==64 and session.used['tokens']>200000
        assert session.used['successful_operations']==64 and session.used['failed_operations']==0
        assert session.disclosed and session.used['evidence_bytes']>0
        assert session.used['disclosure_bytes']>session.used['evidence_bytes']
        assert session.status()['estimated_cost'] is None
    finally:session.close()
    assert path.read_bytes()==before
    saved=notebook(str(path)+'.conversations',session.journal.id)
    assert len(saved['events'])>256 and saved==notebook(str(path)+'.conversations',session.journal.id)

@pytest.mark.parametrize('limits,reason',[
    ({'requests':1},'RESOURCE_LIMIT'),({'operations':1},'RESOURCE_LIMIT'),
    ({'tokens':1},'TOKEN_RESERVATION'),({'disclosure_bytes':1},'DISCLOSURE_LIMIT'),
])
def test_optional_budgets_pause_without_destroying_context(tmp_path,limits,reason):
    path,client,scope=setup(tmp_path,[reply(calls=calls(6)),reply('done')],limits)
    session=Session(scope,client,lambda _:True)
    try:
        with pytest.raises(Paused,match=reason):session.submit('Synthetic')
        assert not session.closed and session.worker.process.poll() is None
        if limits.get('operations'):
            block=session.turns[-1]
            assert len(block)==7 and {m['tool_call_id'] for m in block[1:]}=={'c'+str(i) for i in range(6)}
        assert len(client.calls)<=1
    finally:session.close()

def test_repeated_successes_continue_and_analyst_redirects(tmp_path):
    steps=[reply(calls=calls(1))]*3+[reply('Repeated inspection complete.'),reply('A different investigative direction is needed.')]
    path,client,scope=setup(tmp_path,steps);session=Session(scope,client,lambda _:True)
    try:
        assert session.submit('Investigate')['interpretation']
        assert not session.closed and session.used['successful_operations']==3
        assert session.workspace.meta('latest_repeat') is not None
        assert session.submit('Consider a different hypothesis')['interpretation']
    finally:session.close()

def test_provider_failure_pauses_and_manual_next_turn_resumes(tmp_path):
    from forensic_assistant.ai.provider_diagnostics import ProviderFailure
    def timeout(_):raise ProviderFailure('timeout','timeout')
    path,client,scope=setup(tmp_path,[timeout,reply('Partial assessment retained.')]);session=Session(scope,client,lambda _:True)
    try:
        with pytest.raises(Paused):session.submit('Investigate')
        assert len(client.calls)==1
        assert session.submit('Try again explicitly')['interpretation']
    finally:session.close()

def test_duration_and_soft_checkpoint(tmp_path,monkeypatch):
    import forensic_assistant.conversational_ai.service as service
    path,client,scope=setup(tmp_path,[reply('Still authorized.')]*4);session=Session(scope,client,lambda _:True)
    try:
        session.used['active_seconds']=3601
        session.submit('Continue beyond fifteen minutes')
        assert session.used['active_seconds']>3600
        assert session.used['automatic_checkpoints']==1
        session.pause_at_checkpoint=True
        clock=[10000.0];monkeypatch.setattr(service.time,'monotonic',lambda:clock[0])
        def slow(_):clock[0]+=601;return reply(calls=calls(1))
        session.provider.steps=iter([slow,reply('Continue by analyst direction')])
        with pytest.raises(Paused,match='ACTIVE_TURN_CHECKPOINT'):session.submit('Long active turn')
        session.submit('Continue explicitly')
    finally:session.close()

def test_extended_journal_and_legacy_limits(tmp_path):
    from forensic_assistant.investigation_ai.transcript import Transcript,load
    t=Transcript(tmp_path/'logs',dict(engine='conversational-v1',storage_profile='conversation-long-v1'),private=True)
    for i in range(80):t.append('synthetic',{'text':'a'*65536})
    t.finish({'termination':'COMPLETED'})
    assert t.size>4*1024*1024 and len(load(tmp_path/'logs',t.id)[1])==81
    legacy=Transcript(tmp_path/'old',dict(engine='legacy'),private=True)
    try:
        with pytest.raises(ValueError,match='BUDGET'):
            for _ in range(80):legacy.append('synthetic',{'text':'a'*65536})
    finally:legacy.close()

def test_model_bounds_offline(monkeypatch):
    from forensic_assistant.conversational_ai import resources
    monkeypatch.setattr(resources,'model_capacity',lambda _: (16384,1024,'synthetic small model'))
    size,output,_=resources.request_capacity('model',DEFAULTS)
    assert output==1024 and size==16384-1024-2048

def test_over_300_real_records_and_reference_retention(tmp_path):
    from forensic_assistant.conversational_ai.contracts import FAMILIES
    from contextlib import closing
    from datetime import datetime,timedelta
    from forensic_assistant.database.db import connect,register_source,insert_events
    from forensic_assistant.database import sources
    from forensic_assistant.ingest.normalize import normalize
    path=tmp_path/'many.db'
    with closing(connect(path)) as db:
        sid=sources.create(db,hostname='synthetic',volume_root='C:')
        sha='b'*64;register_source(db,sha,310,'synthetic.evtx');items=[]
        for i in range(310):
            stamp=(datetime(2026,9,30,12)+timedelta(seconds=i)).isoformat()+'Z'
            xml=f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Synthetic"/><EventID>900</EventID><Channel>Application</Channel><TimeCreated SystemTime="{stamp}"/></System><EventData><Data Name="ObjectName">item-{i}</Data></EventData></Event>'
            items.append(normalize(xml,sha,'synthetic.evtx',i))
        insert_events(db,items);sources.assign(db,sid,[sha],reason='Synthetic');db.commit()
    grant={'source_ids':[sid]}
    steps=[]
    for offset in range(0,320,20):
        steps += [reply(calls=[dict(id='page'+str(offset),name='search_evidence',arguments=dict(artifact='evtx',offset=offset,limit=20))]),reply('Incomplete coverage; no absence inference.')]
    client=p.ScriptedProvider(steps)
    scope=authorize(path,grant['source_ids'],'2026-09-30T00:00:00Z','2026-10-01T00:00:00Z',list(FAMILIES),'openai','scripted')
    session=Session(scope,client,lambda _:True)
    try:
        for offset in range(0,320,20):session.submit('Inspect page '+str(offset))
        assert len(session.known)==310 and session.disclosed==session.known
        assert session.compacted>0
        assert session.used['evidence_bytes']>0
    finally:session.close()
    saved=notebook(str(path)+'.conversations',session.journal.id)
    ids={r['evidence_id'] for e in saved['events'] if e['kind']=='tool_result' for r in e['data']['result'].get('records',[])}
    assert ids==session.known

def test_soft_warning_is_not_termination(tmp_path,monkeypatch):
    import forensic_assistant.conversational_ai.service as service
    now=[10000.0];events=[]
    def slow(_):
        now[0]+=301
        return reply(calls=[dict(id='note',name='note',arguments=dict(kind='hypothesis',text='Unverified alternative',status='active'))])
    path,client,scope=setup(tmp_path,[slow,reply('Useful partial assessment')])
    session=Session(scope,client,lambda _:True,emit=events.append)
    monkeypatch.setattr(service.time,'monotonic',lambda:now[0])
    try:
        assert session.submit('Continue')['interpretation']
        assert not session.paused
        assert any('still active' in e.get('text','') for e in events)
    finally:session.close()

def test_explicit_active_duration_stops_before_provider(tmp_path):
    path,client,scope=setup(tmp_path,[],dict(active_seconds=100))
    session=Session(scope,client,lambda _:True)
    try:
        session.used['active_seconds']=101
        with pytest.raises(Paused,match='RESOURCE_LIMIT'):session.submit('Continue')
        assert not client.calls
    finally:session.close()

def test_pause_audit_failure_closes_worker(tmp_path,monkeypatch):
    path,client,scope=setup(tmp_path,[],dict(requests=1));session=Session(scope,client,lambda _:True)
    original=session.journal.append
    def fail(kind,data,terminal=False):
        if kind=='paused':raise OSError('synthetic')
        return original(kind,data,terminal)
    monkeypatch.setattr(session.journal,'append',fail)
    session.used['requests']=1
    with pytest.raises(OSError):session.submit('Stop')
    assert session.closed and session.worker.process.poll() is not None

def test_response_total_size_and_complete_continuation():
    # Individual components fit; their combined transport envelope does not.
    value=reply('a'*p.MAX_CONTENT,calls=calls(128))
    for c in value['tool_calls']:c['arguments']={'text':'a'*4000}
    with pytest.raises(p.ValidationError,match='RESPONSE_SIZE_EXCEEDED'):p.validate(value)

def test_notebook_keeps_more_than_old_notes_and_observations(tmp_path):
    path,client,scope=setup(tmp_path,[])
    session=Session(scope,client,lambda _:True)
    try:
        # Durable append/replay capacity without fabricating verified evidence.
        for i in range(210):
            value={'unverified':True,'kind':'open_question','status':'unresolved','text':str(i)}
            session.event('note',value);session.notes.append(value)
        assert len(session.notes)==210
    finally:session.close()
    assert len(notebook(str(path)+'.conversations',session.journal.id)['notes'])==210

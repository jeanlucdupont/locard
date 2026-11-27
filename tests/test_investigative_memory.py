"""Journal-first SQLite memory and bounded autonomous continuation; no providers."""
import copy
import json
import sqlite3
from pathlib import Path
import pytest
from forensic_assistant.conversational_ai.workspace import Workspace,events,reconstruct
from forensic_assistant.conversational_ai.service import Session,Paused
from forensic_assistant.investigation_ai.transcript import Transcript,digest
from test_conversational_ai import setup,reply,call,last


@pytest.fixture(autouse=True)
def private(tmp_path,monkeypatch):monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))


def journal(tmp_path):
    j=Transcript(tmp_path/'journals',dict(engine='conversational-v1',storage_profile='conversation-long-v1',authorization={'synthetic':True}),private=True)
    j.append('authorization',{'synthetic':True});return j


def test_idempotent_transaction_and_interrupted_projection(tmp_path,monkeypatch):
    j=journal(tmp_path);w=Workspace(j.path/'workspace.db',j.id)
    first=list(events(j.path))[0];w.apply(first);w.apply(first)
    j.append('analyst_message',{'role':'user','content':'Consider ordinary explanations.'})
    e=list(events(j.path))[-1];original=w._project
    def fail(e):original(e);raise sqlite3.OperationalError('synthetic disk failure')
    monkeypatch.setattr(w,'_project',fail)
    with pytest.raises(sqlite3.OperationalError):w.apply(e)
    assert w.meta('next')=='1' and w.db.execute('SELECT count(*) FROM notes').fetchone()[0]==0
    monkeypatch.setattr(w,'_project',original);w.reconcile(j.path)
    assert w.meta('next')=='2' and w.query('notes')['items'][0]['author']=='analyst'
    assert w.db.execute('PRAGMA foreign_keys').fetchone()[0]==1
    assert w.db.execute('PRAGMA user_version').fetchone()[0]==1
    assert 'value' not in {r[1] for r in w.db.execute('PRAGMA table_info(fields)')}
    w.close();j.close()


def test_manifest_chain_and_session_conflicts(tmp_path):
    j=journal(tmp_path);w=Workspace(j.path/'workspace.db',j.id);w.reconcile(j.path)
    altered=copy.deepcopy(list(events(j.path))[0]);altered['data']={'synthetic':False}
    altered['hash']=digest({k:v for k,v in altered.items() if k!='hash'})
    with pytest.raises(ValueError,match='CONFLICT'):w.apply(altered)
    other=tmp_path/'other';other.mkdir()
    with pytest.raises(ValueError,match='SESSION_MISMATCH'):w.reconcile(other)
    w.close();j.close()
    with pytest.raises(ValueError,match='ALREADY_EXISTS'):Workspace(j.path/'workspace.db',j.id)
    p=j.path/'events.jsonl';p.write_bytes(p.read_bytes().replace(b'true',b'false'))
    with pytest.raises(ValueError):reconstruct(j.path,tmp_path/'invalid-rebuild')
    assert not (tmp_path/'invalid-rebuild').exists()


def test_hardlinks_and_companion_redirection_rejected(tmp_path,monkeypatch):
    import os
    j=journal(tmp_path);w=Workspace(j.path/'workspace.db',j.id)
    try:
        alias=j.path/'unexpected-link'
        try:os.link(w.path,alias)
        except PermissionError:
            original=Path.stat
            def linked(path,*a,**kw):
                info=original(path,*a,**kw)
                if path==w.path:
                    data=list(info);data[3]=2;return os.stat_result(data)
                return info
            with monkeypatch.context() as patch:
                patch.setattr(Path,'stat',linked)
                with pytest.raises(ValueError,match='REDIRECTION'):w.query()
        else:
            with pytest.raises(ValueError,match='REDIRECTION'):w.query()
            alias.unlink()
        companion=Path(str(w.path)+'-wal');companion.mkdir()
        with pytest.raises(ValueError,match='REDIRECTION'):w.query()
        companion.rmdir()
    finally:w.close();j.close()


def test_revisions_and_reference_validation(tmp_path):
    seen={}
    def revise(messages):
        seen['first']=last(messages)['note_id']
        return reply(calls=[call('note',dict(kind='hypothesis',text='A competing explanation remains open.',status='revised',supersedes=seen['first'],alternatives=['Ordinary use.']))])
    path,provider,scope=setup(tmp_path,[reply(calls=[call('note',dict(kind='hypothesis',text='Initial tentative explanation.',status='active'))]),revise,
        reply(calls=[call('memory',dict(kind='notes'))]),reply('Both revisions remain unverified.')])
    s=Session(scope,provider,lambda _:True)
    try:
        s.submit('Explore alternatives.')
        notes=s.workspace.query('notes')['items'];old=next(n for n in notes if n['id']==seen['first'])
        assert old['superseded'] and old['unverified']
        assert not s.workspace.query('notes',status='active')['items'] or all(n['id']!=seen['first'] for n in s.workspace.query('notes',status='active')['items'])
        for value in ({'evidence_ids':['unknown']},{'operation_ids':['A999999']},{'supersedes':'N999999'}):
            with pytest.raises(ValueError):s.workspace.validate_note(value)
        with pytest.raises(ValueError):s.workspace.query('fields',evidence_id='unknown')
        changed=copy.deepcopy(scope);changed['provider']='local'
        with pytest.raises(ValueError,match='AUTHORITY'):s.workspace.bound(changed,s.view)
        with pytest.raises(ValueError,match='AUTHORITY'):s.workspace.bound(scope,{**s.view,'view_id':'0'*32})
    finally:s.close()


@pytest.mark.parametrize('capacity',[28000,32000,40000])
def test_real_context_pressure_recovery(tmp_path,capacity):
    from scripts.diagnose_investigative_memory import diagnostic
    result=diagnostic(tmp_path,capacity)
    assert all(result['checks'].values())
    assert result['usage']['memory_operations']==2
    assert result['usage']['context_consolidations']>0
    assert max(result['request_sizes'])<=capacity


def test_mandatory_context_capacity_fails_before_dispatch(tmp_path):
    path,provider,scope=setup(tmp_path,[reply('Must not be called.')],{'request_bytes':1000})
    s=Session(scope,provider,lambda _:True)
    try:
        with pytest.raises(Paused,match='CONTEXT_CAPACITY'):s.submit('Investigate.')
        assert not provider.calls
    finally:s.close()


def test_explicit_checkpoint_pause_and_budget(tmp_path):
    path,provider,scope=setup(tmp_path,[reply('Not called')])
    s=Session(scope,provider,lambda _:True,checkpoint_seconds=.001,pause_at_checkpoint=True)
    try:
        with pytest.raises(Paused,match='ACTIVE_TURN_CHECKPOINT'):s.submit('Investigate.')
        assert not provider.calls and s.used['automatic_checkpoints']==0
    finally:s.close()
    root=tmp_path/'budget';root.mkdir();path,provider,scope=setup(root,[reply('Not called')],{'active_seconds':60})
    s=Session(scope,provider,lambda _:True)
    try:
        s.used['active_seconds']=61
        with pytest.raises(Paused,match='RESOURCE_LIMIT'):s.submit('Investigate.')
        assert not provider.calls
    finally:s.close()


def test_exhausted_checkpoint_does_not_dispatch_health_call(tmp_path,monkeypatch):
    path,provider,scope=setup(tmp_path,[],{'active_seconds':60})
    s=Session(scope,provider,lambda _:True,checkpoint_seconds=.001)
    try:
        s.used['active_seconds']=61
        with monkeypatch.context() as patch:
            patch.setattr(s.worker,'call',lambda *a,**k:pytest.fail('Expired checkpoint dispatched'))
            with pytest.raises(Paused,match='RESOURCE_LIMIT'):s.checkpoint()
    finally:s.close()


def test_failed_memory_operation_is_identified(tmp_path):
    path,provider,scope=setup(tmp_path,[reply(calls=[call('memory',dict(kind='fields',evidence_id='unknown'))]),reply('Unavailable reference is not evidence absence.')])
    s=Session(scope,provider,lambda _:True)
    try:
        s.submit('Inspect prior memory.')
        action=s.workspace.query('actions')['items'][0]
        assert action['tool']=='memory' and action['status']=='failed'
        assert json.loads(action['coverage'])['tool']=='memory'
    finally:s.close()


def test_reconstruction_does_not_read_case_or_restore_authority(tmp_path):
    path,provider,scope=setup(tmp_path,[reply('No forensic conclusion.')]);s=Session(scope,provider,lambda _:True)
    s.submit('Investigate.');s.close();before=(s.journal.path/'events.jsonl').read_bytes()
    path.rename(tmp_path/'unavailable.db')
    a=reconstruct(s.journal.path,tmp_path/'history-one');b=reconstruct(s.journal.path,tmp_path/'history-two')
    assert a==b and a['next_event']>0
    assert (s.journal.path/'events.jsonl').read_bytes()==before


def test_projection_failure_stops_before_provider(tmp_path,monkeypatch):
    path,provider,scope=setup(tmp_path,[reply('Must not be called')]);s=Session(scope,provider,lambda _:True)
    def fail(event):raise sqlite3.OperationalError('synthetic')
    monkeypatch.setattr(s.workspace,'apply',fail)
    with pytest.raises(RuntimeError,match='WORKSPACE_PROJECTION_FAILED'):s.submit('Investigate.')
    assert not provider.calls and s.closed and s.worker.process.poll() is not None
    result=reconstruct(s.journal.path,tmp_path/'recovered')
    assert result['counts']['notes']==1


def test_malformed_model_note_has_no_authority(tmp_path):
    from forensic_assistant.conversational_ai.contracts import arguments
    for args in [dict(kind='observation',text='Claim',status='active',verified=True),
                 dict(kind='hypothesis',text='Claim',status='active',evidence_ids=['x','x'])]:
        with pytest.raises(ValueError):arguments('note',args)


def test_local_retrieval_is_not_provider_exposure_and_partial_zero(tmp_path):
    j=journal(tmp_path);w=Workspace(j.path/'workspace.db',j.id)
    def put(kind,data):j.append(kind,data);w.reconcile(j.path)
    put('tool_attempt',dict(name='search_evidence',arguments={'artifact':'evtx'},operation_id='A1'))
    put('behavioral_computation',dict(cache_hit=True,population_id='synthetic-population'))
    value=dict(records=[dict(evidence_id='synthetic-id',artifact='evtx',fields=[dict(field='/secret',truncated=True,redacted=True,timestamp_meaning='Context time')])],next_offset=1,coverage={'complete':False})
    put('tool_result',dict(operation_id='A1',name='search_evidence',result=value))
    assert json.loads(w.query('actions')['items'][0]['computation'])['cache_hit'] is True
    with pytest.raises(ValueError):w.validate_note({'evidence_ids':['synthetic-id']})
    assert w.query('evidence')['items'][0]['disclosure']=='retrieved'
    assert w.query('fields')['items'][0]['disclosure']=='retrieved_only'
    put('provider_attempt',{'messages':[dict(role='tool',content=json.dumps(value))]})
    w.validate_note({'evidence_ids':['synthetic-id']})
    f=w.query('fields')['items'][0]
    assert f['disclosure']=='possibly_exposed'
    assert f['truncated']==f['redacted']==1 and 'value' not in f and f['meaning']=='Context time'
    put('tool_attempt',dict(name='search_evidence',arguments={'artifact':'registry'},operation_id='A2'))
    put('tool_result',dict(operation_id='A2',name='search_evidence',result={'records':[],'coverage':{'analysis_complete':False},'total':None}))
    assert [a['status'] for a in w.query('actions')['items']]==['partial','partial']
    put('tool_attempt',dict(name='search_evidence',arguments={'artifact':'browser'},operation_id='A3'))
    put('tool_result',dict(operation_id='A3',name='search_evidence',result={'records':[],'coverage':{'complete':True},'total':0}))
    assert w.query('actions')['items'][-1]['status']=='completed'
    put('tool_attempt',dict(name='search_evidence',arguments={'artifact':'mft'},operation_id='A4'))
    put('tool_failure',dict(operation_id='A4',code='ANALYST_CANCELLED'))
    assert w.query('actions')['items'][-1]['status']=='cancelled'
    w.close();j.close()


def test_legitimate_repeated_successes_not_prohibited(tmp_path):
    steps=[reply(calls=[call('search_evidence',{'artifact':'evtx','limit':1})]) for _ in range(4)]+[reply('Repeated checks did not establish causality.')]
    path,provider,scope=setup(tmp_path,steps);s=Session(scope,provider,lambda _:True)
    try:
        s.submit('Recheck the same retained record deliberately.')
        assert s.used['successful_forensic_operations']==4
        assert s.workspace.meta('latest_repeat') is not None
    finally:s.close()

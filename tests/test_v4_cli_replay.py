import json
import sqlite3
import pytest
from forensic_assistant.cli import main
from forensic_assistant.investigation_ai.controller import run
from forensic_assistant.investigation_ai.replay import replay
from forensic_assistant.investigation_ai.transcript import load
from test_v4_controller import Scripted, tool, final
from test_v4_worker import make_case, config

def test_replay_without_model_and_changed_case_refusal(tmp_path):
    path=tmp_path/'case.db';event=make_case(path);root=tmp_path/'runs'
    result=run(config(path),'PowerShell',root,client=Scripted([tool('show_evidence',{'evidence_id':event['id']}),final]))
    repeated=replay(config(path),root,result['investigation_id'])
    assert repeated['termination']=='REPLAY_MATCH' and repeated['model_called'] is False
    assert len(repeated['comparisons'])==2 and all(v['match'] for v in repeated['comparisons'])
    db=sqlite3.connect(path);db.execute("UPDATE events SET command_line='later state'");db.commit();db.close()
    changed=replay(config(path),root,result['investigation_id'])
    assert changed['termination']=='REPLAY_REFUSED' and 'EVIDENCE_STATE_CHANGED' in changed['reason']
    manifest,_=load(root,result['investigation_id']);assert manifest['status']=='ANSWER_SUPPORTED'

def test_cli_never_uses_write_opener(tmp_path,monkeypatch,capsys):
    path=tmp_path/'case.db';make_case(path)
    def forbidden(*args,**kwargs):raise AssertionError('V4 used write-capable opener')
    monkeypatch.setattr('forensic_assistant.cli.connect',forbidden)
    monkeypatch.setattr('forensic_assistant.investigation_ai.cli.LocalClient',lambda *args:Scripted([final]))
    assert main(['--db',str(path),'investigate-ai','PowerShell','--no-semantic','--json'])==0
    result=json.loads(capsys.readouterr().out)
    assert result['termination']=='ANSWER_SUPPORTED'
    assert main(['--db',str(path),'investigation','show',result['investigation_id'],'--explain'])==0
    reviewed=json.loads(capsys.readouterr().out)
    assert reviewed['events'] and reviewed['current_case_status']['matches_recorded_fingerprint'] is True
    assert main(['--db',str(path),'investigation','replay',result['investigation_id'],'--no-semantic'])==0
    assert json.loads(capsys.readouterr().out)['termination']=='REPLAY_MATCH'

def test_missing_database_never_created_and_noninteractive_approval_rejected(tmp_path,capsys):
    path=tmp_path/'absent.db'
    assert main(['--db',str(path),'investigate-ai','PowerShell','--approve-tools'])==2
    assert not path.exists()
    assert 'interactive' in capsys.readouterr().err
    assert main(['--db',str(path),'investigate-ai','PowerShell','--no-semantic'])==2
    assert not path.exists()

def test_optional_dependencies_not_imported_by_v4_deterministic(monkeypatch,tmp_path):
    import builtins
    original=builtins.__import__
    def guarded(name,*args,**kwargs):
        if name.split('.')[0] in ('torch','faiss','transformers','sentence_transformers','numpy'):
            raise AssertionError('Optional dependency loaded by deterministic controller')
        return original(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',guarded)
    path=tmp_path/'case.db';make_case(path)
    result=run(config(path),'PowerShell',tmp_path/'runs',client=Scripted([final]))
    assert result['termination']=='ANSWER_SUPPORTED'

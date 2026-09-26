from contextlib import closing
import json
from pathlib import Path
import sqlite3
import weakref
import pytest
from forensic_assistant.database.db import connect,register_source,insert_events
from forensic_assistant.ingest.normalize import normalize
from forensic_assistant.interactive.shell import Shell
from forensic_assistant.interactive.state import State
from forensic_assistant.interactive.case import validate
from test_interactive_shell import Input
from test_ingest import xml


def evidence_case(path,sha):
    with closing(connect(path)) as db:
        with db:
            register_source(db,sha,1,'synthetic.evtx')
            event=normalize(xml(),sha,'synthetic.evtx',512)
            insert_events(db,[event])
    return event.id


def test_real_commands_investigations_and_reports_are_isolated(tmp_path,monkeypatch,capsys):
    from test_v4_controller import Scripted,final
    from forensic_assistant.reporting.bundle import validate as validate_report
    a=tmp_path/'a.db';b=tmp_path/'b.db'
    aid=evidence_case(a,'a'*64);bid=evidence_case(b,'b'*64)
    monkeypatch.setattr('forensic_assistant.investigation_ai.cli.LocalClient',lambda *a:Scripted([final]))
    a_before=a.read_bytes();b_before=b.read_bytes()
    reader=Input(str(a),f'show {aid}','semantic status','investigate-ai PowerShell --no-semantic',
                 f'report generate --evidence {aid} --output "{tmp_path / "report-a"}"',
                 f'case "{b}"',f'show {aid}',f'show {bid}','semantic status',
                 'investigate-ai PowerShell --no-semantic',
                 f'report generate --evidence {bid} --output "{tmp_path / "report-b"}"','exit')
    assert Shell(State(None),reader).run()==0
    assert a.read_bytes()==a_before and b.read_bytes()==b_before
    for path,own,other,label in ((a,aid,bid,'a'),(b,bid,aid,'b')):
        root=Path(str(path)+'.investigations')
        manifests=list(root.glob('*/manifest.json'));assert len(manifests)==1
        report=json.loads((tmp_path/('report-'+label)/'report.json').read_text())
        rendered=json.dumps(report)
        assert own in rendered and other not in rendered
        assert validate_report(tmp_path/('report-'+label),case=path)['evidence_grounding']=='PASS'
    assert 'not found' in capsys.readouterr().err.lower()
    a.rename(tmp_path/'released-a.db');b.rename(tmp_path/'released-b.db')


def test_embedding_models_and_overrides_not_retained(tmp_path,monkeypatch):
    a=tmp_path/'a.db';b=tmp_path/'b.db';connect(a).close();connect(b).close()
    refs=[];paths=[]
    class Model:
        def __init__(self,path):refs.append(weakref.ref(self));paths.append(str(path))
    monkeypatch.setattr('forensic_assistant.semantic.model.LocalModel',Model)
    monkeypatch.setattr('forensic_assistant.semantic.index.search',lambda *a,**kw:{'synthetic':True})
    shell=Shell(State(None),Input(str(a),'semantic search "a" --model-path custom',f'case "{b}"','semantic search "b"','exit'))
    assert shell.run()==0
    assert paths==['custom',str(b.parent/'semantic-models'/'bge')]
    assert all(ref() is None for ref in refs)


def test_relative_long_unicode_paths_and_same_case(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder=tmp_path/('long-'+('a'*80))/('b'*80)/('c'*80);folder.mkdir(parents=True)
    case=folder/'unicode é 日.db';connect(case).close()
    assert validate(case.relative_to(tmp_path))==case
    state=State(None)
    assert Shell(state,Input(str(case),f'case "{case}"','exit')).run()==0
    assert state.recent==[str(case)]


def test_case_with_lock_rejects_selection_without_writes(tmp_path):
    case=tmp_path/'case.db';connect(case).close()
    with closing(sqlite3.connect(case)) as writer:
        writer.execute('BEGIN EXCLUSIVE')
        with pytest.raises(sqlite3.OperationalError):validate(case)
        writer.rollback()
    assert validate(case)==case


def test_state_redirection_rejected(tmp_path):
    target=tmp_path/'real';target.mkdir()
    link=tmp_path/'link'
    try:link.symlink_to(target,target_is_directory=True)
    except OSError:pytest.skip('Symlink creation unavailable')
    state=State(link/'ui-state.json').load()
    assert state.blocked
    state.remember(tmp_path/'case.db')
    assert not (target/'ui-state.json').exists()

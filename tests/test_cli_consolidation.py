"""Canonical workflows exercise existing services without provider/case access."""
import argparse
import json
from types import SimpleNamespace
import pytest
from forensic_assistant.cli import build_parser,dispatch
from forensic_assistant import workflow_cli,investigation_workflow as flow
from forensic_assistant.interactive import shell
from test_interactive_shell import Input,case

@pytest.fixture(autouse=True)
def forbid_provider(monkeypatch):
    monkeypatch.setattr('forensic_assistant.ai.backend.ModelBackend.complete',lambda *a,**k:pytest.fail('provider request'))

@pytest.mark.parametrize('words,operation',[
    ('case status','status'),('evidence search','search'),('evidence timeline','timeline'),
    ('evidence show EVTX:synthetic','show'),('evidence around EVTX:synthetic','around'),
    ('evidence source list','source'),('evidence semantic status','semantic'),
    ('analyze logons','logons'),('analyze session --logon-id 1','session'),
    ('analyze process-tree --evidence EVTX:synthetic','process-tree'),('analyze detections','detections'),
    ('analyze correlate EVTX:synthetic','investigate'),('evidence export mft','dump'),
    ('investigation advanced current-case question','investigate-ai'),
    ('investigation history show abc','ai-history'),('audit activity','activity'),
    ('ai status','ai'),('settings version','workflow')])
def test_operation_services(words,operation):
    assert build_parser().parse_args(words.split()).command==operation

@pytest.mark.parametrize('kind',['browser','registry','prefetch','evtx'])
def test_record_size_only_mft(kind):
    with pytest.raises(SystemExit):build_parser().parse_args(['evidence','ingest',kind,'sample','--record-size','1024'])
    assert build_parser().parse_args(['evidence','ingest','mft','sample','--record-size','1024']).record_size==1024

@pytest.mark.parametrize('choice,expected',[(('n',),None),(('y','n'),(False,False)),(('y','y','n'),(True,False)),(('y','y','y'),(True,True))])
def test_guided_separate_approvals(monkeypatch,choice,expected):
    monkeypatch.setattr('forensic_assistant.assessment_handoff.prepare',lambda *a:dict(assessment_id='saved',limitations=['Incomplete'],scope={'start':'s','end':'e'}))
    monkeypatch.setattr('forensic_assistant.ai.settings.load',lambda:{'provider':'openai','model':'synthetic'})
    calls=[]
    monkeypatch.setattr(flow.assessment_handoff_cli,'execute',lambda *a,**k:calls.append((a,k)) or {'kind':'assessment_investigation','message':'Synthetic'})
    answers=iter(choice)
    result=flow.run('synthetic','saved','Question',read=lambda p:next(answers),display=lambda t:None)
    if expected is None:assert result['stage']=='cloud_disclosure' and not calls
    else:
        assert len(calls)==1
        assert (calls[0][1]['decompose'],calls[0][1]['synthesize'])==expected
        assert calls[0][1]['autonomous'] is True
        assert calls[0][1]['live_explanation']==expected[1]

@pytest.mark.parametrize('cancel',[KeyboardInterrupt,EOFError])
def test_guided_cancel_before_dispatch(monkeypatch,cancel):
    monkeypatch.setattr('forensic_assistant.assessment_handoff.prepare',lambda *a:dict(assessment_id='saved',limitations=[]))
    monkeypatch.setattr('forensic_assistant.ai.settings.load',lambda:{'provider':'openai'})
    monkeypatch.setattr(flow.assessment_handoff_cli,'execute',lambda *a,**k:pytest.fail('execution'))
    def read(p):raise cancel()
    with pytest.raises((KeyboardInterrupt,EOFError)):flow.run('synthetic','saved','Question',read=read,display=lambda t:None)

@pytest.mark.parametrize('operation',['register','accept','reject','supersede'])
def test_findings_uuid_mismatch_no_write(monkeypatch,operation):
    class Workspace:
        def __init__(self,path):pass
        def export(self):return {'metadata':{'id':'selected'}}
        def __getattr__(self,name):pytest.fail('mutation reached')
    monkeypatch.setattr('forensic_assistant.investigation_ai.findings.Workspace',Workspace)
    with pytest.raises(ValueError,match='WORKSPACE_CHANGED'):
        workflow_cli.findings(SimpleNamespace(finding_operation=operation,workspace='synthetic',workspace_id='wrong'))

@pytest.mark.parametrize('cmd',[['settings','version'],['investigation','findings','list','--workspace','synthetic'],['investigation','history','show','fake','--transcripts','synthetic']])
def test_recorded_and_version_do_not_open_case(monkeypatch,cmd,capsys):
    monkeypatch.setattr('forensic_assistant.activity.Command',lambda *a:pytest.fail('live case audit'))
    monkeypatch.setattr('sqlite3.connect',lambda *a,**k:pytest.fail('database'))
    if 'findings' in cmd:monkeypatch.setattr(workflow_cli,'findings',lambda a:{'findings':[],'revision':0})
    if 'history' in cmd:monkeypatch.setattr('forensic_assistant.investigation_ai.cli.dispatch',lambda a:{'synthetic':True})
    assert dispatch(build_parser().parse_args(cmd))==0


def test_shell_nested_help_removed_aliases_and_quit(tmp_path,capsys):
    db=case(tmp_path)
    reader=Input(str(db),'settings color off','help','help all','help evidence search','expert','ask hello','exit','quit')
    app=shell.Shell(__import__('forensic_assistant.interactive.state',fromlist=['State']).State(None),reader)
    assert app.run()==0
    text=capsys.readouterr().out
    assert 'Unknown command: expert' in text and 'Unknown command: ask' in text and 'Unknown command: exit' in text
    assert 'investigation reason' in text and '--evtx-text' in text


def test_audit_verification_no_case_write(tmp_path,monkeypatch):
    from forensic_assistant import activity
    args=build_parser().parse_args(['--db',str(tmp_path/'none.db'),'audit','verify'])
    monkeypatch.setattr(activity,'Command',lambda *a:pytest.fail('audit mutation'))
    assert dispatch(args)==0
    assert not (tmp_path/'none.db').exists()


@pytest.mark.parametrize('choice',['existing','edit','interview'])
def test_start_briefing_paths_stop_before_evidence(monkeypatch,choice):
    document={'narrative':'original','answers':{},'interviews':[]}
    state={'revisions':[{'digest':'prior','content':document}]}
    saved=[]
    class Store:
        def __init__(self,case):pass
        def load(self):return state
        def save(self,value,prior):
            saved.append((value,prior));return state
    monkeypatch.setattr(flow,'Store',Store)
    monkeypatch.setattr(flow.briefing_workflow,'view',lambda value:value)
    monkeypatch.setattr(flow.briefing_workflow,'render',lambda value:'Unverified briefing')
    monkeypatch.setattr(flow.briefing_workflow,'edit',lambda *a:document)
    monkeypatch.setattr('forensic_assistant.briefing_interview.interview',lambda *a:document)
    monkeypatch.setattr(flow.assessment_cli,'assess',lambda *a,**k:pytest.fail('assessment without approval'))
    answers=iter([choice,*(['y'] if choice=='interview' else []),'n'])
    value=flow.start('synthetic',read=lambda p:next(answers),display=lambda t:None)
    assert value['stage']=='assessment'
    assert saved==([] if choice=='existing' else [(document,'prior')])


def test_case_new_separate_from_ingestion(tmp_path,monkeypatch):
    from forensic_assistant.interactive import workspace
    from forensic_assistant.interactive.state import State
    monkeypatch.setattr(workspace,'cases_root',lambda:tmp_path/'managed')
    monkeypatch.setattr('forensic_assistant.interactive.setup.add_evidence',lambda *a:pytest.fail('implicit ingestion'))
    app=shell.Shell(State(None),Input('Synthetic','Analyst','Lab','y'))
    assert workspace.create_empty(app)
    assert app.active.is_file()
    from contextlib import closing
    from forensic_assistant.interactive.case import open_existing
    with closing(open_existing(app.active)) as db:
        assert db.execute('select count(*) from evidence_records').fetchone()[0]==0
    app.audit.end()


def test_exact_stage_dependencies_fail_closed():
    from forensic_assistant.assessment_handoff_cli import execute
    with pytest.raises(ValueError,match='Synthesis requires'):
        execute('unopened','unknown',read=lambda p:'y',synthesize=True)


# Reuse the existing synthetic, integrity-checked recorded source fixture.
from test_findings import source,workspace,refs

def test_canonical_findings_mutations_revisions_and_source_binding(workspace,source):
    from forensic_assistant.investigation_ai.findings import Workspace
    p=build_parser();identity=workspace.export()['metadata']['id']
    root=['investigation','findings']
    common=['--workspace',str(workspace.directory),'--workspace-id',identity,'--actor','Analyst']
    registered=workflow_cli.run(p.parse_args(root+['register',*common,'--revision','0','--statement','Possible association.','--support',refs(source)[0]]))
    fid=registered['changed_finding_id']
    assert registered['revision']==1 and registered['findings'][0]['state']=='proposed'
    with pytest.raises(ValueError):
        workflow_cli.run(p.parse_args(root+['accept',fid,*common,'--revision','0','--rationale','Reviewed']))
    accepted=workflow_cli.run(p.parse_args(root+['accept',fid,*common,'--revision','1','--rationale','Reviewed']))
    assert accepted['revision']==2 and accepted['findings'][0]['state']=='accepted'
    changed=workflow_cli.run(p.parse_args(root+['supersede',fid,*common,'--revision','2','--rationale','New review','--statement','Association unresolved.','--support',refs(source)[0]]))
    assert changed['revision']==3
    assert Workspace(workspace.directory).get(fid)['findings'][0]['state']=='superseded'

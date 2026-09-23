import json
import pytest
from forensic_assistant.cli import main
from forensic_assistant.reporting.bundle import generate,validate,inspect
from forensic_assistant.investigation_ai.controller import run
from test_v4_worker import make_case,config
from test_v4_controller import Scripted,final

def test_cli_never_creates_missing_database(tmp_path,capsys):
    path=tmp_path/'missing.db'
    assert main(['--db',str(path),'report','generate','--evidence','unknown','--output',str(tmp_path/'report')])==2
    assert json.loads(capsys.readouterr().out)['status']=='FAILED'
    assert not path.exists() and not (tmp_path/'report').exists()

def test_cli_generate_show_validate(tmp_path,capsys):
    case=tmp_path/'case.db';event=make_case(case);output=tmp_path/'report'
    assert main(['--db',str(case),'report','generate','--evidence',event['id'],'--output',str(output)])==0
    assert json.loads(capsys.readouterr().out)['input_mode']=='explicit_evidence_ids'
    assert main(['report','show',str(output)])==0
    assert 'No complete investigation' in json.loads(capsys.readouterr().out)['scope']
    assert main(['report','validate',str(output),'--case',str(case)])==0
    assert json.loads(capsys.readouterr().out)['evidence_grounding']=='PASS'

def test_same_state_multiple_investigations_and_validation(tmp_path):
    case=tmp_path/'case.db';make_case(case);root=tmp_path/'runs'
    ids=[run(config(case),'PowerShell',root,client=Scripted([final]))['investigation_id'] for _ in range(2)]
    generate(case,tmp_path/'report',investigation_ids=ids,transcript_root=root)
    data=inspect(tmp_path/'report')[0]['data']
    observed=[c for c in data['claims'] if c['category']=='OBSERVED FACT']
    assert len(observed)==1 and observed[0]['origins']==sorted(ids)
    assert validate(tmp_path/'report',case=case)['evidence_grounding']=='NOT_CHECKED'
    assert validate(tmp_path/'report',case=case,transcript_root=root)['evidence_grounding']=='PASS'
    import sqlite3
    db=sqlite3.connect(case);db.execute("UPDATE events SET command_line='changed'");db.commit();db.close()
    newer=run(config(case),'PowerShell',root,client=Scripted([final]))['investigation_id']
    with pytest.raises(ValueError,match='different evidence states'):
        generate(case,tmp_path/'mixed',investigation_ids=[ids[0],newer],transcript_root=root)

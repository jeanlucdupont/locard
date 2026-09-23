import sqlite3
import pytest
from forensic_assistant.reporting.collect import build, ReportWorker
from forensic_assistant.reporting.model import Limits
from forensic_assistant.investigation_ai.controller import run
from test_v4_worker import make_case, config
from test_v4_controller import Scripted, final

def test_direct_selection_is_not_an_investigation(tmp_path):
    path=tmp_path/'case.db';event=make_case(path)
    result=build(path,evidence_ids=[event['id']])
    assert result['input_mode']=='explicit_evidence_ids'
    assert 'No complete investigation' in result['scope']
    assert result['methodology']['input_mode']==result['input_mode']
    assert result['investigations']==[]
    assert result['timeline'][0]['source']=='EVTX SystemTime'
    assert result['claims'] and result['graph']['evidence_to_claims'][event['id']]
    assert 'source_locations' not in next(iter(result['inventory'].values()))
    assert build(path,evidence_ids=[event['id']])==result

def test_investigation_grounding_and_case_change(tmp_path):
    path=tmp_path/'case.db';make_case(path)
    result=run(config(path),'PowerShell',tmp_path/'runs',client=Scripted([final]))
    report=build(path,investigation_ids=[result['investigation_id']],transcript_root=tmp_path/'runs')
    assert report['claims'][0]['assertion']['value']=='powershell.exe'
    db=sqlite3.connect(path);db.execute("UPDATE events SET process_name='changed.exe'");db.commit();db.close()
    with pytest.raises(ValueError,match='EVIDENCE_STATE_CHANGED'):
        build(path,investigation_ids=[result['investigation_id']],transcript_root=tmp_path/'runs')

def test_report_worker_releases_snapshot_and_rejects_sql(tmp_path):
    path=tmp_path/'case.db';event=make_case(path)
    with ReportWorker({'case_path':str(path)}) as worker:
        response=worker.call('collect',{'ids':[event['id']]})
        writer=sqlite3.connect(path);writer.execute("UPDATE events SET process_name='other.exe'");writer.commit()
        assert writer.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()==(0,0,0);writer.close()
        with pytest.raises(ValueError,match='STATE_CHANGED'):worker.call('check',fingerprint=response['fingerprint'])
        with pytest.raises(ValueError,match='Unknown'):worker.call('SELECT * FROM events')

def test_bounded_claim_omissions_are_visible(tmp_path):
    path=tmp_path/'case.db';event=make_case(path)
    report=build(path,evidence_ids=[event['id']],limits=Limits(claims=1))
    assert report['status']=='COMPLETE_WITH_LIMITATIONS' and report['omissions']['claims']>0
    assert any(c['category']=='LIMITATION' for c in report['claims'])

def test_report_preserves_case_bytes_and_source_location_semantics(tmp_path):
    import hashlib
    from forensic_assistant.database.db import connect,register_source
    from test_ingest import SHA
    path=tmp_path/'case.db';event=make_case(path,wal=False)
    db=connect(path)
    with db:register_source(db,SHA,1,'second-synthetic-location.evtx')
    db.close();before=hashlib.sha256(path.read_bytes()).hexdigest()
    normal=build(path,evidence_ids=[event['id']])
    explicit=build(path,evidence_ids=[event['id']],include_source_locations=True)
    assert 'source_locations' not in normal['inventory'][SHA]
    assert explicit['inventory'][SHA]['source_locations']==['second-synthetic-location.evtx','synthetic.evtx']
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before
    db=sqlite3.connect(path)
    assert db.execute('SELECT source_file FROM events').fetchone()[0]=='synthetic.evtx'
    assert db.execute('PRAGMA user_version').fetchone()[0]==3
    db.close()

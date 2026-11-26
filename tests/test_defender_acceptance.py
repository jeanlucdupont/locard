"""Defender v2 policies and atomic maintenance; synthetic evidence only."""
import base64
import hashlib
import json
import sqlite3
import subprocess
import sys
import pytest
from forensic_assistant import activity
from forensic_assistant.artifacts.defender import timestamp,parse,interpret
from forensic_assistant.artifacts.defender_maintenance import repair,population
from forensic_assistant.database.artifacts import dump
from forensic_assistant.database import sources
from forensic_assistant.retrieval.evidence import get_evidence
from forensic_assistant.conversational_ai.tools import Tools
from test_defender_artifacts import case,local_worker,log,parsed,ASR,STAMP

BM='BEGIN BM telemetry\nGUID: xyz\nSignatureID: 55\nSigSha: opaque\nThreatLevel: 1\nProcessID: 4\nProcessCreationTime: 134394059202396034\nSessionID: 1\nCreationTime: 11-17-2026 16:18:40\nImagePath: C:\\lab\\neutral.exe\nTaint Info: Parents: opaque\nOperations: opaque\nEND BM telemetry\n'

@pytest.fixture(autouse=True)
def private(tmp_path,monkeypatch):monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))

@pytest.mark.parametrize('value,convention,policy,expected,status',[
 ('2026-11-17T16:18:40.123456789','mplog-leading','format-utc','2026-11-17T16:18:40.123456789Z','normalized'),
 ('2026-11-17T16:18:40Z',None,'unknown','2026-11-17T16:18:40.000000000Z','normalized'),
 ('2026-11-17T16:18:40+02:00',None,'UTC','2026-11-17T14:18:40.000000000Z','normalized'),
 ('11-17-2026 16:18:40','bm-creation','format-utc','2026-11-17T16:18:40.000000000Z','normalized'),
 ('11-17-2026 16:18:40.12-06:00','bm-creation','format-utc','2026-11-17T22:18:40.120000000Z','normalized'),
 ('2026-11-17T16:18:40','mplog-leading','unknown',None,'timezone_unknown'),
 ('2026-11-17T16:18:40',None,'format-utc',None,'timezone_unknown'),
 ('11-17-2026 16:18:40',None,'-06:00','2026-11-17T22:18:40.000000000Z','normalized'),
 ('02-30-2026 16:18:40','bm-creation','UTC',None,'invalid'),
 ('nonsense','bm-creation','UTC',None,'unsupported_format'),
 ('','bm-creation','UTC',None,'missing'),
])
def test_policies(value,convention,policy,expected,status):
 t=timestamp(value,'x','test meaning',policy,convention)
 assert t['timestamp_utc']==expected and t['normalization_status']==status
 assert t['original_value']==value and t['parser_version']=='2'
 if status=='normalized':assert t['interpretation_basis']!='none'


def test_completeness_and_meanings(tmp_path):
 r=parsed(log(tmp_path,BM))[0]
 assert r['detail']['parsing_status']=='parsed'
 assert r['timestamps'][0]['timestamp_utc']=='2026-11-17T16:18:40.239603400Z'
 assert r['timestamps'][0]['precision_ns']==100
 assert r['timestamps'][1]['precision_ns']==1000000000
 assert r['timestamps'][0]['meaning']!=r['timestamps'][1]['meaning']
 for value in ('invalid','02-30-2026 16:18:40','2026-11-17T16:18:40'):
  r=parsed(log(tmp_path,BM.replace('11-17-2026 16:18:40',value)))[0]
  assert r['detail']['parsing_status']=='parsed' and r['detail']['structural_status']=='complete'
 r=parsed(log(tmp_path,BM.replace('END BM telemetry','')))[0]
 assert r['detail']['parsing_status']=='partial' and r['detail']['structural_status']=='incomplete'
 r=parsed(log(tmp_path,BM.replace('END BM telemetry','CreationTime: 11-17-2026 17:00:00\nEND BM telemetry')))[0]
 assert len(r['timestamps'])==3 and len({t['slot'] for t in r['timestamps']})==3


def legacy(db):
 """Emulate retained v1 timestamp derivation, without changing original bytes."""
 for row in list(db.execute("SELECT evidence_id,original_json FROM evidence_records WHERE source_type='defender'")):
  d=json.loads(row['original_json'])
  for k in ('timestamp_interpretations','parser_version','time_policy','structural_status','decoding_status'):d.pop(k,None)
  if d['category']=='behavior_telemetry':d['parsing_status']='partial';d['limitations']+=['Invalid timestamp retained without inventing a normalized time.','Incomplete or size-fragmented original record; do not infer completeness.']
  db.execute("UPDATE evidence_records SET original_json=?,parser_version='1' WHERE evidence_id=?",(dump(d),row['evidence_id']))
 db.execute("UPDATE evidence_timestamps SET timestamp_utc=NULL,normalization_status='timezone_unknown' WHERE encoding='recorded text'");db.commit()


def apply(db,sid):
 path=db.execute('PRAGMA database_list').fetchone()[2]
 with activity.bind(activity.Session(path)),activity.mutation('DEFENDER_NORMALIZATION_REPAIR'):
  return repair(db,sid,apply=True)


def test_repair_preview_identity_provenance_idempotency(tmp_path):
 db,sid,scope,p,_=case(tmp_path,BM+ASR.replace('Z',''),runner=local_worker);legacy(db)
 original=p.read_bytes();members=[tuple(r) for r in db.execute('SELECT * FROM source_assignment_files')];runs=[tuple(r) for r in db.execute('SELECT * FROM ingestion_runs')]
 rows={r['evidence_id']:json.loads(r['original_json']) for r in db.execute('SELECT * FROM evidence_records')}
 before=list(db.iterdump());preview=repair(db,sid);assert preview['changed']==2 and list(db.iterdump())==before
 result=apply(db,sid);assert result['comparison_sha256']==preview['comparison_sha256']
 assert result['after']['parsed']==2 and result['after']['with_time']==2
 for row in db.execute('SELECT * FROM evidence_records'):
  d=json.loads(row['original_json']);assert d['raw_base64']==rows[row['evidence_id']]['raw_base64'];assert d['text']==rows[row['evidence_id']]['text'];assert len(d['normalization_history'])==1
 assert [tuple(r) for r in db.execute('SELECT * FROM source_assignment_files')]==members
 assert [tuple(r) for r in db.execute('SELECT * FROM ingestion_runs ORDER BY id')]==runs
 assert p.read_bytes()==original
 assert apply(db,sid)['changed']==0
 assert db.execute("SELECT count(*) FROM artifact_runs WHERE parser_name='locard.defender.repair'").fetchone()[0]==0
 assert db.execute('PRAGMA user_version').fetchone()[0]==5
 eid=next(iter(rows));assert 'normalization_history' not in get_evidence(db,eid)['detail']
 db.close()

@pytest.mark.parametrize('failure',['cancel','callback','bytes','shared','missing','boundary','future_parser'])
def test_atomic_refusal(tmp_path,failure,monkeypatch):
 monkeypatch.setattr('forensic_assistant.investigation_ai.snapshot.tempfile.gettempdir',lambda:str(tmp_path))
 db,sid,scope,p,_=case(tmp_path,BM+ASR,runner=local_worker);legacy(db)
 if failure=='bytes':db.execute("UPDATE evidence_records SET original_json=json_set(original_json,'$.raw_base64','QUFB')")
 if failure=='shared':
  other=sources.create(db,name='second');sources.assign(db,other,[hashlib.sha256(p.read_bytes()).hexdigest()],reason='test')
 if failure=='missing':
  eid=db.execute('SELECT evidence_id FROM evidence_records ORDER BY evidence_id DESC').fetchone()[0]
  db.execute('DELETE FROM evidence_timestamps WHERE evidence_id=?',(eid,));db.execute('DELETE FROM evidence_objects WHERE evidence_id=?',(eid,));db.execute('DELETE FROM evidence_records WHERE evidence_id=?',(eid,))
 if failure=='future_parser':db.execute("UPDATE evidence_records SET parser_version='999'")
 if failure=='boundary':db.execute("UPDATE evidence_records SET locator_json=json_set(locator_json,'$.ordinal',99)")
 db.commit();before=list(db.iterdump())
 def progress(n):
  if failure=='cancel':raise KeyboardInterrupt()
  if failure=='callback':raise RuntimeError('synthetic failure')
 with activity.bind(activity.Session(tmp_path/'case.db')):
  with pytest.raises((ValueError,KeyboardInterrupt,RuntimeError)):
   repair(db,sid,apply=True,progress=progress)
 assert list(db.iterdump())==before
 assert not list(tmp_path.glob('locard-investigation-*'))
 db.close()


def test_summary_priority_original_verification_and_unknown(tmp_path):
 text=BM.replace('11-17-2026 16:18:40','01-01-2026 12:00:00')+ASR.replace(STAMP,'No time')+'unknown abc\nunknown abc\n'
 db,sid,scope,p,_=case(tmp_path,text,runner=local_worker)
 tools=Tools(db,scope);result=tools.execute('activity_overview',dict(kind='defender_groups',limit=10));bm=next(r for r in result['records'] if r['category']=='behavior_telemetry')
 names=[f['name'] for f in bm['original_fields']];assert names[:2]==['ImagePath','ProcessID']
 image=bm['original_fields'][0];assert image['field']=='/detail/fields/8/value'
 assert tools.execute('verify_observation',dict(evidence_id=bm['evidence_id'],field=image['field'],value_json=json.dumps(image['value'])))['verified']
 stats=population(db,sid);assert stats['without_normalized_time']==3
 assert next(iter(stats['unknown_prefix_groups'].values()))['text']=='unknown abc\n'
 db.close()


def test_script_explicit_authorization_and_readonly_preview(tmp_path):
 db,sid,scope,p,_=case(tmp_path,BM,runner=local_worker);legacy(db);db.close()
 command=[sys.executable,'scripts/defender_maintenance.py','--db',str(tmp_path/'case.db'),'--source',sid]
 assert subprocess.run(command+['--apply'],capture_output=True).returncode==2
 r=subprocess.run(command+['--preview'],capture_output=True,text=True);assert r.returncode==0,r.stderr
 assert json.loads(r.stdout)['changed']==1
 r=subprocess.run(command+['--apply','--confirm'],capture_output=True,text=True);assert r.returncode==0,r.stderr
 assert json.loads(r.stdout)['applied']
 assert activity.inspect(tmp_path/'case.db.audit.jsonl')['valid'] is True


def test_ingestion_policy_is_explicit_and_preserves_other_evidence(tmp_path):
 from forensic_assistant.cli import main
 from forensic_assistant.database.db import connect
 db=connect(tmp_path/'policy.db');sid=sources.create(db,name='test');db.commit();db.close()
 p=log(tmp_path,ASR.replace('Z',''))
 assert main(['--db',str(tmp_path/'policy.db'),'evidence','ingest','defender',str(p),'--source',sid,'--defender-time-policy','unknown','--json'])==0
 db=connect(tmp_path/'policy.db',existing_only=True)
 assert db.execute('SELECT timestamp_utc FROM evidence_timestamps').fetchone()[0] is None
 assert json.loads(db.execute('SELECT parameters_json FROM artifact_runs').fetchone()[0])['defender_time_policy']=='unknown'
 db.close()


def test_unsupported_policies_and_mp_detection(tmp_path):
 with pytest.raises(ValueError):timestamp('2026-01-01T00:00:00','x','x','local')
 p=tmp_path/'MPDetection-test.log';p.write_text(ASR.replace('Z',''))
 t=parsed(p)[0]['timestamps'][0];assert t['normalization_status']=='timezone_unknown'
 t=list(parse(p,hashlib.sha256(p.read_bytes()).hexdigest(),defender_time_policy='UTC'))[0]['timestamps'][0]
 assert t['timestamp_utc']==STAMP.replace('.123Z','.123000000Z')


def test_audit_intent_failure_prevents_script_changes(tmp_path,monkeypatch):
 import importlib.util
 spec=importlib.util.spec_from_file_location('maintenance_script','scripts/defender_maintenance.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 db,sid,scope,p,_=case(tmp_path,BM,runner=local_worker);legacy(db);before=list(db.iterdump());db.close()
 def fail(*args,**kwargs):raise activity.AuditError('synthetic append failure')
 monkeypatch.setattr(activity,'append',fail)
 monkeypatch.setattr(sys,'argv',['maintenance','--db',str(tmp_path/'case.db'),'--source',sid,'--apply','--confirm'])
 assert module.main()==2
 db=sqlite3.connect(tmp_path/'case.db');assert list(db.iterdump())==before;db.close()


def test_unrelated_records_and_epoch_fingerprint(tmp_path):
 from forensic_assistant.database.db import register_source
 db,sid,scope,p,_=case(tmp_path,BM,runner=local_worker);legacy(db)
 register_source(db,'e'*64,0,'other.evtx')
 db.execute("INSERT INTO evidence_records(evidence_id,source_type,artifact_type,file_sha256,source_file,locator_json,extractor_version,warnings_json,original_json) VALUES ('EVTX:synthetic','evtx','event',?,'other.evtx','{}','1','[]','{}')",('e'*64,));db.commit()
 from forensic_assistant.semantic.documents import fingerprint
 old_fingerprint=fingerprint(db)
 preserved=tuple(db.execute("SELECT * FROM evidence_records WHERE evidence_id='EVTX:synthetic'").fetchone())
 apply(db,sid)
 assert fingerprint(db)!=old_fingerprint
 assert tuple(db.execute("SELECT * FROM evidence_records WHERE evidence_id='EVTX:synthetic'").fetchone())==preserved
 db.close()


def test_unsupported_leading_suffix_never_becomes_utc(tmp_path):
 p=log(tmp_path,ASR.replace(STAMP,'2026-01-01T12:00:00+02'))
 t=parsed(p)[0]['timestamps'][0]
 assert t['original_value']=='2026-01-01T12:00:00+02'
 assert t['timestamp_utc'] is None and t['normalization_status']=='unsupported_format'

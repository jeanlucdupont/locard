"""Synthetic Defender original bytes and production integration; no live sources."""
import base64
import hashlib
import json
import sqlite3
from pathlib import Path
import pytest
from forensic_assistant.artifacts.defender import parse,supported
from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.database.db import connect
from forensic_assistant.database import sources
from forensic_assistant.retrieval.evidence import EvidenceQueries,get_evidence
from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
from forensic_assistant.conversational_ai.tools import Tools

STAMP='2026-01-01T12:00:00.123Z'
ASR=STAMP+' ASR Notification:Process: C:\\Windows\\neutral.exe, Action: BLOCK, Target: C:\\lab\\other.exe, Reason: 0, Persisted: y, Rule:0x1234\r\n'
LOW=STAMP+' Engine:command line reported as lowfi: C:\\lab\\neutral.exe(neutral.exe --json {"x":"(nested)"})\r\n'

@pytest.fixture(autouse=True)
def private(tmp_path,monkeypatch):monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))

def log(tmp_path,text=ASR,enc='utf-8'):
 p=tmp_path/'MPLog-synthetic.log';p.write_bytes(text.encode(enc));return p

def parsed(path):return list(parse(path,hashlib.sha256(path.read_bytes()).hexdigest()))

def case(tmp_path,text=ASR,runner=None):
 p=log(tmp_path,text);db=connect(tmp_path/'case.db');sid=sources.create(db,name='Synthetic')
 kwargs={} if runner is None else {'runner':runner}
 result=ingest_artifact(db,p,'defender',**kwargs)
 assert result['status']=='complete',result
 sha=hashlib.sha256(p.read_bytes()).hexdigest();sources.assign(db,sid,[sha],reason='Synthetic');db.commit()
 scope=authorize(tmp_path/'case.db',[sid],'2026-01-01T00:00:00Z','2026-01-02T00:00:00Z',list(FAMILIES),'openai','scripted')
 return db,sid,scope,p,result

@pytest.mark.parametrize('enc',['utf-8','utf-8-sig','utf-16','utf-16-be'])
def test_bytes_fields_timestamp_and_encoding(tmp_path,enc):
 p=log(tmp_path,LOW+ASR+'unknown future message\r\n',enc);packs=parsed(p)
 assert b''.join(base64.b64decode(x['detail']['raw_base64']) for x in packs)==p.read_bytes()
 assert [x['record']['artifact_type'] for x in packs]==['lowfi','asr_notification','unknown']
 assert dict((f['name'],f['value']) for f in packs[0]['detail']['fields'])['CommandLine']=='neutral.exe --json {"x":"(nested)"}'
 assert packs[0]['timestamps'][0]['timestamp_utc']=='2026-01-01T12:00:00.123000000Z'
 assert packs[1]['record']['locator_json']


def test_multiline_unknown_repeated_fields_and_incomplete(tmp_path):
 text='BEGIN BM telemetry\r\nGUID: abc\r\nImagePath: C:\\lab\\neutral.exe\r\nProcessID: 4\r\nMystery: a\r\nMystery: b\r\nCreationTime: 2026-01-01T12:00:00\r\nEND BM telemetry\r\nBEGIN BM telemetry\r\nProcessID: 5'
 records=parsed(log(tmp_path,text));assert len(records)==2
 assert [f['value'] for f in records[0]['detail']['fields'] if f['name']=='Mystery']==['a','b']
 assert records[0]['timestamps'][0]['timestamp_utc'] is None
 assert records[1]['detail']['parsing_status']=='partial'


def test_real_worker_publication_duplicate_and_retrieval(tmp_path):
 db,sid,scope,p,result=case(tmp_path,ASR+LOW)
 try:
  original=p.read_bytes();again=ingest_artifact(db,p,'defender');assert again['duplicates']==2 and again['inserted']==0
  tools=Tools(db,scope);found=tools.execute('discover_security_signals',{'artifact':'defender'})
  assert len(found['records'])==2
  row=found['records'][0];assert row['category']=='asr_notification'
  action=next(f for f in row['original_fields'] if f['name']=='Action')
  assert tools.execute('verify_observation',dict(evidence_id=row['evidence_id'],field=action['field'],value_json='"BLOCK"'))['verified']
  assert tools.execute('show_evidence',dict(evidence_id=row['evidence_id']))
  members=tools.execute('search_evidence',row['members_filter']);assert len(members['records'])==1
  assert p.read_bytes()==original
 finally:db.close()


def test_groups_entire_population_and_ambiguous_time(tmp_path):
 db,sid,scope,p,result=case(tmp_path,ASR*101+ASR.replace('BLOCK','AUDIT')+LOW+LOW.replace('nested','different')+ASR.replace(STAMP,'No assignable timestamp'))
 try:
  tools=Tools(db,scope);answer=tools.execute('activity_overview',dict(kind='defender_groups',limit=10))
  assert sorted(x['count'] for x in answer['records'])==[1,1,1,101]
  assert answer['coverage']['time_unassignable_records']==1
  assert sum(x['count'] for x in answer['records'])==104
  assert answer==tools.execute('activity_overview',dict(kind='defender_groups',limit=10))
  found=EvidenceQueries(db).search(artifact='defender',defender_action='AUDIT',source_scope=sid)
  assert len(found.records)==1
 finally:db.close()


def test_invalid_file_does_not_become_evidence(tmp_path):
 p=log(tmp_path,'unrelated arbitrary text');db=connect(tmp_path/'case.db')
 try:
  r=ingest_artifact(db,p,'defender');assert r['inserted']==0 and r['errors'] and r['status'] in ('partial','failed')
 finally:db.close()


def local_worker(kind,path,sha,stage,options,timeout):
 from forensic_assistant.artifacts.worker import run
 return run(kind,path,sha,stage,options)


def test_readonly_scope_uncertainty_and_redaction(tmp_path):
 from copy import deepcopy
 db,sid,scope,p,_=case(tmp_path,ASR+LOW.replace('nested','password=SuperSecret'),runner=local_worker)
 try:
  before=db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]
  tools=Tools(db,scope)
  for args in ({'artifact':'defender','source_id':'forged'},{'artifact':'defender','start':'2025-01-01T00:00:00Z'}):
   with pytest.raises(ValueError):tools.execute('discover_security_signals',args)
  restricted=deepcopy(scope);restricted['families']=['evtx']
  with pytest.raises(ValueError):Tools(db,restricted).execute('discover_security_signals',{'artifact':'defender'})
  response=tools.execute('discover_security_signals',{'artifact':'defender'})
  for row in response['records']:
   for f in row['original_fields']:
    if f['redacted'] or f['truncated']:assert f['field'] not in tools.disclosed.get(row['evidence_id'],{})
  other=sources.create(db,name='other');sources.assign(db,other,[hashlib.sha256(p.read_bytes()).hexdigest()],reason='Synthetic ambiguity');db.commit()
  assert Tools(db,scope).execute('activity_overview',{'kind':'defender_groups'})['records']==[]
  assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]==before
 finally:db.close()


def test_long_invalid_bytes_and_fragment_preservation(tmp_path):
 from forensic_assistant.artifacts.defender import MAX_CHUNK
 p=log(tmp_path,LOW);p.write_bytes(p.read_bytes()+b'Engine:'+b'x'*(MAX_CHUNK+10)+b'\xff\r\n')
 records=parsed(p)
 assert len(records)==3
 assert b''.join(base64.b64decode(r['detail']['raw_base64']) for r in records)==p.read_bytes()
 assert all(r['detail']['parsing_status']=='partial' for r in records[1:])
 assert 'Undecodable' in ' '.join(records[-1]['detail']['limitations'])
 assert json.loads(records[1]['record']['locator_json'])['line_start']==json.loads(records[2]['record']['locator_json'])['line_start']


def test_categories_not_verdicts_and_unknown_status(tmp_path):
 texts=['Engine:Process 4212 will be fully monitored because of injection from C:\\lab\\agent.exe',
        'RTP minifilter Path: C:\\lab\\file, Process: C:\\lab\\agent.exe, Status: 0xBAD, FileId: 10',
        'Engine:signature match SignatureID: 12', 'Engine:signature throttling enabled',
        'Engine:dynamic signature received', 'Service startup', 'Engine Version: 1.2.3',
        'Engine:cloud communication failed', 'Engine:configuration changed',
        'Detection add: Threat: synthetic', 'Remediation: Action: unknown']
 p=log(tmp_path,'\r\n'.join(STAMP+' '+v for v in texts))
 records=parsed(p)
 assert [r['record']['artifact_type'] for r in records]==['injection_monitoring','file_scan','signature_observation','signature_throttling','signature_update','service_start','version','cloud_diagnostic','configuration','detection','remediation']
 assert records[1]['detail']['fields'] and '0xBAD' in str(records[1]['detail']['fields'])
 assert not any('confidence' in r['detail'] for r in records)


def test_existing_case_cli_source_and_human_render(tmp_path):
 from forensic_assistant.cli import build_parser
 from forensic_assistant.v2_cli import ingest_sources
 from forensic_assistant.retrieval import show_display,search_display
 p=log(tmp_path,ASR);db=connect(tmp_path/'case.db');sid=sources.create(db,name='existing');db.commit()
 try:
  schema=db.execute('PRAGMA user_version').fetchone()[0]
  args=build_parser().parse_args(['evidence','ingest','defender',str(p),'--source',sid])
  results=ingest_sources(db,args);assert results[0]['inserted']==1
  assert db.execute('PRAGMA user_version').fetchone()[0]==schema
  records=EvidenceQueries(db).search(artifact='defender',source_scope=sid).as_dict()
  assert len(records['records'])==1
  assert 'ASR' in show_display.render(records['records'][0])
  assert 'asr_notification' in search_display.render(records,ids=True)
 finally:db.close()


def test_incomplete_records_retained_partial_and_interrupt_rejects_stage(tmp_path):
 p=log(tmp_path,'BEGIN BM telemetry\r\nProcessID: 1\r\n');db=connect(tmp_path/'case.db')
 try:
  r=ingest_artifact(db,p,'defender',runner=local_worker);assert r['inserted']==1 and r['status']=='partial' and r['errors']==1
  before=db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]
  def interrupted(*args):raise KeyboardInterrupt()
  with pytest.raises(KeyboardInterrupt):ingest_artifact(db,p,'defender',runner=interrupted)
  assert db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]==before
  assert db.execute('SELECT status FROM ingestion_runs ORDER BY id DESC LIMIT 1').fetchone()[0]!='complete'
 finally:db.close()


def test_time_precision_invalid_filetime_and_exclusive_end(tmp_path):
 from forensic_assistant.artifacts.defender import timestamp
 assert timestamp('2026-99-01T00:00:00','x','x')['normalization_status']=='invalid'
 assert timestamp('2026-01-01T00:00:00.123456789Z','x','x')['timestamp_utc'].endswith('.123456789Z')
 p=log(tmp_path,'BEGIN BM telemetry\nProcessCreationTime: 134116992000000000\nCreationTime: invalid\nEND BM telemetry\n')
 r=parsed(p)[0];assert r['timestamps'][0]['encoding']=='FILETIME' and r['timestamps'][1]['normalization_status']=='unsupported_format'
 db,sid,scope,p,_=case(tmp_path,ASR.replace('2026-01-01T12:00:00.123Z','2026-01-02T00:00:00Z'),runner=local_worker)
 try:assert not Tools(db,scope).execute('activity_overview',{'kind':'defender_groups'})['records']
 finally:db.close()


def test_scripted_defender_pivot_real_worker(tmp_path):
 from forensic_assistant.conversational_ai.service import Session,notebook
 from forensic_assistant.conversational_ai.provider import ScriptedProvider
 from test_conversational_ai import reply,call,last
 from test_security_discovery import event,DEFENDER,DEFENDER_CHANNEL
 from forensic_assistant.database.db import register_source
 db,sid,scope,p,_=case(tmp_path,ASR,runner=local_worker)
 register_source(db,'b'*64,10,'synthetic.evtx');sources.assign(db,sid,['b'*64],reason='Synthetic')
 event(db,1,1121,fields={'Target Commandline':'neutral.exe'},sha='b'*64,stamp=STAMP);db.commit();db.close()
 def members(messages):return reply(calls=[call('search_evidence',last(messages)['records'][0]['members_filter'])])
 def inspect(messages):return reply(calls=[call('show_evidence',{'evidence_id':last(messages)['records'][0]['evidence_id'],'limit':40})])
 def pivot(messages):return reply(calls=[call('search_evidence',dict(artifact='evtx',event_id=1121))])
 provider=ScriptedProvider([reply(calls=[call('discover_security_signals',{'artifact':'defender'})]),members,inspect,pivot,reply('These are potentially related observations, not proven causality.')])
 session=Session(scope,provider,lambda _:True)
 try:result=session.submit('Examine retained security observations without assuming compromise.')
 finally:session.close()
 assert session.used['successful_forensic_operations']==4
 assert notebook(str(tmp_path/'case.db')+'.conversations',session.journal.id)==notebook(str(tmp_path/'case.db')+'.conversations',session.journal.id)


def test_provider_free_diagnostic_and_renamed_unicode_input(tmp_path):
 import subprocess,sys
 from forensic_assistant.artifacts.ingest import discover
 p=log(tmp_path,LOW+ASR,'utf-16');renamed=tmp_path/'renamed.bin';p.rename(renamed)
 assert list(discover(renamed,'defender'))==[(renamed,'defender')]
 result=subprocess.run([sys.executable,'scripts/defender_artifacts.py',str(renamed),'--json','--limit','1'],capture_output=True,text=True,timeout=15)
 assert result.returncode==0,result.stderr
 data=json.loads(result.stdout);assert data['categories']=={'lowfi':1,'asr_notification':1}
 assert data['source_unchanged'] and data['examples'][0]['detail']['raw_base64']


def test_discovery_members_path_and_incomplete_time_coverage(tmp_path):
 db,sid,scope,p,_=case(tmp_path,ASR+ASR.replace(STAMP,'No assignable timestamp'),runner=local_worker)
 try:
  tools=Tools(db,scope);groups=tools.execute('discover_security_signals',{'artifact':'defender'})
  assert not groups['coverage']['complete'] and groups['coverage']['timed_population_complete']
  row=groups['records'][0]
  result=tools.execute('search_evidence',{'artifact':'defender','object_basename':'other.exe'})
  assert len(result['records'])==1
  with pytest.raises(ValueError):tools.execute('show_evidence',{'evidence_id':'DEFENDER:invented'})
  assert groups['coverage']['time_unassignable_records']==1
 finally:db.close()


def test_defender_query_cancellation_keeps_read_view(tmp_path):
 import threading
 from test_retrieval_resilience import shim
 from forensic_assistant.conversational_ai.supervision import ConversationWorkerError
 db,sid,scope,p,_=case(tmp_path,ASR,runner=local_worker);db.close()
 cls=shim(tmp_path,"from forensic_assistant.artifacts import defender_query\noriginal=defender_query.groups\ndef slow(db,*a,**kw):\n if kw.get('offset')==1:db.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) SELECT sum(x) FROM n').fetchone()\n return original(db,*a,**kw)\ndefender_query.groups=slow")
 with cls(dict(case_path=scope['case'],scope=scope,_transaction_view=True)) as worker:
  view=worker.call('chat_init',seconds=5)['evidence_state']
  timer=threading.Timer(.2,worker.cancel);timer.start()
  try:
   with pytest.raises(ConversationWorkerError) as error:worker.call('activity_overview',{'kind':'defender_groups','offset':1},seconds=None)
  finally:timer.join()
  assert error.value.code=='ANALYST_CANCELLED' and error.value.view==view
  assert worker.call('activity_overview',{'kind':'defender_groups'},seconds=None)['result']['records']


def test_derived_group_metadata_not_original_verification(tmp_path):
 db,sid,scope,p,_=case(tmp_path,runner=local_worker)
 try:
  tools=Tools(db,scope);result=tools.execute('discover_security_signals',{'artifact':'defender'});eid=result['records'][0]['evidence_id']
  tools.execute('show_evidence',{'evidence_id':eid,'limit':40})
  with pytest.raises(ValueError,match='original'):
   tools.execute('verify_observation',{'evidence_id':eid,'field':'/detail/category','value_json':'"asr_notification"'})
  detail=get_evidence(db,eid)['detail'];assert 'group_key' not in detail and 'raw_base64' not in detail
 finally:db.close()


def test_unknown_and_partial_records_do_not_collapse(tmp_path):
 db,sid,scope,p,_=case(tmp_path,ASR+'2026-01-01T12:00:01Z unknown aaa\n2026-01-01T12:00:02Z unknown bbb\n',runner=local_worker)
 try:
  result=Tools(db,scope).execute('activity_overview',{'kind':'defender_groups','limit':10})
  assert len(result['records'])==3
 finally:db.close()


def test_documented_minifilter_and_mp_detection_service_variant(tmp_path):
 text=STAMP+' [Mini-filter] Unsuccessful scan status for file: C:\\lab\\doc.bin Process: C:\\lab\\app.exe, Status: 0xBAD, State: 1, ScanRequest 42, FileId: 123, Reason: 2, IoStatusBlockForNewFile: 0, DesiredAccess:1, FileAttributes:2, ScanAttributes:3, AccessStateFlags:4, BackingFileInfo: 5\r\n'
 rows=parsed(log(tmp_path,text));values={f['name']:f['value'] for f in rows[0]['detail']['fields']}
 assert rows[0]['record']['artifact_type']=='file_scan'
 assert values['Path']==r'C:\lab\doc.bin' and values['ScanRequest']=='42' and values['Status']=='0xBAD'
 p=tmp_path/'MPDetection-synthetic.log';p.write_text(STAMP+' Service started - Microsoft Defender Antivirus\n'+STAMP+' Engine Version: 1.2.3\n',encoding='utf-8')
 assert [r['record']['artifact_type'] for r in parsed(p)]==['service_start','version']

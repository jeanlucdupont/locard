"""Synthetic whole-population behavioral discovery; no reference incident indicators."""
import base64
import json
import sqlite3
import time
from pathlib import Path
import pytest
from forensic_assistant.database.db import connect,register_source
from forensic_assistant.database import sources
from forensic_assistant.conversational_ai.tools import Tools
from forensic_assistant.detections.execution_features import features
from test_security_discovery import fixture,event,readonly,SECURITY,START,END

@pytest.fixture(autouse=True)
def private(tmp_path,monkeypatch):monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))

@pytest.mark.parametrize('command,image,expected',[
 ('"C:\\Program Files\\Acme\\viewer.exe" document.txt',None,{'local_path'}),
 ('msiexec.exe /i suite.msi /quiet',None,set()),
 ('powershell.exe -NoProfile -File maintenance.ps1','powershell.exe',{'shell','interpreter_flags'}),
 ('cmd.exe /c python.exe task.py && echo finished','cmd.exe',{'shell','nested_interpreter','chaining'}),
 ('tool.exe https://assets.example.invalid/a -out C:\\Temp\\result.dat',None,{'remote_reference','local_path','output_redirection','user_writable_reference'}),
 ('cmd.exe /c echo %TEMP% ^& value','cmd.exe',{'shell','environment_reference','escaping'}),
 ('powershell.exe "unterminated','powershell.exe',{'shell','quoting_ambiguity'}),
 ('tool.exe résumé.txt',None,set()),
 (None,None,set()),
 ('reg.exe add HKCU\\Software\\Synthetic /v Entry /d benign',None,{'registry_operation'}),
 ('sc.exe create Synthetic binPath= C:\\lab\\agent.exe',None,{'service_task_operation','local_path'}),
])
def test_lexical(command,image,expected):
 r=features(command,image);assert expected<=set(r['features']);assert r['lexical_only']
 if not expected:assert not r['features']


def test_static_decoding_and_limits():
 encoded=base64.b64encode('Write-Output "training"'.encode('utf-16le')).decode()
 result=features('powershell.exe -EncodedCommand '+encoded,'powershell.exe')
 assert result['decoded']['text']=='Write-Output "training"' and result['decoded']['derived']
 assert features('powershell.exe -enc !!!','powershell.exe')['decoded']['status']=='unsupported_or_invalid'
 assert features('x'*40000)['analysis_truncated']


def populate(tmp_path,n=1500):
 path,sid,scope,_=fixture(tmp_path,alerts=());db=connect(path)
 for i in range(n):event(db,i,4688,SECURITY,'Security',{'NewProcessName':'C:\\Windows\\worker.exe','CommandLine':'worker.exe /routine','ParentProcessName':'services.exe'})
 rare=event(db,n+1,4688,SECURITY,'Security',{'NewProcessName':'cmd.exe','CommandLine':'cmd.exe /c python.exe job.py && echo %TEMP%','ParentProcessName':'explorer.exe'})
 remote=event(db,n+2,4688,SECURITY,'Security',{'NewProcessName':'tool.exe','CommandLine':'tool.exe https://cdn.example.invalid/item -out C:\\Temp\\item.dat'})
 missing=event(db,n+3,4688,SECURITY,'Security',{'NewProcessName':'missing.exe'})
 db.commit();db.close();return path,sid,scope,rare,remote,missing


def test_full_population_diversity_members_and_verification(tmp_path):
 path,sid,scope,rare,remote,missing=populate(tmp_path)
 with readonly(path) as db:
  tools=Tools(db,scope);r=tools.execute('discover_execution_behaviors',{'artifact':'evtx','limit':10})
  assert r['coverage']['records_processed']==1503
  assert r['coverage']['records_with_commands']==1502
  assert r['coverage']['analysis_complete'] and r['coverage']['counts_complete']
  assert rare in {x['evidence_id'] for x in r['records']}
  assert remote in {x['evidence_id'] for x in r['records']}
  chosen=next(x for x in r['records'] if x['evidence_id']==rare)
  f=next(x for x in chosen['original_fields'] if x['name']=='command')
  assert tools.execute('verify_observation',dict(evidence_id=rare,field=f['field'],value_json=json.dumps(f['value'])))['verified']
  assert tools.execute('discover_execution_behaviors',chosen['members'])['records'][0]['evidence_id']==rare
  assert r==tools.execute('discover_execution_behaviors',{'artifact':'evtx','limit':10})


def test_authorization_and_unknown_time(tmp_path):
 path,sid,scope,rare,remote,missing=populate(tmp_path,0);db=connect(path)
 event(db,9,4688,SECURITY,'Security',{'CommandLine':'outside.exe'},stamp=END)
 event(db,10,4688,SECURITY,'Security',{'CommandLine':'untimed.exe'},stamp='bad')
 register_source(db,'b'*64,1,'shared.evtx');sources.assign(db,sid,['b'*64],reason='test')
 other=sources.create(db,name='other');sources.assign(db,other,['b'*64],reason='test')
 event(db,11,4688,SECURITY,'Security',{'CommandLine':'shared.exe'},sha='b'*64)
 db.commit();db.close()
 with readonly(path) as db:
  tools=Tools(db,scope)
  for a in ({'source_id':other},{'start':'2019-01-01T00:00:00Z'}):
   with pytest.raises(ValueError):tools.execute('discover_execution_behaviors',a)
  r=tools.execute('discover_execution_behaviors',{'artifact':'evtx'})
  c=r['coverage']['families']['evtx'];assert c['excluded_unknown_time']==1 and c['excluded_ambiguous_source']==1 and c['excluded_outside_window']==1
  assert all(x['evidence_id'] not in ('outside.exe','shared.exe') for x in r['records'])


def test_scripted_worker_conversation(tmp_path):
 from forensic_assistant.conversational_ai.service import Session,notebook
 from forensic_assistant.conversational_ai.provider import ScriptedProvider
 from test_conversational_ai import reply,call,last
 path,sid,scope,rare,remote,missing=populate(tmp_path,5)
 def inspect(messages):return reply(calls=[call('show_evidence',{'evidence_id':last(messages)['records'][0]['evidence_id']})])
 provider=ScriptedProvider([reply(calls=[call('discover_execution_behaviors',{'feature':'nested_interpreter'})]),inspect,reply('Unusual structure is a lead; legitimate automation remains possible.')])
 session=Session(scope,provider,lambda _:True)
 try:session.submit('Review execution-related observations without assuming compromise.')
 finally:session.close()
 assert session.used['successful_forensic_operations']==2
 assert notebook(str(path)+'.conversations',session.journal.id)==notebook(str(path)+'.conversations',session.journal.id)

def test_cross_artifact_original_semantics(tmp_path):
 from forensic_assistant.artifacts.ingest import ingest_artifact
 from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES
 from v2_fixtures import registry_file,prefetch_file
 from test_defender_artifacts import ASR,LOW,local_worker
 path,sid,scope,*_=populate(tmp_path,0);db=connect(path)
 log=tmp_path/'MPLog-synthetic.log';log.write_text(ASR+LOW,encoding='utf-8')
 for family,p in [('registry',registry_file(tmp_path/'NTUSER.DAT',target=r'C:\lab\maintenance.exe')),('prefetch',prefetch_file(tmp_path/'neutral.pf')),('defender',log)]:
  r=ingest_artifact(db,p,family,**({'runner':local_worker} if family=='defender' else {}));assert r['inserted']>0,r
  shas=[x[0] for x in db.execute('SELECT DISTINCT file_sha256 FROM evidence_records WHERE source_type=?',(family,))]
  sources.assign(db,sid,shas,reason='Synthetic')
 db.commit();db.close()
 scope=authorize(path,[sid],'2010-01-01T00:00:00Z','2030-01-01T00:00:00Z',list(FAMILIES),'openai','scripted')
 before=path.read_bytes()
 with readonly(path) as db:
  tools=Tools(db,scope)
  meanings={'registry':'configured_execution','prefetch':'historical_execution_indicator','defender':'command_line_observation'}
  for family,meaning in meanings.items():
   r=tools.execute('discover_execution_behaviors',{'artifact':family,'limit':10})
   assert meaning in {x['kind'] for x in r['records']},r
   for row in r['records']:
    for f in row['original_fields']:
     if not f['truncated'] and not f['redacted']:
      assert tools.execute('verify_observation',dict(evidence_id=row['evidence_id'],field=f['field'],value_json=json.dumps(f['value'])))['verified']
  r=tools.execute('discover_execution_behaviors',{'limit':10})
  assert set(r['coverage']['families'])=={'registry','evtx','prefetch','defender'}
 assert path.read_bytes()==before


def test_worker_cancel_progress_and_recovery(tmp_path):
 import threading
 from test_retrieval_resilience import shim
 from forensic_assistant.conversational_ai.supervision import ConversationWorkerError
 path,sid,scope,*_=populate(tmp_path,1)
 worker_type=shim(tmp_path,"from forensic_assistant.detections.execution_observations import Population\nimport time\noriginal=Population.rows\ndef slow(self,family):\n if self.hostname=='slow':\n  while True:self.check();time.sleep(.01)\n yield from original(self,family)\nPopulation.rows=slow")
 before=path.read_bytes();progress=[]
 with worker_type(dict(case_path=str(path),scope=scope,_transaction_view=True)) as worker:
  worker.progress=progress.append;view=worker.call('chat_init',seconds=5)['evidence_state']
  timer=threading.Timer(.2,worker.cancel);timer.start()
  try:
   with pytest.raises(ConversationWorkerError) as error:worker.call('discover_execution_behaviors',{'hostname':'slow'},seconds=None)
  finally:timer.join()
  assert error.value.code=='ANALYST_CANCELLED' and error.value.view==view
  with pytest.raises(ConversationWorkerError) as error:worker.call('discover_execution_behaviors',{'hostname':'slow'},seconds=.2)
  assert error.value.code=='OPERATION_DEADLINE'
  assert worker.call('discover_execution_behaviors',{},seconds=5)['result']['records']
  assert progress[-1]['processed']==4
 assert path.read_bytes()==before


def test_grouping_preserves_literal_arguments_and_budget(tmp_path):
 from forensic_assistant.detections.execution import discover,wire
 path,sid,scope,*_=populate(tmp_path,0);db=connect(path)
 for i,arg in enumerate(['one.txt','two.txt','one.txt']):event(db,50+i,4688,SECURITY,'Security',{'CommandLine':'tool.exe '+arg})
 db.commit();db.close()
 with readonly(path) as db:
  r=discover(db,sid,START,END,families=('evtx',),limit=10,byte_limit=7000)
  assert len(wire(r))<=7000 and r['next_offset']
  seen=[];offset=0
  while True:
   page=discover(db,sid,START,END,families=('evtx',),limit=1,offset=offset)
   seen.extend(page['records'])
   if page['next_offset'] is None:break
   offset=page['next_offset']
  assert len({x['group_id'] for x in seen})==5
  assert sorted(x['count'] for x in seen)==[1,1,1,1,2]

def test_discover_inspect_verify_pivot_and_challenge(tmp_path):
 from forensic_assistant.conversational_ai.service import Session,notebook
 from forensic_assistant.conversational_ai.provider import ScriptedProvider
 from test_conversational_ai import reply,call,last
 path,sid,scope,*_=populate(tmp_path,10);seen={}
 def inspect(messages):
  row=last(messages)['records'][0];seen['eid']=row['evidence_id'];seen['field']=next(f for f in row['original_fields'] if f['name']=='command')
  return reply(calls=[call('show_evidence',{'evidence_id':seen['eid']})])
 def verify(messages):
  f=seen['field'];return reply(calls=[call('verify_observation',dict(evidence_id=seen['eid'],field=f['field'],value_json=json.dumps(f['value'])))])
 def pivot(messages):
  assert last(messages)['verified'];return reply(calls=[call('search_evidence',dict(artifact='browser',limit=2))])
 provider=ScriptedProvider([reply(calls=[call('discover_execution_behaviors',{})]),inspect,verify,pivot,
  reply(calls=[call('search_evidence',dict(artifact='registry',limit=2))]),
  reply(calls=[call('note',dict(kind='hypothesis',text='Administration is a plausible alternative; no malicious verdict is established.',status='active'))]),
  reply('The verified command is an observation. Browser and Registry pivots did not establish a causal chain; coverage remains limited.')])
 before=path.read_bytes();session=Session(scope,provider,lambda _:True)
 try:result=session.submit('Review unusual execution and alternatives without known indicators.')
 finally:session.close()
 assert len(result['verified_observations'])==1 and result['notes'][0]['unverified']
 saved=notebook(str(path)+'.conversations',session.journal.id)
 assert saved==notebook(str(path)+'.conversations',session.journal.id)
 assert path.read_bytes()==before and session.worker.process.poll() is not None

def test_powershell_sysmon_provider_qualification_and_large_fields(tmp_path):
 path,sid,scope,*_=populate(tmp_path,0);db=connect(path)
 valid=event(db,90,1,'Microsoft-Windows-Sysmon','Microsoft-Windows-Sysmon/Operational',{'Image':'agent.exe','CommandLine':'agent.exe /routine'})
 script=event(db,91,4104,'Microsoft-Windows-PowerShell','Microsoft-Windows-PowerShell/Operational',{'ScriptBlockText':'Write-Output "hello";'+'x'*40000})
 wrong=event(db,92,4688,'NotSecurity','Application',{'CommandLine':'wrong.exe'})
 db.commit();db.close()
 with readonly(path) as db:
  tools=Tools(db,scope);r=tools.execute('discover_execution_behaviors',{'artifact':'evtx','limit':10})
  assert r['coverage']['feature_analysis_truncated_records']==1
  assert wrong not in {x['evidence_id'] for x in r['records']}
  assert any(x['kind']=='script_content' and x['analysis_truncated'] for x in r['records'])
  assert any(x['event_id']==1 and x['count']==1 for x in r['statistics']['event_populations'])
  f=next(f for x in r['records'] if x['evidence_id']==script for f in x['original_fields'] if f['name']=='command')
  assert f['truncated']
  with pytest.raises(ValueError):tools.execute('verify_observation',dict(evidence_id=script,field=f['field'],value_json=json.dumps(f['value'])))

def test_host_conflict_excluded_and_host_filter_narrows(tmp_path):
 path,sid,scope,rare,remote,missing=populate(tmp_path,0);db=connect(path)
 db.execute('UPDATE evidence_records SET hostname=? WHERE evidence_id=?',('other-host',rare));db.commit();db.close()
 with readonly(path) as db:
  tools=Tools(db,scope);r=tools.execute('discover_execution_behaviors',{'artifact':'evtx'})
  assert r['coverage']['families']['evtx']['excluded_host_conflict']==1
  assert rare not in {x['evidence_id'] for x in r['records']}
  r=tools.execute('discover_execution_behaviors',{'artifact':'evtx','hostname':'not-lab'})
  assert r['coverage']['records_processed']==0 and not r['records']
  assert r['coverage']['families']['evtx']['excluded_host_filter']==2

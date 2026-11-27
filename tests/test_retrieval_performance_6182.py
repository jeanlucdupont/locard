"""Identity/range plan regressions with independent retained-row comparisons."""
import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path
import pytest
from retrieval_performance_fixtures import population,START,END
from test_security_discovery import readonly
from forensic_assistant.retrieval.evidence import EvidenceQueries,get_evidence
from forensic_assistant.database import sources
from forensic_assistant.conversational_ai.contracts import authorize,FAMILIES,catalog
from forensic_assistant.conversational_ai.tools import Tools,leaves

@pytest.fixture(autouse=True)
def private(tmp_path,monkeypatch):monkeypatch.setenv('LOCALAPPDATA',str(tmp_path))

@pytest.fixture
def case(tmp_path):return population(tmp_path,keys=1000,mft=100)

@pytest.mark.parametrize('exact',[False,True])
@pytest.mark.parametrize('filter', ['registry_key','registry_key_contains','value_name'])
def test_registry_selection_and_pages(case,exact,filter):
 path,sid,key,val,mid=case
 with closing(readonly(path)) as db:
  value=r'Software\Synthetic\00000999' if filter!='value_name' else db.execute('SELECT value_name FROM registry_values WHERE evidence_id=?',(val,)).fetchone()[0]
  selected=EvidenceQueries(db).search(artifact='registry',source_scope=sid,start=START,end=END,exact_count=exact,limit=2,**{filter:value})
  if filter!='value_name':assert {r['id'] for r in selected.records}=={'K00000999','V00000999'}
  else:
   expected={r[0] for r in db.execute('SELECT evidence_id FROM registry_values WHERE value_name=? COLLATE NOCASE',(value,))}
   assert {r['id'] for r in selected.records}<=expected
   assert selected.as_dict().get('has_more',selected.total>2 if exact else False)
  repeated=EvidenceQueries(db).search(artifact='registry',source_scope=sid,start=START,end=END,exact_count=exact,limit=2,**{filter:value})
  assert selected.as_dict()==repeated.as_dict()
  for record in selected.records:assert record==get_evidence(db,record['id'])


def test_identity_plan_and_independent_verification(case):
 path,sid,key,val,mid=case;before=path.read_bytes()
 scope=authorize(path,[sid],START,END,list(FAMILIES),'openai','scripted');profile=[]
 with closing(readonly(path)) as db:
  tools=Tools(db,scope,profile=profile);original=tools.original(val,known=False)
  for pointer in ('/detail/value_name','/detail/value_data'):
   index=next(i for i,(p,v) in enumerate(leaves(original)) if p==pointer)
   page=tools.page(original,index,1);f=page['fields'][0]
   result=tools.execute('verify_observation',dict(evidence_id=val,field=pointer,value_json=json.dumps(f['value'])))
   assert result['verified']
   with pytest.raises(ValueError):tools.execute('verify_observation',dict(evidence_id=val,field=pointer,value_json='"not-original"'))
  plans=[r[3] for phase in profile for r in phase.get('plan',[])]
  assert not any('SCAN evidence_timestamps' in r for r in plans)
  assert any('SEARCH evidence_timestamps' in r for r in plans)
  assert any(p['phase']=='retained_record_hydration' for p in profile)
 assert path.read_bytes()==before


def test_mft_timestamps_and_paths(case):
 path,sid,key,val,mid=case
 with closing(readonly(path)) as db:
  result=EvidenceQueries(db).search(artifact='mft',timeline=True,source_scope=sid,start=START,end=END,limit=10000)
  expected=[tuple(r) for r in db.execute("SELECT t.evidence_id,t.slot,t.timestamp_utc FROM evidence_timestamps t JOIN evidence_records e USING(evidence_id) WHERE e.source_type='mft' AND t.timestamp_utc>=? AND t.timestamp_utc<=? ORDER BY t.timestamp_utc,t.evidence_id,t.slot",('2010-01-01T00:00:00.000000000Z','2030-01-01T00:00:00.000000000Z'))]
  assert [(r['id'],r['timestamp']['slot'],r['timestamp_utc']) for r in result.records]==expected
  page=EvidenceQueries(db).search(artifact='mft',timeline=True,source_scope=sid,start=START,end=END,limit=3,offset=2,exact_count=False)
  assert [(r['id'],r['timestamp']['slot'],r['timestamp_utc']) for r in page.records]==expected[2:5]


def test_diagnostic_and_authorization(case):
 path,sid,key,val,mid=case;before=path.read_bytes()
 args=[sys.executable,'scripts/benchmark_forensic_retrieval.py','--db',str(path),'--source',sid,'--start',START,'--end',END,'--operation','show','--evidence-id',val,'--repeat','2','--diagnostics','--json']
 p=subprocess.run(args,capture_output=True,text=True,timeout=30);assert p.returncode==0,p.stderr
 r=json.loads(p.stdout);assert r['reports'][0]['result_sha256']==r['reports'][1]['result_sha256']
 assert r['reports'][0]['read_view']==r['reports'][1]['read_view']
 assert all(x['profile'] for x in r['reports']);assert path.read_bytes()==before


def test_catalog_display_has_execution_discovery():
 from forensic_assistant.conversational_ai import cli
 import inspect
 assert "for t in catalog()" in inspect.getsource(cli)
 assert 'discover_execution_behaviors' in {t['function']['name'] for t in catalog()}

def test_pinned_timeline_hydrates_once_without_losing_slots(case):
 path,sid,key,val,mid=case
 with closing(readonly(path)) as db:
  db.execute('BEGIN');calls=[]
  def hydrate(eid):calls.append(eid);return get_evidence(db,eid)
  result=EvidenceQueries(db,hydrate=hydrate).search(evidence_id=mid,artifact='mft',timeline=True,source_scope=sid,start=START,end=END,limit=20,exact_count=False)
  assert len(result.records)>1
  assert calls==[mid]
  assert len({r['timeline_id'] for r in result.records})==len(result.records)

def test_diagnostic_verification_uses_retained_scalar(case):
 path,sid,key,val,mid=case
 with closing(readonly(path)) as db:value=get_evidence(db,val)['detail']['value_name']
 args=[sys.executable,'scripts/benchmark_forensic_retrieval.py','--db',str(path),'--source',sid,'--start',START,'--end',END,'--operation','verify','--evidence-id',val,'--field','/detail/value_name','--value-json',json.dumps(value),'--repeat','2','--json']
 p=subprocess.run(args,capture_output=True,text=True,timeout=30);assert p.returncode==0,p.stderr
 r=json.loads(p.stdout);assert all(x['verified'] is True for x in r['reports'])
 assert r['reports'][0]['result_sha256']==r['reports'][1]['result_sha256']


def test_derived_only_cte_can_be_candidate_restricted(case):
 from forensic_assistant.artifacts.userassist import timeline_cte
 path,sid,key,val,mid=case
 with closing(readonly(path)) as db:
  sql=timeline_cte(db,include_persisted=False,candidate_sql='SELECT evidence_id FROM evidence_records WHERE evidence_id=?')
  assert db.execute(sql+'SELECT count(*) FROM locard_times',(key,)).fetchone()[0]==0

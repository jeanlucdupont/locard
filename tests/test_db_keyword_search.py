import importlib.util
import json
import sqlite3
from pathlib import Path
import pytest
spec=importlib.util.spec_from_file_location('keyword',Path(__file__).parents[1]/'scripts/db_keyword_search.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

def test_literal_unicode_dynamic_readonly_single_traversal(tmp_path):
 p=tmp_path/'case.db';db=sqlite3.connect(p)
 db.execute('CREATE TABLE "odd table"(id INTEGER PRIMARY KEY,"odd column" TEXT,b BLOB)')
 db.executemany('INSERT INTO "odd table" VALUES(?,?,?)',[(1,'Straße 100% _literal',b'needle'),(2,'STRASSE 100% _literal',b'x'),(3,'other',None)])
 db.commit();db.close();before=p.read_bytes();db=module.open_readonly(p);sql=[];db.set_trace_callback(sql.append)
 try:
  r=module.search(db,['strasse','100%','_literal','needle'],examples=1)
  assert r['complete'];table=r['tables'][0]
  assert [m['count'] for m in table['matches']]==[2,2,2]
  assert table['binary_cells']==2 and all(len(m['examples'])==1 for m in table['matches'])
  assert len([s for s in sql if s.startswith('SELECT "id"')])==1
  with pytest.raises(sqlite3.DatabaseError):db.execute('DELETE FROM "odd table"')
 finally:db.close()
 assert p.read_bytes()==before

def test_cancel_reports_incomplete(tmp_path):
 p=tmp_path/'case.db';db=sqlite3.connect(p);db.execute('CREATE TABLE x(t TEXT)');db.executemany('INSERT INTO x VALUES(?)',[('needle',)]*20);db.commit();db.close()
 calls=0
 def cancel():
  nonlocal calls
  calls+=1
  if calls>5:raise KeyboardInterrupt()
 db=module.open_readonly(p)
 try:r=module.search(db,['needle'],check=cancel)
 finally:db.close()
 assert not r['complete'] and not r['counts_complete'] and r['tables'][0]['matches'][0]['count']==4

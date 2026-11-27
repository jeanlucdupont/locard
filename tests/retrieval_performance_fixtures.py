"""Scalable synthetic retained tables; never reads a case outside tmp_path."""
import json
from forensic_assistant.database.db import connect,register_source
from forensic_assistant.database import sources
from forensic_assistant.artifacts.ingest import ingest_artifact
from v2_fixtures import registry_file,mft_file

START='2010-01-01T00:00:00Z';END='2030-01-01T00:00:00Z'
def population(folder,keys=2000,mft=1000):
 path=folder/'case.db';db=connect(path)
 sid=sources.create(db,name='Synthetic',hostname='lab',volume_root='C:')
 for kind,p in [('registry',registry_file(folder/'hive',dirty=True)),('mft',mft_file(folder/'mft'))]:
  ingest_artifact(db,p,kind)
 for row in db.execute('SELECT DISTINCT file_sha256 FROM evidence_records').fetchall():sources.assign(db,sid,[row[0]],reason='Synthetic')
 key=db.execute('SELECT evidence_id FROM registry_keys ORDER BY evidence_id LIMIT 1').fetchone()[0]
 val=db.execute('SELECT evidence_id,key_id FROM registry_values LIMIT 1').fetchone();key=val['key_id'];val=val[0]
 mid=db.execute('SELECT evidence_id FROM mft_records LIMIT 1').fetchone()[0]
 # Stable generated identities are synthetic, not claims about real parser output.
 db.execute('CREATE TEMP TABLE seq(n INTEGER PRIMARY KEY)')
 db.executemany('INSERT INTO seq VALUES(?)',((n,) for n in range(max(keys,mft))))
 def clone(table,seed,identity,overrides,limit):
  cols=[r[1] for r in db.execute('PRAGMA table_info('+table+')')]
  expr=[overrides.get(c,'v.'+c) for c in cols]
  db.execute('INSERT INTO '+table+'('+','.join(cols)+') SELECT '+','.join(expr)+' FROM '+table+' v CROSS JOIN seq s WHERE v.evidence_id=? AND s.n<?',(seed,limit))
 for seed,prefix,n,typ in ((key,'K',keys,'registry_key'),(val,'V',keys,'registry_value'),(mid,'M',mft,'mft')):
  clone('evidence_records',seed,prefix,{'evidence_id':"'"+prefix+"'||printf('%08d',s.n)"},n)
 clone('registry_keys',key,'K',{'evidence_id':"'K'||printf('%08d',s.n)",'key_path':"'Software\\Synthetic\\'||printf('%08d',s.n)",'parent_id':'NULL'},keys)
 clone('registry_values',val,'V',{'evidence_id':"'V'||printf('%08d',s.n)",'key_id':"'K'||printf('%08d',s.n)"},keys)
 clone('evidence_timestamps',key,'K',{'evidence_id':"'K'||printf('%08d',s.n)"},keys)
 for table in ('mft_records','mft_names','evidence_timestamps','evidence_objects'):
  clone(table,mid,'M',{'evidence_id':"'M'||printf('%08d',s.n)"},mft)
 db.commit();db.close();return path,sid,key,val,mid

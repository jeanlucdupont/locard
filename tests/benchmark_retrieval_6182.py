"""Developer-only synthetic before/after benchmark; baseline is current Git HEAD."""
import hashlib,json,subprocess,sys,time,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]));sys.path.insert(0,str(Path(__file__).parent))
from retrieval_performance_fixtures import population,START,END
from test_security_discovery import readonly
from forensic_assistant.retrieval import evidence
from forensic_assistant.artifacts import userassist

def baseline(module,path):
 obj=types.ModuleType(module);obj.__package__=module.rsplit('.',1)[0]
 exec(subprocess.check_output(['git','show','HEAD:'+path],text=True),obj.__dict__);return obj

def run(folder,keys=200000,mft=100000):
 folder=folder.resolve();folder.mkdir(exist_ok=True)
 if (folder/'identity.json').exists():path,sid,key,val,mid=json.loads((folder/'identity.json').read_text());path=Path(path)
 else:
  path,sid,key,val,mid=population(folder,keys,mft);(folder/'identity.json').write_text(json.dumps([str(path),sid,key,val,mid]))
 old=baseline('forensic_assistant.retrieval.baseline','forensic_assistant/retrieval/evidence.py')
 oldua=baseline('forensic_assistant.artifacts.baseline','forensic_assistant/artifacts/userassist.py')
 # Controlled selective paths and a populated narrow timestamp window.
 import sqlite3
 setup=sqlite3.connect(path)
 setup.execute("UPDATE evidence_objects SET original='\\Synthetic\\'||evidence_id||'.dat',normalized='\\synthetic\\'||lower(evidence_id)||'.dat',basename=lower(evidence_id)||'.dat',path_kind='volume_relative' WHERE evidence_id GLOB 'M[0-9]*'")
 setup.execute("UPDATE evidence_timestamps SET timestamp_utc='2026-01-01T00:00:10.000000000Z' WHERE evidence_id GLOB 'M[0-9]*' AND evidence_id>=?",(f'M{mft-10:08d}',))
 setup.commit();setup.close()
 current=userassist.timeline_cte;output={};db=readonly(path);db.execute("BEGIN")
 queries=dict(identity=dict(evidence_id=val,artifact='registry'),key=dict(registry_key=rf'Software\Synthetic\{keys-1:08d}',artifact='registry'),substring=dict(registry_key_contains=f'{keys-1:08d}',artifact='registry'),path=dict(artifact='mft',path=rf'C:\Synthetic\M{mft-1:08d}.dat',start='2026-01-01T00:00:00Z',end='2026-01-01T00:00:20Z'),timeline=dict(artifact='mft',timeline=True,start='2026-01-01T00:00:00Z',end='2026-01-01T00:00:20Z'))
 try:
  for version,service,cte in [('before',old,oldua.timeline_cte),('after',evidence,current)]:
   userassist.timeline_cte=cte;output[version]={}
   for name,q in queries.items():
    repeats=[]
    for _ in range(2):
     profile=[];t=time.perf_counter();r=service.EvidenceQueries(db,profile=profile).search(**(dict(start=START,end=END)|q),source_scope=sid,exact_count=False)
     repeats.append(time.perf_counter()-t)
    result=r.as_dict();encoded=json.dumps(result,sort_keys=True,default=str).encode()
    output[version][name]=dict(seconds=repeats,result_sha256=hashlib.sha256(encoded).hexdigest(),profile=profile)
    print(version,name,repeats,flush=True)
  assert all(output['before'][name]['result_sha256']==output['after'][name]['result_sha256'] for name in queries)
  output['rows']={t:db.execute('SELECT count(*) FROM '+t).fetchone()[0] for t in ('registry_keys','registry_values','mft_records','evidence_timestamps')}
  output['database_bytes']=path.stat().st_size
 finally:userassist.timeline_cte=current;db.close()
 (folder/'results.json').write_text(json.dumps(output,indent=2));print(json.dumps(output['rows']),output['database_bytes'])
if __name__=='__main__':run(Path(sys.argv[1]))

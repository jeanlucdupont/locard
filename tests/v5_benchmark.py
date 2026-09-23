"""Manual synthetic benchmark: python tests/v5_benchmark.py OUTPUT_ROOT CLAIMS.

Creates only generated MFT records and derived outputs in the named scratch root.
No analyst evidence, model, network, or committed binary fixture is used.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import platform
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from v2_fixtures import mft_record
from forensic_assistant.database.db import connect
from forensic_assistant.artifacts.ingest import ingest_artifact
from forensic_assistant.reporting.bundle import generate,inspect,validate
from forensic_assistant.reporting.collect import ReportWorker
from forensic_assistant.reporting.model import Limits

def peak(handle=None):
    if sys.platform!='win32': return None
    class Counters(ctypes.Structure):
        _fields_=[('cb',ctypes.c_ulong),('PageFaultCount',ctypes.c_ulong)]+[(name,ctypes.c_size_t) for name in ('PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage','QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage')]
    info=Counters();info.cb=ctypes.sizeof(info)
    kernel=ctypes.WinDLL('kernel32');kernel.GetCurrentProcess.restype=ctypes.c_void_p
    function=ctypes.WinDLL('psapi').GetProcessMemoryInfo
    function.argtypes=[ctypes.c_void_p,ctypes.POINTER(Counters),ctypes.c_ulong]
    if not function(handle if handle is not None else kernel.GetCurrentProcess(),ctypes.byref(info),info.cb):return None
    return info.PeakWorkingSetSize

def main():
    root=Path(sys.argv[1]).resolve();root.mkdir(parents=True,exist_ok=False)
    count=int(sys.argv[2]);case=root/'synthetic.db';source=root/'synthetic.mft'
    source.write_bytes(b''.join(mft_record(number=i,names=('.',) if i==5 else ('synthetic-%04d.exe'%i,),directory=i==5) for i in range(625)))
    db=connect(case)
    result=ingest_artifact(db,source,'mft',hostname='synthetic.example',volume_root='C:')
    if result['status']!='complete':raise RuntimeError(result)
    ids=[r[0] for r in db.execute('SELECT evidence_id FROM evidence_records ORDER BY evidence_id')]
    timestamp_count=db.execute('SELECT count(*) FROM evidence_timestamps').fetchone()[0];db.close()
    peaks=[];original=ReportWorker.close
    def close(worker):
        if worker.process and worker.process.poll() is None:
            measured=None
            if sys.platform=='win32':
                kernel=ctypes.WinDLL('kernel32');kernel.OpenProcess.restype=ctypes.c_void_p
                kernel.OpenProcess.argtypes=[ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong]
                kernel.CloseHandle.argtypes=[ctypes.c_void_p]
                handle=kernel.OpenProcess(0x0400|0x0010,False,worker.worker_pid)
                try: measured=peak(handle) if handle else None
                finally:
                    if handle:kernel.CloseHandle(handle)
            if measured is not None:peaks.append(measured)
        original(worker)
    ReportWorker.close=close
    out=root/'report';start=time.perf_counter()
    generated=generate(case,out,evidence_ids=ids,limits=Limits(claims=count,timeline=5000,seconds=600))
    generation=time.perf_counter()-start
    start=time.perf_counter();checked=validate(out,case=case);validation=time.perf_counter()-start
    if checked['evidence_grounding']!='PASS':raise RuntimeError(checked)
    report,_=inspect(out)
    start=time.perf_counter()
    for path in out.iterdir():hashlib.sha256(path.read_bytes()).hexdigest()
    hashing=time.perf_counter()-start
    summary=dict(python=platform.python_version(),platform=platform.system(),
        evidence_records=len(ids),timeline_candidates=timestamp_count,claims=len(report['data']['claims']),
        timeline_entries=len(report['data']['timeline']),generation_seconds=round(generation,3),
        grounding_validation_seconds=round(validation,3),hashing_seconds=round(hashing,4),
        json_bytes=(out/'report.json').stat().st_size,html_bytes=(out/'report.html').stat().st_size,
        parent_peak_working_set_bytes=peak(),worker_peak_working_set_bytes=max(peaks,default=None),
        status=generated['status'],grounding=checked['evidence_grounding'])
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()

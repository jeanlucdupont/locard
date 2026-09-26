"""Parser subprocess. Bounded staging, never executable evidence or shell commands."""
import importlib
import importlib.metadata
import json
import os
import sqlite3
import sys
from pathlib import Path
from forensic_assistant.database.db import connect,register_source,now
from forensic_assistant.database.artifacts import dump
from forensic_assistant.artifacts.storage import store

PARSERS={'mft':'dissect.ntfs','prefetch':'libscca-python','registry':'libregf-python'}
MAX_RECORD_BYTES=64*1024*1024
MAX_RECORDS=5_000_000


def run(kind,path,sha,stage_path,options,reader=None):
    module=importlib.import_module('forensic_assistant.artifacts.'+kind)
    version=importlib.metadata.version(PARSERS[kind]);db=connect(stage_path)
    inserted=errors=0
    try:
        with db:
            register_source(db,sha,Path(path).stat().st_size,path)
            run_id=db.execute('INSERT INTO ingestion_runs(source_file,started_utc,status) VALUES (?,?,?)',(path,now(),'running')).lastrowid
        stream=reader(path,sha,**options) if reader else module.parse(path,sha,**options)
        def error(message,locator):
            nonlocal errors
            errors+=1
            error_id=db.execute('INSERT INTO ingestion_errors(run_id,record_offset,stage,message) VALUES (?,?,?,?)',
                                (run_id,locator.get('offset'),'parse',message)).lastrowid
            db.execute('INSERT INTO artifact_errors VALUES (?,?)',(error_id,dump(locator)))
        try:
            for index,pack in enumerate(stream):
                if index>=MAX_RECORDS:raise ValueError('Parser record limit reached')
                if 'error' in pack:error(pack['error'],pack.get('locator',{}));continue
                if len(dump(pack).encode())>MAX_RECORD_BYTES:raise ValueError('Parsed record exceeds size limit')
                inserted+=store(db,pack,sha,path,PARSERS[kind],version)
                if index%500==0:db.commit()
        except Exception as exc:
            error(f'Iteration stopped: {type(exc).__name__}: {exc}',{})
        if kind=='mft':module.reconstruct_paths(db,sha)
        if kind=='registry':
            from forensic_assistant.artifacts.registry_extractors import extract_all
            extract_all(db)
        db.commit()
        return {'records':inserted,'errors':errors,'parser_version':version}
    finally:db.close()


def limit_memory():
    """Fail closed if OS memory containment cannot be established."""
    if sys.platform=='win32':
        import ctypes
        from ctypes import wintypes as w
        class Basic(ctypes.Structure):
            _fields_=[('process_time',ctypes.c_int64),('job_time',ctypes.c_int64),('flags',w.DWORD),
                      ('min_working',ctypes.c_size_t),('max_working',ctypes.c_size_t),('active',w.DWORD),
                      ('affinity',ctypes.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
        class IO(ctypes.Structure):_fields_=[(n,ctypes.c_uint64) for n in ('read','write','other','read_bytes','write_bytes','other_bytes')]
        class Extended(ctypes.Structure):
            _fields_=[('basic',Basic),('io',IO),('process_memory',ctypes.c_size_t),('job_memory',ctypes.c_size_t),
                      ('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.CreateJobObjectW.restype=w.HANDLE
        kernel.SetInformationJobObject.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD]
        kernel.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE]
        kernel.GetCurrentProcess.restype=w.HANDLE
        handle=kernel.CreateJobObjectW(None,None);limits=Extended()
        limits.basic.flags=0x100|0x2000;limits.process_memory=2*1024**3
        if not handle or not kernel.SetInformationJobObject(handle,9,ctypes.byref(limits),ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(handle,kernel.GetCurrentProcess()):
            raise OSError(ctypes.get_last_error(),'Cannot establish parser worker memory limit')
        return handle  # Held for worker lifetime; OS closes it on exit.
    import resource
    resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))


if __name__=='__main__':
    try:
        guard=limit_memory()
        if len(sys.argv)>6 and sys.argv[6]=='--parent-guard':
            ready=Path(sys.argv[4]+'.ready')
            temporary=Path(str(ready)+'.tmp')
            temporary.write_text(json.dumps({'worker_pid':os.getpid()}),encoding='ascii')
            os.replace(temporary,ready)
            if sys.stdin.buffer.readline(16)!=b'go\n':raise ValueError('Parent containment handshake cancelled')
        print(json.dumps(run(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],json.loads(sys.argv[5]))))
    except Exception as exc:
        print(json.dumps({'error':f'{type(exc).__name__}: {exc}'}));sys.exit(1)

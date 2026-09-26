"""Parent-owned Windows job: terminate the real worker, not only venv launcher."""
import os
import sys

class CleanupError(RuntimeError):
    """Do not return to a shell when process cleanup cannot be confirmed."""

class WorkerJob:
    def __init__(self,pid):
        self.handle=None
        if sys.platform!='win32': return
        if type(pid) is not int or pid<=0 or pid==os.getpid(): raise ValueError('Invalid worker PID')
        import ctypes
        from ctypes import wintypes as w
        class Basic(ctypes.Structure):
            _fields_=[('process_time',ctypes.c_int64),('job_time',ctypes.c_int64),('flags',w.DWORD),
                      ('min_working',ctypes.c_size_t),('max_working',ctypes.c_size_t),('active',w.DWORD),
                      ('affinity',ctypes.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
        class IO(ctypes.Structure):
            _fields_=[(name,ctypes.c_uint64) for name in ('read','write','other','read_bytes','write_bytes','other_bytes')]
        class Extended(ctypes.Structure):
            _fields_=[('basic',Basic),('io',IO),('process_memory',ctypes.c_size_t),('job_memory',ctypes.c_size_t),
                      ('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.CreateJobObjectW.restype=w.HANDLE
        kernel.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];kernel.OpenProcess.restype=w.HANDLE
        kernel.SetInformationJobObject.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD]
        kernel.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE]
        kernel.CloseHandle.argtypes=[w.HANDLE]
        kernel.TerminateJobObject.argtypes=[w.HANDLE,w.UINT]
        self.kernel=kernel
        handle=kernel.CreateJobObjectW(None,None)
        process=kernel.OpenProcess(0x0100|0x0200|0x0001|0x1000,False,pid)
        limits=Extended();limits.basic.flags=0x2000
        try:
            if not handle or not process or not kernel.SetInformationJobObject(handle,9,ctypes.byref(limits),ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(handle,process):
                raise OSError(ctypes.get_last_error(),'Cannot contain actual forensic worker')
            self.handle=handle;handle=None
        finally:
            if process:kernel.CloseHandle(process)
            if handle:kernel.CloseHandle(handle)

    def close(self):
        if self.handle:
            handle=self.handle;self.handle=None
            terminated=self.kernel.TerminateJobObject(handle,1)
            closed=self.kernel.CloseHandle(handle)
            if not terminated or not closed:
                raise CleanupError('Cannot confirm worker job cleanup')

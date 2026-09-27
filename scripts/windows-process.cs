// Windows process boundary shared by the bootstrapper and thin launcher.
// No shell interpretation. Assign a suspended child to a kill-on-close job first.
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Locard.Setup {
    public sealed class CleanupException : IOException {
        public CleanupException(string message) : base(message) {}
    }
    public sealed class Result {
        public int ExitCode;
        public string Output;
    }
    public static class NativeProcess {
        [StructLayout(LayoutKind.Sequential)] struct Security {
            public int length; public IntPtr descriptor; public int inherit;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup {
            public int cb; public string reserved, desktop, title;
            public int x,y,width,height,charsX,charsY,fill,flags;
            public short show,reservedSize; public IntPtr reservedBytes,input,output,error;
        }
        [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {
            public IntPtr process,thread; public int pid,tid;
        }
        [StructLayout(LayoutKind.Sequential)] struct BasicLimit {
            public long processTime,jobTime; public uint flags;
            public UIntPtr min,max; public uint active; public UIntPtr affinity;
            public uint priority,scheduling;
        }
        [StructLayout(LayoutKind.Sequential)] struct IoCounters {
            public ulong read,write,other,readBytes,writeBytes,otherBytes;
        }
        [StructLayout(LayoutKind.Sequential)] struct Limits {
            public BasicLimit basic; public IoCounters io;
            public UIntPtr processMemory,jobMemory,peakProcess,peakJob;
        }
        [StructLayout(LayoutKind.Sequential)] struct Accounting {
            public long user,kernel,periodUser,periodKernel;
            public uint faults,total,active,terminated;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern IntPtr CreateJobObject(IntPtr attributes,string name);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref Limits value,int size);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out Accounting value,int size,IntPtr returned);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int kind);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern bool CreateProcess(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref Startup startup,out ProcessInfo info);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern IntPtr CreateFile(string path,uint access,uint share,ref Security security,uint creation,uint flags,IntPtr template);

        public static string Quote(string value) {
            if (value==null) value="";
            if (value.IndexOf('\0')>=0) throw new ArgumentException("NUL in process argument");
            StringBuilder output=new StringBuilder("\""); int slashes=0;
            foreach(char c in value) {
                if(c=='\\') { slashes++; continue; }
                if(c=='"') output.Append('\\',slashes*2+1);
                else output.Append('\\',slashes);
                output.Append(c); slashes=0;
            }
            output.Append('\\',slashes*2); output.Append('"'); return output.ToString();
        }
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetConsoleCtrlHandler(ControlHandler handler,bool add);
        delegate bool ControlHandler(uint signal);
        static void Check(bool ok) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        public static Result Run(string executable,string[] arguments,string cwd,int timeoutSeconds,bool capture,Func<bool> stopping,bool cancelOnSignal) {
            string temporary=capture ? Path.GetTempFileName() : null;
            try { return RunContained(executable,arguments,cwd,timeoutSeconds,capture,stopping,cancelOnSignal,temporary); }
            finally { if(temporary!=null) File.Delete(temporary); }
        }
        static Result RunContained(string executable,string[] arguments,string cwd,int timeoutSeconds,bool capture,Func<bool> stopping,bool cancelOnSignal,string temporary) {
            IntPtr job=IntPtr.Zero, file=IntPtr.Zero; ProcessInfo info=new ProcessInfo();
            bool assigned=false; int cancelled=0;
            ControlHandler cancel=delegate(uint signal) {
                if(signal>1) return false;
                if(cancelOnSignal) Interlocked.Exchange(ref cancelled,1); return true;
            };
            uint code=1;
            try {
                job=CreateJobObject(IntPtr.Zero,null); Check(job!=IntPtr.Zero);
                Limits limits=new Limits(); limits.basic.flags=0x2000;
                Check(SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(typeof(Limits))));
                Startup startup=new Startup(); startup.cb=Marshal.SizeOf(typeof(Startup));
                startup.flags=0x100; startup.input=GetStdHandle(-10);
                startup.output=GetStdHandle(-11); startup.error=GetStdHandle(-12);
                if(capture) {
                    Security security=new Security(); security.length=Marshal.SizeOf(typeof(Security)); security.inherit=1;
                    file=CreateFile(temporary,0x40000000,7,ref security,2,0x80,IntPtr.Zero);
                    Check(file!=new IntPtr(-1)); startup.output=file; startup.error=file;
                }
                StringBuilder command=new StringBuilder(Quote(executable));
                foreach(string arg in arguments) command.Append(" ").Append(Quote(arg));
                Check(SetConsoleCtrlHandler(cancel,true));
                Check(CreateProcess(executable,command,IntPtr.Zero,IntPtr.Zero,true,4,IntPtr.Zero,cwd,ref startup,out info));
                Check(AssignProcessToJobObject(job,info.process)); assigned=true;
                Check(ResumeThread(info.thread)!=0xffffffff);
                Stopwatch clock=Stopwatch.StartNew();
                while(true) {
                    if((cancelOnSignal && stopping()) || Interlocked.CompareExchange(ref cancelled,0,0)!=0) { code=130; break; }
                    uint wait=WaitForSingleObject(info.process,100);
                    if(wait==0) { Check(GetExitCodeProcess(info.process,out code)); break; }
                    Check(wait==258);
                    if(timeoutSeconds>0 && clock.Elapsed.TotalSeconds>=timeoutSeconds) { code=124; break; }
                    if(capture && new FileInfo(temporary).Length>1048576) throw new IOException("Subprocess diagnostic output exceeded 1 MiB");
                }
            } finally {
                SetConsoleCtrlHandler(cancel,false);
                GC.KeepAlive(cancel);
                bool cleaned=true;
                if(info.process!=IntPtr.Zero && !assigned) {
                    cleaned=TerminateProcess(info.process,130) && WaitForSingleObject(info.process,5000)==0;
                }
                if(job!=IntPtr.Zero) {
                    cleaned=TerminateJobObject(job,130) && cleaned;
                    Accounting accounting=new Accounting(); Stopwatch limit=Stopwatch.StartNew();
                    do {
                        if(!QueryInformationJobObject(job,1,out accounting,Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero)) { cleaned=false; break; }
                        if(accounting.active==0) break;
                        Thread.Sleep(10);
                    } while(limit.ElapsedMilliseconds<5000);
                    cleaned=(accounting.active==0) && cleaned;
                    cleaned=CloseHandle(job) && cleaned;
                }
                if(info.thread!=IntPtr.Zero) CloseHandle(info.thread);
                if(info.process!=IntPtr.Zero) CloseHandle(info.process);
                if(file!=IntPtr.Zero && file!=new IntPtr(-1)) CloseHandle(file);
                if(!cleaned) throw new CleanupException("Cannot confirm installer/launcher child-process cleanup");
            }
            {
                string output="";
                if(temporary!=null && new FileInfo(temporary).Length>1048576)
                    throw new IOException("Subprocess diagnostic output exceeded 1 MiB");
                if(temporary!=null) using(var stream=new FileStream(temporary,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))
                    using(var reader=new StreamReader(stream,Encoding.UTF8)) output=reader.ReadToEnd();
                return new Result { ExitCode=unchecked((int)code), Output=output };
            }
        }
    }
}

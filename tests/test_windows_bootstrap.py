"""Windows-only bootstrap boundaries; generated executables contain no case data."""
import base64
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import pytest

ROOT=Path(__file__).resolve().parents[1]
POWERSHELL=shutil.which('powershell')
SHELLS=[p for p in (POWERSHELL,shutil.which('pwsh')) if p]
pytestmark=pytest.mark.skipif(os.name!='nt' or not POWERSHELL,reason='Windows PowerShell integration gate')


def literal(value):return "'"+str(value).replace("'","''")+"'"


@pytest.mark.parametrize('release,valid',[('42.7',True),('42.8',True),('0.8.1',True),('42',False),('42.7.invalid',False)])
def test_project_version_syntax(tmp_path,release,valid):
    (tmp_path/'pyproject.toml').write_text('[project]\nversion = "'+release+'"\nrequires-python = ">=3.11"\n')
    result=policy('(Get-LocardProject '+literal(tmp_path)+').Version')
    assert (result.returncode==0)==valid
    if valid:assert result.stdout.decode().strip()==release


def command(shell,code,**kwargs):
    encoded=base64.b64encode(code.encode('utf-16le')).decode()
    return subprocess.run([shell,'-NoProfile','-NonInteractive','-EncodedCommand',encoded],capture_output=True,timeout=40,**kwargs)


@pytest.fixture(scope='module')
def stub(tmp_path_factory):
    directory=tmp_path_factory.mktemp('native-stub');exe=directory/'stub.exe'
    source='''using System; using System.Text; using System.IO; using System.Diagnostics;
class Stub { static int Main(string[] args) {
 if(args.Length>0 && args[0]=="--tree") {
  File.WriteAllText(args[1],Process.GetCurrentProcess().Id.ToString());
  Process p=Process.Start(Process.GetCurrentProcess().MainModule.FileName,"--child "+args[2]);
  System.Threading.Thread.Sleep(60000); return 0;
 }
 if(args.Length>0 && args[0]=="--child") { File.WriteAllText(args[1],Process.GetCurrentProcess().Id.ToString()); System.Threading.Thread.Sleep(60000);return 0; }
 if(args.Length>0 && args[0]=="--exit") return Int32.Parse(args[1]);
 if(args.Length>0 && args[0]=="--large") { Console.Write(new string('x',2097152)); return 0; }
 Console.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(Environment.CurrentDirectory)));
 foreach(string arg in args) Console.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(arg)));
 return 0;
} }'''
    result=command(POWERSHELL,'Add-Type -TypeDefinition '+literal(source)+' -OutputAssembly '+literal(exe)+' -OutputType ConsoleApplication')
    assert result.returncode==0,result.stderr
    return exe


@pytest.fixture
def checkout(tmp_path,stub):
    root=tmp_path/'checkout spaces café';(root/'.venv'/'Scripts').mkdir(parents=True)
    shutil.copy2(stub,root/'.venv'/'Scripts'/'locard.exe')
    shutil.copy2(ROOT/'locard.ps1',root/'locard.ps1')
    shutil.copytree(ROOT/'scripts',root/'scripts')
    return root


@pytest.mark.parametrize('shell',SHELLS,ids=lambda p:Path(p).stem)
def test_launcher_arguments_and_caller_directory(checkout,tmp_path,shell):
    values=['space word','café Ω','','embedded"quote', 'C:\\trailing\\','space \\"quoted"\\','--db','case.db']
    result=command(shell,'$forward=@('+','.join(map(literal,values))+'); & '+literal(checkout/'locard.ps1')+' @forward; exit $LASTEXITCODE',cwd=tmp_path)
    assert result.returncode==0,result.stderr
    lines=result.stdout.decode().splitlines()
    assert [base64.b64decode(v).decode() for v in lines]==[str(tmp_path),*values]


@pytest.mark.parametrize('shell',SHELLS,ids=lambda p:Path(p).stem)
def test_launcher_exit_code(checkout,shell):
    result=command(shell,'& '+literal(checkout/'locard.ps1')+" '--exit' '37'; exit $LASTEXITCODE")
    assert result.returncode==37,result.stderr


@pytest.mark.parametrize('missing',['environment','executable'])
def test_launcher_missing_environment(checkout,missing):
    (checkout/'.venv'/'Scripts'/'locard.exe').unlink()
    if missing=='environment':(checkout/'.venv'/'Scripts').rmdir();(checkout/'.venv').rmdir()
    result=command(POWERSHELL,'& '+literal(checkout/'locard.ps1'))
    assert result.returncode!=0 and b'install.ps1' in result.stderr


def alive(pid):
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.restype=ctypes.c_void_p
    handle=kernel.OpenProcess(0x100000,False,pid)
    if not handle:return False
    kernel.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint]
    kernel.CloseHandle.argtypes=[ctypes.c_void_p]
    try:return kernel.WaitForSingleObject(handle,0)==258
    finally:kernel.CloseHandle(handle)


@pytest.mark.parametrize('shell',SHELLS,ids=lambda p:Path(p).stem)
def test_timeout_kills_child_and_descendant(tmp_path,stub,shell):
    parent=tmp_path/'parent.pid';child=tmp_path/'child.pid'
    # Stub native arguments are intentionally space-free for its child-spawning code.
    code="$ErrorActionPreference='Stop'; . "+literal(ROOT/'scripts/windows-process.ps1')+'; $r=Invoke-LocardProcess -Executable '+literal(stub)+' -Arguments @('+','.join(map(literal,['--tree',parent,child]))+') -TimeoutSeconds 3 -Capture; Write-Output $r.ExitCode'
    result=command(shell,code)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()==b'124'
    assert parent.exists() and child.exists()
    assert not alive(int(parent.read_text())) and not alive(int(child.read_text()))


@pytest.mark.parametrize('shell',SHELLS,ids=lambda p:Path(p).stem)
@pytest.mark.parametrize('termination',['parent-death','ctrl-c'])
def test_cancel_tree(tmp_path,stub,shell,termination):
    parent=tmp_path/'parent.pid';child=tmp_path/'child.pid';outcome=tmp_path/'outcome.txt'
    code="$ErrorActionPreference='Stop'; . "+literal(ROOT/'scripts/windows-process.ps1')+'; '
    if termination=='ctrl-c':
        # A private hidden console: never signal pytest or the analyst. Clear the
        # inherited ignore-Ctrl+C flag for this synthetic console before sending.
        timer='''using System; using System.Threading; using System.Runtime.InteropServices;
public static class CancelTest { static Timer timer;
[DllImport("kernel32.dll")] static extern bool GenerateConsoleCtrlEvent(uint kind,uint group);
[DllImport("kernel32.dll")] static extern bool SetConsoleCtrlHandler(IntPtr handler,bool add);
public static void Start() { SetConsoleCtrlHandler(IntPtr.Zero,false); timer=new Timer(delegate(object state) { GenerateConsoleCtrlEvent(0,0); },null,4000,Timeout.Infinite); } }'''
        code+='Add-Type -TypeDefinition '+literal(timer)+'; [CancelTest]::Start(); '
    code+='$r=Invoke-LocardProcess -Executable '+literal(stub)+' -Arguments @('+','.join(map(literal,['--tree',parent,child]))+') -Capture; [IO.File]::WriteAllText('+literal(outcome)+',[string]$r.ExitCode); exit $r.ExitCode'
    encoded=base64.b64encode(code.encode('utf-16le')).decode()
    startup=subprocess.STARTUPINFO();startup.dwFlags|=subprocess.STARTF_USESHOWWINDOW;startup.wShowWindow=0
    process=subprocess.Popen([shell,'-NoProfile','-NonInteractive','-EncodedCommand',encoded],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                             creationflags=subprocess.CREATE_NEW_CONSOLE,startupinfo=startup)
    try:
        until=time.monotonic()+15
        while not child.exists() and time.monotonic()<until:time.sleep(.05)
        assert parent.exists() and child.exists()
        if termination=='parent-death':process.kill()
        process.wait(timeout=15)
        until=time.monotonic()+5
        while any(alive(int(p.read_text())) for p in (parent,child)) and time.monotonic()<until:time.sleep(.05)
        assert not any(alive(int(p.read_text())) for p in (parent,child))
        if termination=='ctrl-c':
            assert process.returncode!=0
            if outcome.exists():assert int(outcome.read_text()) in (130,-1073741510)  # STATUS_CONTROL_C_EXIT
    finally:
        if process.poll() is None:process.kill();process.wait()


def policy(code,shell=POWERSHELL):
    return command(shell,"$ErrorActionPreference='Stop'; . "+literal(ROOT/'scripts/install-support.ps1')+'; '+code)


def info(version='3.12.14',**kwargs):
    return dict(version=version,executable=r'C:\Python\python.exe',implementation='cpython',platform='win32',
                bits=64,machine='AMD64',release='final',free_threaded=False,prefix='base',base='base',editable=False,**kwargs)


def psjson(value):return '('+literal(json.dumps(value))+' | ConvertFrom-Json)'


@pytest.mark.parametrize('version,requirement,expected',[
    ('3.10.9','>=3.11',False),('3.11.0','>=3.11',True),('3.12.14','>=3.11',True),
    ('3.15.0','>=3.11',True),('3.15.0','>=3.11,<3.15',False),('3.12.0','>=3.11,!=3.12.0',False),
])
def test_python_constraints(version,requirement,expected):
    result=policy('Test-LocardVersion '+literal(version)+' '+literal(requirement))
    assert result.returncode==0,result.stderr
    assert result.stdout.strip().lower()==str(expected).lower().encode()


@pytest.mark.parametrize('versions,expected',[
    (['3.11.9'],'3.11.9'),(['3.14.1','3.12.4','3.12.14'],'3.12.14'),(['3.11.9','3.13.3'],'3.13.3'),
])
def test_deterministic_candidate_choice(versions,expected):
    mapping={v:info(v) for v in versions}
    code='$mapping='+psjson(mapping)+'; function Get-LocardCandidates { '+','.join(map(literal,versions))+' }; function Get-LocardPython($p) { $mapping.$p }; (Select-LocardPython ">=3.11").version'
    result=policy(code)
    assert result.returncode==0,result.stderr
    assert result.stdout.decode().splitlines()[-1]==expected


@pytest.mark.parametrize('change',[{'version':'3.10.9'},{'bits':32},{'machine':'ARM64'},{'implementation':'pypy'},{'free_threaded':True},{'release':'candidate'}])
def test_incompatible_runtime_rejected(change):
    probe=info();probe.update(change)
    result=policy('Test-LocardPython '+psjson(probe)+' ">=3.11"')
    assert result.returncode==0 and result.stdout.strip()==b'False',result.stderr


@pytest.mark.parametrize('mode',['none','old','broken'])
def test_no_usable_python_actionable(mode):
    candidates="'candidate'" if mode!='none' else '@()'
    probe="throw 'broken interpreter'" if mode=='broken' else psjson(info('3.10.9'))
    code='function Get-LocardCandidates { '+candidates+' }; function Get-LocardPython { '+probe+' }; Select-LocardPython ">=3.11"'
    result=policy(code)
    assert result.returncode!=0 and b'No usable Python' in result.stderr


@pytest.mark.parametrize('listing',[
    ' -V:3.12 *        C:\\Python312\\python.exe',
    'No installed Pythons found!',
])
def test_launcher_listing_without_launching_runtime(listing):
    code=r'''function Get-Command { param($Name,$CommandType,[switch]$All,$ErrorAction)
if($Name -eq 'py') { [pscustomobject]@{Source='py.exe'} } }
function Invoke-LocardProcess { '''+psjson(dict(ExitCode=0,Output=listing))+''' }
@(Get-LocardCandidates) | ConvertTo-Json -Compress'''
    result=policy(code)
    assert result.returncode==0,result.stderr
    if 'python.exe' in listing:assert b'Python312' in result.stdout
    else:assert b'did not list an installed runtime' in result.stdout


@pytest.mark.parametrize('kind',['absent','healthy','old','incomplete','file','wrong-prefix','no-pip'])
def test_environment_policy(tmp_path,kind):
    env=tmp_path/'.venv'
    if kind=='file':env.write_text('preserve')
    elif kind!='absent':
        (env/'Scripts').mkdir(parents=True)
        if kind!='incomplete':(env/'pyvenv.cfg').write_text('test');(env/'Scripts/python.exe').write_text('test')
    probe=info('3.10.9' if kind=='old' else '3.12.14');probe['prefix']=str(env) if kind!='wrong-prefix' else 'elsewhere'
    code='function Get-LocardPython { '+psjson(probe)+' }; function Invoke-LocardProcess { '+psjson(dict(ExitCode=1 if kind=='no-pip' else 0))+' }; $r=Get-LocardEnvironment '+literal(tmp_path)+' ([pscustomobject]@{Requires=">=3.11"}); if($r){"healthy"}else{"absent"}'
    result=policy(code)
    assert (result.returncode==0)==(kind in ('absent','healthy')),result.stderr
    assert env.exists()==(kind!='absent')
    if kind=='file':assert env.read_text()=='preserve'


@pytest.mark.parametrize('failure',['none','preparation','dependencies','install','verification','version'])
def test_install_stages_and_success_message(tmp_path,failure):
    shutil.copy2(ROOT/'pyproject.toml',tmp_path/'pyproject.toml');(tmp_path/'.venv').mkdir()
    probe=info();probe['prefix']=str(tmp_path/'.venv')
    code='$script:failure='+literal(failure)+'; function Get-LocardEnvironment { '+psjson(probe)+''' }
function Invoke-LocardProcess {
param($Executable,$Arguments,$TimeoutSeconds,[switch]$Capture)
$code=0; $output=''
if ($Arguments -contains 'wheel') {
 $index=[array]::IndexOf($Arguments,'--wheel-dir'); [IO.File]::WriteAllText((Join-Path $Arguments[$index+1] 'locard_forensics-test.whl'),'test')
 if($script:failure -eq 'preparation'){$code=2}
}
if($Arguments -contains '--find-links' -and $script:failure -eq 'dependencies'){$code=3}
if($Arguments -contains '--force-reinstall' -and $script:failure -eq 'install'){$code=4}
if($Arguments -contains 'check' -and $script:failure -eq 'verification'){$code=5}
if($Arguments -contains '--version') {
 $output='Locard '+(Get-LocardProject '''+literal(tmp_path)+''').Version
 if($script:failure -eq 'version'){$output='wrong version'}
}
[pscustomobject]@{ExitCode=$code;Output=$output}
}
Invoke-LocardInstall -Root '''+literal(tmp_path)
    result=policy(code)
    assert (result.returncode==0)==(failure=='none'),result.stderr
    assert (b'installed successfully' in result.stdout)==(failure=='none')
    if failure=='none':assert result.stdout.decode().strip().endswith("locard.ps1'")
    assert (tmp_path/'.venv').is_dir()


def test_editable_installation_requires_explicit_choice(tmp_path):
    shutil.copy2(ROOT/'pyproject.toml',tmp_path/'pyproject.toml');probe=info();probe['editable']=True
    code='function Get-LocardEnvironment { '+psjson(probe)+' }; function Read-Host { "n" }; Invoke-LocardInstall -Root '+literal(tmp_path)
    result=policy(code)
    assert result.returncode!=0 and b'Editable installation retained' in result.stderr
    assert not (tmp_path/'.locard-install.lock').exists()


def test_python_path_fallback_excludes_store_alias():
    code=r'''function Get-Command { param($Name,$CommandType,[switch]$All,$ErrorAction)
if($Name -eq 'python') { [pscustomobject]@{Source='C:\Python312\python.exe'} }
if($Name -eq 'python3') { [pscustomobject]@{Source='C:\Users\Example\AppData\Local\Microsoft\WindowsApps\python3.exe'} }
}
@(Get-LocardCandidates) | ConvertTo-Json -Compress'''
    result=policy(code)
    assert result.returncode==0,result.stderr
    assert json.loads(result.stdout)==r'C:\Python312\python.exe'


def test_venv_creation_failure_retains_partial_environment(tmp_path):
    shutil.copy2(ROOT/'pyproject.toml',tmp_path/'pyproject.toml')
    code='function Get-LocardEnvironment { $null }; function Select-LocardPython { '+psjson(info())+''' }
function Invoke-LocardProcess { param($Executable,$Arguments)
 [IO.Directory]::CreateDirectory($Arguments[-1]) | Out-Null
 [pscustomobject]@{ExitCode=23;Output='creation failed'}
}
Invoke-LocardInstall -Root '''+literal(tmp_path)
    result=policy(code)
    assert result.returncode!=0 and b'virtual environment creation' in result.stderr
    assert (tmp_path/'.venv').is_dir() and b'installed successfully' not in result.stdout


def test_foreign_lock_file_is_preserved(tmp_path):
    shutil.copy2(ROOT/'pyproject.toml',tmp_path/'pyproject.toml');(tmp_path/'.venv').mkdir()
    marker=tmp_path/'.locard-install.lock';marker.write_text('existing marker')
    code='function Get-LocardEnvironment { '+psjson(info())+''' }
function Invoke-LocardProcess { throw 'stop before installation' }
Invoke-LocardInstall -Root '''+literal(tmp_path)
    result=policy(code)
    assert result.returncode!=0 and marker.read_text()=='existing marker'


@pytest.mark.parametrize('shell',SHELLS,ids=lambda p:Path(p).stem)
def test_discovery_cleanup_failure_never_falls_back(shell):
    code='. '+literal(ROOT/'scripts/windows-process.ps1')+''';
function Get-LocardCandidates { 'first','second' }
function Get-LocardPython($path) {
 if($path -eq 'first') { throw [Locard.Setup.CleanupException]::new('Cannot confirm installer/launcher child-process cleanup') }
 Write-Host 'UNSAFE FALLBACK'; throw 'should not reach this'
}
Select-LocardPython '>=3.11' '''
    result=policy(code,shell)
    assert result.returncode!=0 and b'child-process cleanup' in result.stderr
    assert b'UNSAFE FALLBACK' not in result.stdout


def test_completed_probe_output_is_bounded(stub):
    code='. '+literal(ROOT/'scripts/windows-process.ps1')+'; Invoke-LocardProcess -Executable '+literal(stub)+" -Arguments @('--large') -Capture"
    result=policy(code)
    assert result.returncode!=0 and b'exceeded 1 MiB' in result.stderr
    assert len(result.stdout)<1000

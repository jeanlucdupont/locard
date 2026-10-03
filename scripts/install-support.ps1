# Discovery and installation policy. Dot-sourcing defines functions only.
function Assert-LocardPath {
    param([string]$Path)
    $item = [IO.Path]::GetFullPath($Path)
    while ($item) {
        if (Test-Path -LiteralPath $item) {
            if ((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Redirected installation path is not supported: $item"
            }
        }
        $item = [IO.Path]::GetDirectoryName($item)
    }
}

function Get-LocardProject {
    param([string]$Root)
    $text = Get-Content -LiteralPath (Join-Path $Root 'pyproject.toml') -Raw -Encoding UTF8
    $section = [regex]::Match($text, '(?ms)^\[project\]\s*\r?\n(.*?)(?=^\[|\z)').Groups[1].Value
    $version = [regex]::Match($section, '(?m)^version\s*=\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"\s*$').Groups[1].Value
    $requires = [regex]::Match($section, '(?m)^requires-python\s*=\s*"([^"]+)"\s*$').Groups[1].Value
    if (-not $version -or -not $requires) { throw 'Cannot read project version/Python requirement. Use manual installation.' }
    # Fail closed on future unsupported syntax; validate again with Python tomllib later.
    foreach ($part in $requires.Split(',')) {
        if ($part.Trim() -notmatch '^(>=|<=|==|!=|>|<)\s*\d+\.\d+(\.\d+)?$') {
            throw "Unsupported Python constraint syntax: $requires. Use manual installation."
        }
    }
    [pscustomobject]@{ Version=$version; Requires=$requires }
}

function Test-LocardVersion {
    param([string]$Version, [string]$Requirement)
    $actual = [version]$Version
    foreach ($part in $Requirement.Split(',')) {
        if ($part.Trim() -notmatch '^(>=|<=|==|!=|>|<)\s*(\d+\.\d+(?:\.\d+)?)$') { throw 'Unsupported Python constraint' }
        $op=$Matches[1]; $text=$Matches[2]
        if ($text.Split('.').Count -eq 2) { $text += '.0' }
        $comparison=$actual.CompareTo([version]$text)
        $ok=switch ($op) { '>=' {$comparison -ge 0} '<=' {$comparison -le 0} '>' {$comparison -gt 0} '<' {$comparison -lt 0} '==' {$comparison -eq 0} '!=' {$comparison -ne 0} }
        if (-not $ok) { return $false }
    }
    return $true
}

function Get-LocardPython {
    param([string]$Executable)
    $probe = @'
import sys, sysconfig, struct, platform, json, importlib.metadata as m
try:
 d=m.distribution('locard-forensics'); version=d.version; direct=json.loads(d.read_text('direct_url.json') or '{}')
except m.PackageNotFoundError:
 version=None; direct={}
print(json.dumps(dict(executable=sys.executable, version='.'.join(map(str,sys.version_info[:3])),
 implementation=sys.implementation.name, platform=sys.platform, bits=struct.calcsize('P')*8,
 machine=platform.machine(), release=sys.version_info.releaselevel, free_threaded=bool(sysconfig.get_config_var('Py_GIL_DISABLED')),
 prefix=sys.prefix, base=sys.base_prefix, locard=version, editable=bool(direct.get('dir_info',{}).get('editable')))))
'@
    $result=Invoke-LocardProcess -Executable $Executable -Arguments @('-I','-c',$probe) -TimeoutSeconds 15 -Capture
    if ($result.ExitCode -eq 130 -or $result.ExitCode -eq -1073741510) { throw [OperationCanceledException]::new('Python discovery cancelled') }
    if ($result.ExitCode -ne 0) { throw "Python probe failed ($($result.ExitCode)): $($result.Output.Trim())" }
    $info=$result.Output | ConvertFrom-Json -ErrorAction Stop
    if (-not $info.executable -or -not $info.version) { throw 'Invalid Python probe response' }
    return $info
}

function Test-LocardPython {
    param($Info, [string]$Requirement)
    return ($Info.implementation -eq 'cpython' -and $Info.platform -eq 'win32' -and $Info.bits -eq 64 -and
        $Info.machine -in @('AMD64','x86_64') -and $Info.release -eq 'final' -and -not $Info.free_threaded -and
        (Test-LocardVersion $Info.version $Requirement))
}

function Get-LocardCandidates {
    $paths=[Collections.Generic.List[string]]::new()
    $launcher=Get-Command py -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($launcher) {
        $listing=Invoke-LocardProcess -Executable $launcher.Source -Arguments @('-0p') -TimeoutSeconds 15 -Capture
        if ($listing.ExitCode -eq 130 -or $listing.ExitCode -eq -1073741510) { throw [OperationCanceledException]::new('Python discovery cancelled') }
        foreach ($line in $listing.Output.Split("`n")) {
            if ($line -match '\s((?:[A-Za-z]:\\|\\\\).+?\.exe)\s*$') { $paths.Add($Matches[1].Trim()) }
        }
        if ($paths.Count -eq 0) { Write-Host 'Python launcher found, but it did not list an installed runtime.' }
    }
    foreach ($name in @('python','python3')) {
        foreach ($command in @(Get-Command $name -CommandType Application -All -ErrorAction SilentlyContinue)) {
            if ($command.Source -notmatch '\\Microsoft\\WindowsApps\\') { $paths.Add($command.Source) }
        }
    }
    return $paths | Select-Object -Unique
}

function Select-LocardPython {
    param([string]$Requirement, [string]$Explicit)
    $valid=@()
    $paths=if ($Explicit) { @([IO.Path]::GetFullPath($Explicit)) } else { @(Get-LocardCandidates) }
    foreach ($path in $paths) {
        try {
            $info=Get-LocardPython $path
            if (Test-LocardPython $info $Requirement) {
                Write-Host "Compatible Python $($info.version): $($info.executable)"
                $valid += $info
            } else { Write-Host "Rejected Python $($info.version) ($($info.implementation), $($info.bits)-bit, $($info.machine)); requires standard AMD64 CPython $Requirement." }
        } catch [OperationCanceledException] { throw }
        catch {
            # A broken interpreter can be skipped; unconfirmed cleanup cannot.
            $probeFailure=$_.Exception
            while ($probeFailure) {
                if ($probeFailure.GetType().FullName -in @('Locard.Setup.CleanupException','System.Management.Automation.PipelineStoppedException')) { throw }
                $probeFailure=$probeFailure.InnerException
            }
            Write-Host "Unusable Python candidate '$path': $($_.Exception.Message)"
        }
    }
    if (-not $valid.Count) { throw "No usable Python found. Install standard 64-bit AMD64 CPython $Requirement, then rerun install.ps1. Python 3.12 is validated. You may use -Python 'full path to python.exe'. No Python was installed automatically." }
    return $valid | Sort-Object @{Expression={if ($_.version -match '^3\.12\.') {0} else {1}}}, @{Expression={[version]$_.version};Descending=$true}, executable | Select-Object -First 1
}

function Get-LocardEnvironment {
    param([string]$Root, $Project)
    $environment=Join-Path $Root '.venv'
    Assert-LocardPath $environment
    if (-not (Test-Path -LiteralPath $environment)) { return $null }
    if (-not (Test-Path -LiteralPath $environment -PathType Container)) { throw '.venv exists but is not a directory. It has been preserved.' }
    $python=Join-Path $environment 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath (Join-Path $environment 'pyvenv.cfg') -PathType Leaf) -or -not (Test-Path -LiteralPath $python -PathType Leaf)) {
        throw 'Incomplete .venv. It has been preserved. Inspect it and manually move it aside before reinstalling.'
    }
    Assert-LocardPath $python
    $info=Get-LocardPython $python
    if (-not (Test-LocardPython $info $Project.Requires) -or $info.prefix -eq $info.base -or
        [IO.Path]::GetFullPath($info.prefix).TrimEnd('\') -ne [IO.Path]::GetFullPath($environment).TrimEnd('\')) {
        throw 'Incompatible or invalid .venv. It has been preserved. Use manual recovery; it will not be rebuilt automatically.'
    }
    $pip=Invoke-LocardProcess -Executable $python -Arguments @('-I','-m','pip','--version') -TimeoutSeconds 30 -Capture
    if ($pip.ExitCode -ne 0) { throw 'The existing .venv has no working pip. It has been preserved; repair it manually or move it aside.' }
    return $info
}

function Invoke-LocardInstall {
    param([string]$Root, [string]$Python, [switch]$ReplaceEditable)
    $stage='project validation'; $scratch=$null; $lock=$null
    try {
        Assert-LocardPath $Root
        $project=Get-LocardProject $Root
        Write-Host "Locard Setup - Python requirement: $($project.Requires)"
        $stage='environment validation'
        $info=Get-LocardEnvironment $Root $project
        if ($info) { Write-Host ('Reusing .venv; installed Locard: ' + $(if ($info.locard) {$info.locard} else {'not installed'})) }
        if ($info -and $Python) { throw '-Python is only used when .venv is absent. The existing environment was preserved.' }
        if ($info -and $info.editable -and -not $ReplaceEditable) {
            if ((Read-Host 'An editable developer installation exists. Replace it with a normal installation? [y/N]') -notin @('y','yes')) {
                throw 'Editable installation retained. Use the developer workflow, or explicitly pass -ReplaceEditable.'
            }
        }
        if (-not $info) { $info=Select-LocardPython $project.Requires $Python }
        Write-Host "Using Python $($info.version): $($info.executable)"
        # Exclusive open, not stale lock-file contents, controls concurrent installers.
        $lockPath=Join-Path $Root '.locard-install.lock'
        Assert-LocardPath $lockPath
        $lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $environment=Join-Path $Root '.venv'
        if (-not (Test-Path -LiteralPath $environment)) {
            $stage='virtual environment creation'
            Write-Host 'Creating .venv.'
            $r=Invoke-LocardProcess -Executable $info.executable -Arguments @('-I','-m','venv',$environment)
            if ($r.ExitCode -ne 0) { throw "venv creation returned $($r.ExitCode). Any partial .venv is retained for inspection." }
        }
        $info=Get-LocardEnvironment $Root $project
        $pythonExe=Join-Path $environment 'Scripts\python.exe'
        $scratch=Join-Path ([IO.Path]::GetTempPath()) ('locard-install-'+[Guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($scratch) | Out-Null
        $stage='package metadata validation'
        $metadata=@'
import sys,tomllib,json
from pathlib import Path
p=tomllib.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))['project']
assert p['name']=='locard-forensics' and p['version']==sys.argv[3] and p['requires-python']==sys.argv[4]
assert p['scripts']['locard']=='forensic_assistant.cli:main'
Path(sys.argv[2]).write_text('\n'.join(p['dependencies'])+'\n',encoding='utf-8')
'@
        $requirements=Join-Path $scratch 'requirements.txt'
        $r=Invoke-LocardProcess -Executable $pythonExe -Arguments @('-I','-c',$metadata,(Join-Path $Root 'pyproject.toml'),$requirements,$project.Version,$project.Requires)
        if ($r.ExitCode -ne 0) { throw 'Project packaging metadata verification failed.' }
        Write-Host 'Preparing core packages. Pip may download packages/build requirements; no models or semantic extras are installed.'
        $stage='package preparation'
        $r=Invoke-LocardProcess -Executable $pythonExe -Arguments @('-I','-m','pip','--disable-pip-version-check','wheel','--only-binary=libscca-python,libregf-python,dissect.util','--wheel-dir',$scratch,$Root)
        if ($r.ExitCode -ne 0) { throw "Package preparation returned $($r.ExitCode). Check diagnostics, network access, and compatible native wheels. No installed packages have been replaced." }
        $wheels=@(Get-ChildItem -LiteralPath $scratch -Filter 'locard_forensics-*.whl')
        if ($wheels.Count -ne 1) { throw 'Expected exactly one Locard wheel' }
        $stage='core dependency installation'
        $r=Invoke-LocardProcess -Executable $pythonExe -Arguments @('-I','-m','pip','--disable-pip-version-check','install','--no-index','--find-links',$scratch,'-r',$requirements)
        if ($r.ExitCode -ne 0) { throw "Dependency installation returned $($r.ExitCode). The environment is retained; rerun or use manual recovery." }
        $stage='Locard installation'
        # Reinstall only Locard so same-version checkout changes are picked up after git pull.
        $r=Invoke-LocardProcess -Executable $pythonExe -Arguments @('-I','-m','pip','--disable-pip-version-check','install','--no-deps','--force-reinstall',$wheels[0].FullName)
        if ($r.ExitCode -ne 0) { throw "Locard installation returned $($r.ExitCode). The environment is retained; rerun or use manual recovery." }
        $stage='installation verification'
        $r=Invoke-LocardProcess -Executable $pythonExe -Arguments @('-I','-m','pip','--disable-pip-version-check','check')
        if ($r.ExitCode -ne 0) { throw 'Installed dependency consistency check failed.' }
        $verify=@'
import sys,importlib,importlib.metadata as m,json
from pathlib import Path
import forensic_assistant as f
assert f.__version__==sys.argv[1] and m.version('locard-forensics')==sys.argv[1]
assert Path(f.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
assert not json.loads(m.distribution('locard-forensics').read_text('direct_url.json') or '{}').get('dir_info',{}).get('editable')
for n in ('Evtx.Evtx','defusedxml','dissect.ntfs','pyscca','pyregf','forensic_assistant.artifacts.worker','forensic_assistant.investigation_ai.worker','forensic_assistant.reporting.worker'): importlib.import_module(n)
assert (Path(f.__file__).parent/'database'/'schema.sql').is_file()
'@
        $r=Invoke-LocardProcess -Executable $pythonExe -Arguments @('-I','-c',$verify,$project.Version) -TimeoutSeconds 60
        if ($r.ExitCode -ne 0) { throw 'Installed package, parser imports, or resources failed verification.' }
        $r=Invoke-LocardProcess -Executable (Join-Path $environment 'Scripts\locard.exe') -Arguments @('--version') -TimeoutSeconds 30 -Capture
        if ($r.ExitCode -ne 0 -or $r.Output.Trim() -ne "Locard $($project.Version)") { throw 'Installed locard.exe version verification failed.' }
    } catch {
        throw "Locard setup failed during ${stage}: $($_.Exception.Message)"
    } finally {
        if ($lock) { $lock.Dispose() }
        # Remove only this invocation's private packaging scratch, never .venv or cases.
        if ($scratch -and (Test-Path -LiteralPath $scratch)) {
            if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($scratch)).TrimEnd('\') -ne [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') -or [IO.Path]::GetFileName($scratch) -notmatch '^locard-install-[a-f0-9]{32}$') { throw 'Refusing cleanup outside owned temporary staging' }
            Assert-LocardPath $scratch
            Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction Stop
        }
    }
    $launch = '.\locard.ps1'
    if ([IO.Path]::GetFullPath((Get-Location).ProviderPath).TrimEnd('\') -ne [IO.Path]::GetFullPath($Root).TrimEnd('\')) {
        $launch = "& '" + (Join-Path $Root 'locard.ps1').Replace("'", "''") + "'"
    }
    Write-Host "`nLocard $($project.Version) installed successfully.`n`nStart Locard with:`n`n  $launch"
}

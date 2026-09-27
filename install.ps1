#requires -Version 5.1
param([string]$Python, [switch]$ReplaceEditable)
$ErrorActionPreference = 'Stop'
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This bootstrapper requires Windows. Use manual Python installation on other platforms.' }
    . (Join-Path $PSScriptRoot 'scripts\windows-process.ps1')
    . (Join-Path $PSScriptRoot 'scripts\install-support.ps1')
    Invoke-LocardInstall -Root $PSScriptRoot -Python $Python -ReplaceEditable:$ReplaceEditable
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}

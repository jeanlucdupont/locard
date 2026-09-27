#requires -Version 5.1
# Use this checkout's installation; preserve the caller's directory and arguments.
$ErrorActionPreference = 'Stop'
try {
    $executable = Join-Path $PSScriptRoot '.venv\Scripts\locard.exe'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw 'Locard has not been installed in this repository. Run install.ps1 first.'
    }
    . (Join-Path $PSScriptRoot 'scripts\windows-process.ps1')
    $result = Invoke-LocardProcess -Executable $executable -Arguments $args -Interactive
    exit $result.ExitCode
} catch {
    [Console]::Error.WriteLine('Locard launcher: ' + $_.Exception.Message)
    exit 1
}

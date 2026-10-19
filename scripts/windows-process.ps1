# Shared native invocation: no command-string evaluation or global environment changes.
$nativeSource = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows-process.cs'))
$hasher = [Security.Cryptography.SHA256]::Create()
try { $sourceHash = [BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($nativeSource))).Replace('-', '') }
finally { $hasher.Dispose() }
# Add-Type definitions cannot be replaced in a long-lived PowerShell process.
# Give each source revision its own namespace instead of reusing stale job code.
$script:LocardProcessNamespace = 'Locard.Setup.H' + $sourceHash
$script:LocardProcessType = ($script:LocardProcessNamespace + '.NativeProcess') -as [type]
if (-not $script:LocardProcessType) {
    Add-Type -TypeDefinition $nativeSource.Replace('namespace Locard.Setup {', ('namespace ' + $script:LocardProcessNamespace + ' {')) -ErrorAction Stop
    $script:LocardProcessType = ($script:LocardProcessNamespace + '.NativeProcess') -as [type]
}

function Invoke-LocardProcess {
    [CmdletBinding()]
    param([string]$Executable, [string[]]$Arguments = @(), [int]$TimeoutSeconds = 0, [switch]$Capture, [switch]$Interactive)
    $script:LocardProcessType::Run($Executable, $Arguments, (Get-Location).ProviderPath, $TimeoutSeconds, $Capture.IsPresent, [Func[bool]]{ $PSCmdlet.Stopping }, (-not $Interactive.IsPresent))
}

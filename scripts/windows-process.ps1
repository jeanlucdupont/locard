# Shared native invocation: no command-string evaluation or global environment changes.
if (-not ('Locard.Setup.NativeProcess' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'windows-process.cs') -ErrorAction Stop
}

function Invoke-LocardProcess {
    [CmdletBinding()]
    param([string]$Executable, [string[]]$Arguments = @(), [int]$TimeoutSeconds = 0, [switch]$Capture, [switch]$Interactive)
    [Locard.Setup.NativeProcess]::Run($Executable, $Arguments, (Get-Location).ProviderPath, $TimeoutSeconds, $Capture.IsPresent, [Func[bool]]{ $PSCmdlet.Stopping }, (-not $Interactive.IsPresent))
}

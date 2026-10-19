<#
.SYNOPSIS
    Runs the PowerSCAP test suite with the in-box Pester 3.4, under Windows PowerShell 5.1 (default) or PowerShell 7.
.PARAMETER Edition
    Desktop: Windows PowerShell 5.1, the shipping runtime. Core: PowerShell 7 (pwsh).
.EXAMPLE
    powershell -NoProfile -File build\Invoke-Tests.ps1 -ExcludeTag Admin,Slow,Online
.EXAMPLE
    powershell -NoProfile -File build\Invoke-Tests.ps1 -Edition Core -ExcludeTag Admin,Slow,Online
#>
param(
    [string[]]$Tag,
    [string[]]$ExcludeTag,
    [string]$Path,
    [ValidateSet('Desktop', 'Core')][string]$Edition = 'Desktop'
)

# Accept "A,B" as one argument (callers outside PowerShell can't pass arrays).
$Tag = @($Tag | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$ExcludeTag = @($ExcludeTag | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

$current = if ($PSVersionTable.PSEdition -eq 'Core') { 'Core' } else { 'Desktop' }
if ($current -ne $Edition) {
    # Run in the requested edition. STA: the GUI tests need a single-threaded apartment.
    $argsList = @('-NoProfile', '-NonInteractive', '-STA', '-File', $PSCommandPath, '-Edition', $Edition)
    if ($Tag) { $argsList += '-Tag'; $argsList += ($Tag -join ',') }
    if ($ExcludeTag) { $argsList += '-ExcludeTag'; $argsList += ($ExcludeTag -join ',') }
    if ($Path) { $argsList += '-Path'; $argsList += $Path }
    if ($Edition -eq 'Core') { & pwsh @argsList } else { & powershell.exe @argsList }
    exit $LASTEXITCODE
}

Import-Module Pester -MaximumVersion 3.99 -ErrorAction Stop
$repo = Split-Path $PSScriptRoot -Parent
if (-not $Path) { $Path = Join-Path $repo 'tests' }

$p = @{ Path = $Path; PassThru = $true }
if ($Tag) { $p.Tag = $Tag }
if ($ExcludeTag) { $p.ExcludeTag = $ExcludeTag }
$result = Invoke-Pester @p
exit $result.FailedCount

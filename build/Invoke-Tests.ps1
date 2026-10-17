<#
.SYNOPSIS
    Runs the PowerSCAP test suite under Windows PowerShell 5.1 with the in-box Pester 3.4.
.EXAMPLE
    powershell -NoProfile -File build\Invoke-Tests.ps1 -ExcludeTag Admin,Slow,Online
#>
param(
    [string[]]$Tag,
    [string[]]$ExcludeTag,
    [string]$Path
)

# Accept "A,B" as one argument (callers outside PowerShell can't pass arrays).
$Tag = @($Tag | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$ExcludeTag = @($ExcludeTag | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

if ($PSVersionTable.PSEdition -eq 'Core') {
    # Tests must run on the shipping runtime.
    $argsList = @('-NoProfile', '-NonInteractive', '-File', $PSCommandPath)
    if ($Tag) { $argsList += '-Tag'; $argsList += ($Tag -join ',') }
    if ($ExcludeTag) { $argsList += '-ExcludeTag'; $argsList += ($ExcludeTag -join ',') }
    if ($Path) { $argsList += '-Path'; $argsList += $Path }
    & powershell.exe @argsList
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

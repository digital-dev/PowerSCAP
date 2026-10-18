<#
.SYNOPSIS
    Compares PowerSCAP with SCC rule by rule: optionally runs SCC first, then scans the same benchmarks with PowerSCAP.
.DESCRIPTION
    With -RunScc, SCC's command-line scanner (cscc.exe) scans this machine with its own settings, writing to a folder
    under -OutputPath (cscc -u: the folder is used for this run only; SCC's options are not changed). PowerSCAP then
    scans, straight away, every benchmark SCC produced results for, using the cached content with the same benchmark id
    and version and the profile SCC used, so both tools see the same content and the same machine state. Without
    -RunScc, an existing SCC session is used.

    Run elevated: both scanners need administrator rights for a real comparison.
.EXAMPLE
    .\tools\Invoke-ParityRun.ps1 -RunScc
.EXAMPLE
    .\tools\Invoke-ParityRun.ps1 -SccSession "$env:USERPROFILE\SCC\Sessions\2026-10-15_210812"
#>
[CmdletBinding(DefaultParameterSetName = 'Session')]
param(
    [Parameter(ParameterSetName = 'Run', Mandatory)][switch]$RunScc,
    [Parameter(ParameterSetName = 'Run')][string]$SccPath = (Join-Path $env:ProgramFiles 'SCAP Compliance Checker 5.15\cscc.exe'),
    [Parameter(ParameterSetName = 'Session')][string]$SccSession,
    [string]$OutputPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\parity'),
    [string]$CacheRoot,
    [switch]$AllowUnelevated
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$module = Import-Module (Join-Path $repo 'src\PowerSCAP') -Force -PassThru
# A window that loaded an older engine keeps it (.NET cannot unload assemblies); stop before SCC spends minutes scanning.
if (& $module { $script:EngineStale }) {
    throw 'This PowerShell window is running an older PowerSCAP engine. Open a new elevated PowerShell window and run this again.'
}
$compare = Join-Path $PSScriptRoot 'Compare-XccdfResults.ps1'
$runDir = Join-Path $OutputPath (Get-Date -Format 'yyyyMMdd_HHmmss')
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and -not $AllowUnelevated) { throw 'Run this elevated: SCC and PowerSCAP both need administrator rights for a real comparison.' }

$cacheRootPath = if ($CacheRoot) { $CacheRoot } else { [PowerScap.Engine.Cache.ContentCache]::DefaultRoot() }
$cache = New-Object PowerScap.Engine.Cache.ContentCache($cacheRootPath, $null)
$cached = @($cache.List())

# 1. SCC results: a fresh run, or an existing session.
if ($RunScc) {
    if (-not (Test-Path -LiteralPath $SccPath)) { throw "cscc.exe not found at $SccPath. Pass -SccPath." }
    $sccHome = Split-Path $SccPath -Parent
    $sccRoot = Join-Path $runDir 'scc'
    New-Item -ItemType Directory -Path $sccRoot -Force | Out-Null

    # One cscc scan per benchmark PowerSCAP has cached, so a crash in SCC loses one benchmark, not the rest. Benchmarks
    # are switched with SCC's own commands (-da, then -eb) on its real options file, which is restored afterwards:
    # SCC refuses a separately written options file (-o) as "content modified since last options file was saved".
    [xml]$options = Get-Content -LiteralPath (Join-Path $sccHome 'options.xml') -Raw
    $wanted = @($options.SelectNodes('//content/benchmarkID') | ForEach-Object { $_.InnerText } | Select-Object -Unique | Where-Object {
            $id = $_
            $cached | Where-Object { $_.BenchmarkId -match ('_benchmark_' + [regex]::Escape($id) + '$') }
        })
    if ($wanted.Count -eq 0) { throw 'None of the benchmarks installed in SCC are in the PowerSCAP cache.' }

    $optionsFile = Join-Path $sccHome 'options.xml'
    $backup = Join-Path $runDir 'scc-options-backup.xml'
    Copy-Item -LiteralPath $optionsFile -Destination $backup
    $crashed = @(); $empty = @()
    try {
        foreach ($id in $wanted) {
            & $SccPath -da | Out-Null
            & $SccPath -eb $id | Out-Null
            $before = @(Get-ChildItem -LiteralPath $sccRoot -Recurse -Filter '*XCCDF-Results*.xml').Count
            $sw = [Diagnostics.Stopwatch]::StartNew()
            & $SccPath -u $sccRoot -q
            $code = $LASTEXITCODE
            $made = @(Get-ChildItem -LiteralPath $sccRoot -Recurse -Filter '*XCCDF-Results*.xml').Count - $before
            Write-Host ('SCC {0,-45} {1,5:N0}s  exit code {2}  results {3}' -f $id, $sw.Elapsed.TotalSeconds, $code, $made)
            if ($code -lt 0) { $crashed += $id } elseif ($made -eq 0) { $empty += $id }
        }
    }
    finally {
        # SCC's own options file goes back exactly as it was, whatever happened above.
        Copy-Item -LiteralPath $backup -Destination $optionsFile -Force
        Write-Host "Restored SCC's options file."
    }
    if ($crashed) { Write-Warning ('SCC crashed while scanning: ' + ($crashed -join ', ') + '. Those benchmarks may have no SCC results to compare.') }
    if ($empty) {
        Write-Warning ('SCC wrote no results for: ' + ($empty -join ', ') + '. Its reason is in the Logs folder of each session under ' + $sccRoot)
        Get-ChildItem -LiteralPath $sccRoot -Recurse -Filter '*Error_Log*.txt' | Select-String -Pattern 'ERROR' | Select-Object -First 3 | ForEach-Object { Write-Host ('  ' + $_.Line.Trim()) }
    }
}
else {
    if (-not $SccSession) { throw 'Pass -RunScc, or -SccSession with an existing SCC session folder.' }
    $sccRoot = $SccSession
}
$references = @(Get-ChildItem -LiteralPath $sccRoot -Recurse -Filter '*XCCDF-Results*.xml')
if ($references.Count -eq 0) { throw "No SCC XCCDF results found under $sccRoot." }

# 2. PowerSCAP on the same benchmarks, from the cache, with SCC's profile. Collectors are shared across benchmarks.
$collectors = [PowerScap.Engine.Oval.CollectorRegistry]::CreateDefault()
$psDir = Join-Path $runDir 'powerscap'
$all = foreach ($ref in $references) {
    [xml]$refXml = Get-Content -LiteralPath $ref.FullName -Raw
    $benchmark = $refXml.DocumentElement
    $benchmarkId = $benchmark.GetAttribute('id')
    $version = ($benchmark.ChildNodes | Where-Object { $_.LocalName -eq 'version' } | Select-Object -First 1).InnerText
    $refProfile = @($refXml.GetElementsByTagName('profile', 'http://checklists.nist.gov/xccdf/1.2'))[-1]
    $profileId = if ($refProfile) { $refProfile.GetAttribute('idref') } else { $null }
    $short = $benchmarkId -replace '^xccdf_.*?_benchmark_', ''

    # Same benchmark and version, so both tools evaluate identical content.
    $entry = $cached | Where-Object { $_.BenchmarkId -eq $benchmarkId -and $_.BenchmarkVersion -eq $version -and -not $_.Missing } |
        Sort-Object AddedUtc -Descending | Select-Object -First 1
    if (-not $entry) { Write-Warning "Skipping $short $version`: that version is not in the PowerSCAP cache."; continue }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $scan = Invoke-PowerScapScan -ContentPath $cache.PathOf($entry) -ProfileId $profileId -OutputPath $psDir -Formats Html -PassThru -NoHistory -AllowUnelevated:$AllowUnelevated -Collectors $collectors
    $rows = @(& $compare -Reference $ref.FullName -Actual $scan.Path 6>$null)
    foreach ($r in $rows) {
        [pscustomobject]@{ Benchmark = $short; Version = $version; RuleId = $r.RuleId; Scc = $r.Reference; PowerScap = $r.Actual; Match = $r.Match }
    }
    Write-Host ('{0,-45} {1,4} rules  {2,4} differ  {3,6:N1}s' -f $short, $rows.Count, @($rows | Where-Object { -not $_.Match }).Count, $sw.Elapsed.TotalSeconds)
}

# 3. Summary and details.
$csv = Join-Path $runDir 'parity.csv'
$all | Export-Csv -LiteralPath $csv -NoTypeInformation
$differ = @($all | Where-Object { -not $_.Match })
Write-Host ''
Write-Host ('{0} rules compared, {1} match, {2} differ' -f @($all).Count, (@($all).Count - $differ.Count), $differ.Count)
foreach ($d in $differ) { Write-Host ('  {0,-25} {1,-26} SCC={2,-14} PowerSCAP={3}' -f $d.Benchmark, ($d.RuleId -replace '^xccdf_.*?_rule_', ''), $d.Scc, $d.PowerScap) }
Write-Host "Details: $csv"
Write-Host "SCC results: $sccRoot"
Write-Host "PowerSCAP results: $psDir"

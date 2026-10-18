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

    # One cscc run per benchmark PowerSCAP has cached, each from a temporary copy of SCC's options with only that
    # benchmark enabled (cscc -o, and -dn so nothing is written back): a crash in SCC then loses one benchmark, not the rest.
    # Whitespace preserved: re-indenting turns empty elements into whitespace, which SCC's options schema rejects.
    $options = New-Object Xml.XmlDocument
    $options.PreserveWhitespace = $true
    $options.Load((Join-Path $sccHome 'options.xml'))
    # Every enable-able entry (OVAL-only content has no benchmarkID) is switched off except the benchmark being run.
    $contents = @($options.SelectNodes('//content') | Where-Object { $_.SelectSingleNode('enabled') })
    foreach ($c in $contents) {
        $fp = $c.SelectSingleNode('filepath')
        if ($fp -and $fp.InnerText -and -not [IO.Path]::IsPathRooted($fp.InnerText)) { $fp.InnerText = Join-Path $sccHome $fp.InnerText }
    }
    $wanted = @($contents | Where-Object { $_.SelectSingleNode('benchmarkID') } | Where-Object {
            $id = $_.SelectSingleNode('benchmarkID').InnerText
            $cached | Where-Object { $_.BenchmarkId -match ('_benchmark_' + [regex]::Escape($id) + '$') }
        } | ForEach-Object { $_.SelectSingleNode('benchmarkID').InnerText } | Select-Object -Unique)
    if ($wanted.Count -eq 0) { throw 'None of the benchmarks installed in SCC are in the PowerSCAP cache.' }

    $schemas = New-Object Xml.Schema.XmlSchemaSet
    [void]$schemas.Add($null, (Join-Path $sccHome 'Resources\Schemas\options.xsd'))
    $crashed = @()
    foreach ($id in $wanted) {
        foreach ($c in $contents) {
            $b = $c.SelectSingleNode('benchmarkID')
            $c.SelectSingleNode('enabled').InnerText = $(if ($b -and $b.InnerText -eq $id) { '1' } else { '0' })
        }
        $tmpOptions = Join-Path $runDir "scc-options-$id.xml"
        $writer = New-Object IO.StreamWriter($tmpOptions, $false, (New-Object Text.UTF8Encoding($false)))
        try { $options.Save($writer) } finally { $writer.Dispose() }
        # SCC replaces an options file that fails its schema with defaults (no content enabled): check first.
        $schemaErrors = New-Object 'System.Collections.Generic.List[string]'
        $settings = New-Object Xml.XmlReaderSettings
        $settings.ValidationType = 'Schema'
        $settings.Schemas = $schemas
        $settings.add_ValidationEventHandler({ param($s, $e) $schemaErrors.Add("line $($e.Exception.LineNumber): $($e.Message)") })
        $reader = [Xml.XmlReader]::Create($tmpOptions, $settings)
        try { while ($reader.Read()) { } } finally { $reader.Dispose() }
        if ($schemaErrors.Count -gt 0) { throw "The options file written for SCC fails SCC's schema: $($schemaErrors[0])" }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        & $SccPath -o $tmpOptions -u $sccRoot -q -dn
        $code = $LASTEXITCODE
        Write-Host ('SCC {0,-45} {1,5:N0}s  exit code {2}' -f $id, $sw.Elapsed.TotalSeconds, $code)
        if ($code -lt 0) { $crashed += $id }
        Remove-Item -LiteralPath $tmpOptions -ErrorAction SilentlyContinue
    }
    if ($crashed) { Write-Warning ('SCC crashed while scanning: ' + ($crashed -join ', ') + '. Those benchmarks may have no SCC results to compare.') }
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

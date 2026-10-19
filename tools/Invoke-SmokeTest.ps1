<#
.SYNOPSIS
    End-to-end smoke test on the machine it runs on: detect, download, scan, validate.
.DESCRIPTION
    Built for CI on GitHub's Windows Server runners, and usable on any machine (a Windows 10 VM, a server):
      1. Profiles the machine and finds the NCP benchmarks for what is installed. The operating system's must be one.
      2. Downloads them into a fresh cache (or, with -NoDownload, uses the cache as it is).
      3. Scans each with every output format.
      4. Validates the XCCDF results, OVAL results and ARF files against the official schemas.
    It fails when a scan fails, an output file is invalid, the operating system benchmark does not apply to the machine
    (its own platform checks rule it out), or more than -MaxErrorPercent of a benchmark's rules end in error.
    A Markdown summary goes to -SummaryPath ($env:GITHUB_STEP_SUMMARY in GitHub Actions).
.EXAMPLE
    powershell -NoProfile -File tools\Invoke-SmokeTest.ps1 -OutputPath C:\smoke
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputPath,
    [string]$CacheRoot = (Join-Path ([IO.Path]::GetTempPath()) ('powerscap-smoke-' + [guid]::NewGuid().ToString('N'))),
    [switch]$NoDownload,
    [ValidateRange(0, 100)][double]$MaxErrorPercent = 10,
    [string]$SummaryPath = $env:GITHUB_STEP_SUMMARY,
    [switch]$AllowUnelevated
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
$problems = New-Object 'System.Collections.Generic.List[string]'
# In GitHub Actions, results also go out as annotations: they show on the run page and in the API without a sign-in.
$actions = $env:GITHUB_ACTIONS -eq 'true'
function Write-Annotation([string]$Level, [string]$Title, [string]$Text) {
    if ($actions) { Write-Host ('::{0} title={1}::{2}' -f $Level, $Title, ($Text -replace '%', '%25' -replace "`r?`n", '%0A')) }
}
$lines = New-Object 'System.Collections.Generic.List[string]'

$machine = Get-PowerScapSystemProfile
$os = $machine.Products | Where-Object { [PowerScap.Engine.Profile.BenchmarkMatcher]::IsOperatingSystem($_.NcpTarget) } | Select-Object -First 1
"Machine: $($machine.OsCaption) $($machine.OsBuild) ($($machine.OsEdition)), $(if ($machine.DomainJoined) { 'domain' } else { 'workgroup' }) $($machine.DomainOrWorkgroup)"
"PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
"Detected: " + (($machine.Products | ForEach-Object { $_.Name }) -join ', ')
$lines.Add("### PowerSCAP smoke test: $($machine.OsCaption) $($machine.OsBuild), PowerShell $($PSVersionTable.PSVersion)")
$lines.Add('')
$lines.Add('Detected: ' + (($machine.Products | ForEach-Object { $_.Name }) -join ', '))
$lines.Add('')
if (-not $os) { $problems.Add("No operating system was detected from '$($machine.OsCaption)'.") }

if (-not $NoDownload) {
    $found = @(Find-PowerScapBenchmark -MatchSystem)
    "Matched: " + (($found | ForEach-Object { $_.Name }) -join '; ')
    $osMatch = @($found | Where-Object { $os -and $_.Product.NcpTarget -eq $os.NcpTarget })
    if (-not $osMatch) { $problems.Add("NCP has no SCAP benchmark matched to $(if ($os) { $os.NcpTarget } else { 'this operating system' }).") }
    $found | Save-PowerScapBenchmark -CacheRoot $CacheRoot -ErrorVariable downloadErrors -ErrorAction Continue | Out-Null
    foreach ($e in $downloadErrors) { $problems.Add("Download: $($e.Exception.Message)") }
}

$entries = @(Get-PowerScapBenchmark -Latest -CacheRoot $CacheRoot | Where-Object { -not $_.Missing })
if (-not $entries) { $problems.Add('No content to scan.') }

$lines.Add('| Benchmark | Rules | Pass | Fail | Error | N/A | Not checked | Score | Output files |')
$lines.Add('|---|---:|---:|---:|---:|---:|---:|---:|---|')
foreach ($entry in $entries) {
    $name = if ($entry.ChecklistName) { $entry.ChecklistName } else { $entry.BenchmarkTitle }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $scan = $entry | Invoke-PowerScapScan -CacheRoot $CacheRoot -OutputPath $OutputPath -Formats All -NoHistory -PassThru -AllowUnelevated:$AllowUnelevated
    }
    catch {
        $problems.Add("$name : scan failed: $($_.Exception.Message)")
        $lines.Add("| $name | scan failed | | | | | | | |")
        continue
    }
    $rules = @($scan.Report.Rules)
    $count = { param($r) @($rules | Where-Object { $_.ResultText -eq $r }).Count }
    $errors = & $count 'error'
    $files = @($scan.Files.Values | Where-Object { $_ -match '(XCCDF-Results|OVAL-Results(-\d+)?|ARF)\.xml$' })
    $invalid = @($files | & (Join-Path $PSScriptRoot 'Test-ScapSchema.ps1') | Where-Object { -not $_.Valid })
    foreach ($v in $invalid) { $problems.Add("$name : $(Split-Path $v.Path -Leaf) is not schema-valid: $(($v.Errors | Select-Object -First 3) -join ' | ')") }
    $line = "{0}: {1} rules in {2:0.0}s, score {3:0.##}, {4} error(s), {5} file(s) validated" -f $name, $rules.Count, $sw.Elapsed.TotalSeconds, $scan.Report.DefaultScore, $errors, $files.Count
    $line
    $lines.Add(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7:0.##}% | {8} |' -f $name, $rules.Count, (& $count 'pass'), (& $count 'fail'), $errors,
        (& $count 'notapplicable'), (& $count 'notchecked'), $scan.Report.DefaultScore, $(if ($invalid) { "**$($invalid.Count) invalid**" } else { "$($files.Count) valid" })))

    # Errors are listed so a run on a new platform shows what to look at.
    $errorLines = foreach ($r in @($rules | Where-Object { $_.ResultText -eq 'error' } | Select-Object -First 15)) {
        $why = (($r.Details -split "`n") | Where-Object { $_ -match '^\s*(Message|Error Information)\s*:' } | Select-Object -First 1) -replace '^\s*[\w ]+?\s*:\s*', ''
        "    error {0}: {1}" -f $r.StigId, ("$why".Trim())
    }
    $errorLines
    Write-Annotation 'notice' $name (@($line) + @($errorLines) -join "`n")
    if ($rules.Count -gt 0 -and 100.0 * $errors / $rules.Count -gt $MaxErrorPercent) {
        $problems.Add(("{0} : {1} of {2} rules ended in error (more than {3}%)." -f $name, $errors, $rules.Count, $MaxErrorPercent))
    }
    $isOs = $os -and $entry.Targets -and @($entry.Targets | Where-Object { $_.Trim() -eq $os.NcpTarget }).Count -gt 0
    if ($isOs -and $scan.Report.ExcludedByPlatform) {
        $problems.Add("$name : every rule is Not Applicable: the benchmark's platform checks do not recognize $($machine.OsCaption).")
    }
}

$lines.Add('')
if ($problems.Count) {
    $lines.Add('**Problems**')
    foreach ($p in $problems) { $lines.Add("- $p") }
}
else { $lines.Add('No problems.') }
if ($SummaryPath) { Add-Content -LiteralPath $SummaryPath -Value $lines -Encoding UTF8 }
if (-not $NoDownload) { Remove-Item -LiteralPath $CacheRoot -Recurse -Force -ErrorAction SilentlyContinue }

if ($problems.Count) {
    $problems | ForEach-Object { Write-Host "PROBLEM: $_"; Write-Annotation 'error' 'Smoke test' $_ }
    exit 1
}
'Smoke test passed.'

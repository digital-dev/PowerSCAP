<#
.SYNOPSIS
    Scans every benchmark in tests\content and compares each result file with the matching SCC session results.
.DESCRIPTION
    Run elevated for a real parity run. -AllowUnelevated is for trial runs (admin-only checks will report errors).
.EXAMPLE
    .\tools\Invoke-ParityRun.ps1 -SccSession "$env:USERPROFILE\SCC\Sessions\2026-10-15_210812"
#>
param(
    [string]$SccSession = (Join-Path $env:USERPROFILE 'SCC\Sessions\2026-10-15_210812'),
    [string]$ContentDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tests\content'),
    [string]$OutputPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'out\parity'),
    [switch]$AllowUnelevated
)

$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
$compare = Join-Path $PSScriptRoot 'Compare-XccdfResults.ps1'

# NIWC zip name fragment → SCC stream name fragment
$pairs = [ordered]@{
    'Windows_11'          = 'Microsoft_Windows_11_STIG'
    'MS_Edge'             = 'MS_Edge_STIG'
    'Google_Chrome'       = 'Google_Chrome_Current_Windows'
    'MOZ_Firefox_Windows' = 'MOZ_Firefox_STIG_Windows'
    'Defender_Antivirus'  = 'MS_Defender_Antivirus'
    'Defender_Firewall'   = 'Windows_Firewall_with_Advanced_Security'
    'DotNet_Framework'    = 'MS_Dot_Net_Framework'
}

$all = foreach ($kv in $pairs.GetEnumerator()) {
    $zip = Get-ChildItem $ContentDir -Filter "*$($kv.Key)*.zip" | Select-Object -First 1
    $ref = Get-ChildItem (Join-Path $SccSession 'Results\SCAP\XML') -Filter "*XCCDF-Results_$($kv.Value)*.xml" | Select-Object -First 1
    if (-not $zip -or -not $ref) { Write-Warning "Skipping $($kv.Key): content or SCC results missing"; continue }
    # Scan with the same profile SCC used.
    [xml]$refXml = Get-Content $ref.FullName -Raw
    $refProfile = @($refXml.GetElementsByTagName('profile', 'http://checklists.nist.gov/xccdf/1.2'))[-1]
    $profileId = if ($refProfile) { $refProfile.GetAttribute('idref') } else { $null }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $scan = Invoke-PowerScapScan -ContentPath $zip.FullName -ProfileId $profileId -OutputPath $OutputPath -PassThru -AllowUnelevated:$AllowUnelevated
    $rows = & $compare -Reference $ref.FullName -Actual $scan.Path 6>$null
    foreach ($r in $rows) {
        [pscustomobject]@{ Benchmark = $kv.Key; RuleId = $r.RuleId; Reference = $r.Reference; Actual = $r.Actual; Match = $r.Match }
    }
    Write-Host ('{0,-20} {1,4} rules  {2,4} mismatches  {3,6:N1}s' -f $kv.Key, @($rows).Count, @($rows | Where-Object { -not $_.Match }).Count, $sw.Elapsed.TotalSeconds)
}

$csv = Join-Path $OutputPath 'parity.csv'
$all | Export-Csv $csv -NoTypeInformation
Write-Host "Details: $csv"

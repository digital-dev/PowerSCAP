function Invoke-PowerScapScan {
    <#
    .SYNOPSIS
        Scans the local machine with one SCAP benchmark and writes XCCDF 1.2 results.
    .PARAMETER ContentPath
        SCAP source data stream (.xml or .zip) or standalone XCCDF benchmark.
    .PARAMETER ProfileId
        XCCDF profile to evaluate. Defaults to the first profile in the benchmark.
    .PARAMETER OutputPath
        Folder for the results file <host>_<benchmark>_<yyyyMMdd_HHmmss>_XCCDF-Results.xml.
    .PARAMETER AllowUnelevated
        Runs without administrator rights. Checks that need elevation will report errors; intended for testing.
    .EXAMPLE
        Invoke-PowerScapScan -ContentPath .\U_MS_Windows_11_STIG_SCAP_1-4_Benchmark.zip -OutputPath .\out -PassThru
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ContentPath,
        [string]$ProfileId,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$PassThru,
        [switch]$AllowUnelevated
    )

    $ErrorActionPreference = 'Stop'
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $AllowUnelevated -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'PowerSCAP must run elevated.'
    }

    $start = Get-Date
    $content = [PowerScap.Engine.Content.ScapContentLoader]::Load((Resolve-Path -LiteralPath $ContentPath).ProviderPath)
    if (-not $ProfileId) {
        $first = $content.Benchmark.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'Profile' } | Select-Object -First 1
        if ($first) { $ProfileId = $first.GetAttribute('id') }
    }
    $profile = [PowerScap.Engine.Xccdf.ProfileResolver]::Resolve($content, $ProfileId)
    $collectors = [PowerScap.Engine.Oval.CollectorRegistry]::CreateDefault()
    $results = [PowerScap.Engine.Xccdf.RuleEvaluator]::Evaluate($content, $profile, $collectors, $null)
    $scores = [PowerScap.Engine.Xccdf.Scoring]::Compute($profile, $results)
    $target = [PowerScap.Engine.Xccdf.TargetInfo]::Collect()

    $short = $content.BenchmarkId -replace '^xccdf_.*?_benchmark_', ''
    $short = ($short -replace '[^\w\-\.]', '_')
    $file = Join-Path $OutputPath ('{0}_{1}_{2:yyyyMMdd_HHmmss}_XCCDF-Results.xml' -f $target.HostName, $short, $start)
    [PowerScap.Engine.Xccdf.ResultsWriter]::WriteXccdf($content, $profile, $results, $scores, $target, $file, $start, (Get-Date))
    Write-Verbose "Results written to $file"

    if ($PassThru) {
        [pscustomobject]@{
            BenchmarkId = $content.BenchmarkId
            ProfileId   = $ProfileId
            Scores      = $scores
            Results     = $results
            Path        = $file
        }
    }
}

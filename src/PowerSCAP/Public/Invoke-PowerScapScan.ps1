function Invoke-PowerScapScan {
    <#
    .SYNOPSIS
        Scans the local machine with one SCAP benchmark and writes XCCDF 1.2 results.
    .PARAMETER ContentPath
        SCAP source data stream (.xml or .zip) or standalone XCCDF benchmark.
    .PARAMETER Benchmark
        Cached content from Get-PowerScapBenchmark (pipeline input).
    .PARAMETER ProfileId
        XCCDF profile to evaluate. Defaults to the first profile in the benchmark.
    .PARAMETER OutputPath
        Folder for the results file <host>_<benchmark>_<yyyyMMdd_HHmmss>_XCCDF-Results.xml.
    .PARAMETER AllowInvalidSignature
        Scans content whose XML signature does not verify. The override is recorded in the results.
    .PARAMETER Collectors
        Collector set to reuse across scans (its folder and registry listings are shared). Benchmarks piped
        into one call share a set automatically.
    .PARAMETER AllowUnelevated
        Runs without administrator rights. Checks that need elevation will report errors; intended for testing.
    .EXAMPLE
        Invoke-PowerScapScan -ContentPath .\U_MS_Windows_11_STIG_SCAP_1-4_Benchmark.zip -OutputPath .\out -PassThru
    .EXAMPLE
        Get-PowerScapBenchmark -Latest | Invoke-PowerScapScan -OutputPath .\out
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$ContentPath,
        [Parameter(Mandatory, ParameterSetName = 'Benchmark', ValueFromPipeline)][PowerScap.Engine.Cache.CacheEntry]$Benchmark,
        [Parameter(ParameterSetName = 'Benchmark')][string]$CacheRoot,
        [string]$ProfileId,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$PassThru,
        [switch]$AllowInvalidSignature,
        [PowerScap.Engine.Oval.CollectorRegistry]$Collectors,
        [switch]$AllowUnelevated
    )

    begin {
        $ErrorActionPreference = 'Stop'
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $AllowUnelevated -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'PowerSCAP must run elevated.'
        }
        $requestedProfile = $ProfileId
        # One collector set per call: each folder and registry key is read once, however many benchmarks need it.
        if (-not $Collectors) { $Collectors = [PowerScap.Engine.Oval.CollectorRegistry]::CreateDefault() }
    }

    process {
        $path = if ($PSCmdlet.ParameterSetName -eq 'Benchmark') { (Get-PowerScapCache $CacheRoot).PathOf($Benchmark) } else { (Resolve-Path -LiteralPath $ContentPath).ProviderPath }
        if (-not (Test-Path -LiteralPath $path)) { throw "Cached content is missing from disk: $path" }

        $remarks = New-Object 'System.Collections.Generic.List[string]'
        $signature = [PowerScap.Engine.Content.SignatureVerifier]::Verify($path)
        if ($signature.State -eq [PowerScap.Engine.Content.SignatureState]::Invalid) {
            if (-not $AllowInvalidSignature) {
                throw "Signature check failed for $(Split-Path $path -Leaf): $($signature.Message). Re-download the content or pass -AllowInvalidSignature."
            }
            $remarks.Add("Signature verification failed and was overridden by the operator: $($signature.Message)")
        }

        $start = Get-Date
        $content = [PowerScap.Engine.Content.ScapContentLoader]::Load($path)
        $ProfileId = $requestedProfile
        if (-not $ProfileId) {
            $first = $content.Benchmark.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'Profile' } | Select-Object -First 1
            if ($first) { $ProfileId = $first.GetAttribute('id') }
        }
        $profile = [PowerScap.Engine.Xccdf.ProfileResolver]::Resolve($content, $ProfileId)
        $results = [PowerScap.Engine.Xccdf.RuleEvaluator]::Evaluate($content, $profile, $Collectors, $null)
        $scores = [PowerScap.Engine.Xccdf.Scoring]::Compute($profile, $results)
        $target = [PowerScap.Engine.Xccdf.TargetInfo]::Collect()

        $short = $content.BenchmarkId -replace '^xccdf_.*?_benchmark_', ''
        $short = ($short -replace '[^\w\-\.]', '_')
        $file = Join-Path $OutputPath ('{0}_{1}_{2:yyyyMMdd_HHmmss}_XCCDF-Results.xml' -f $target.HostName, $short, $start)
        [PowerScap.Engine.Xccdf.ResultsWriter]::WriteXccdf($content, $profile, $results, $scores, $target, $file, $start, (Get-Date), $remarks)
        Write-Verbose "Results written to $file"

        if ($PassThru) {
            [pscustomobject]@{
                BenchmarkId = $content.BenchmarkId
                ProfileId   = $ProfileId
                Signature   = $signature
                Scores      = $scores
                Results     = $results
                Path        = $file
            }
        }
    }
}

function Invoke-PowerScapScan {
    <#
    .SYNOPSIS
        Scans the local machine with SCAP benchmarks and writes results, reports and STIG Viewer checklists.
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
    .PARAMETER Formats
        Outputs besides the XCCDF results (always written): Html (All-Settings and Non-Compliance reports),
        Cklb (STIG Viewer checklist), Oval (OVAL results), Arf (Asset Reporting Format), or All.
        Default: Html, Cklb. Scanning several benchmarks in one call also writes a summary page.
    .PARAMETER AllowUnelevated
        Runs without administrator rights. Checks that need elevation will report errors; intended for testing.
    .EXAMPLE
        Invoke-PowerScapScan -ContentPath .\U_MS_Windows_11_STIG_SCAP_1-4_Benchmark.zip -OutputPath .\out -PassThru
    .EXAMPLE
        Get-PowerScapBenchmark -Latest | Invoke-PowerScapScan -OutputPath .\out
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path', ValueFromPipelineByPropertyName)][Alias('FullName')][string]$ContentPath,
        [Parameter(Mandatory, ParameterSetName = 'Benchmark', ValueFromPipeline)][PowerScap.Engine.Cache.CacheEntry]$Benchmark,
        [Parameter(ParameterSetName = 'Benchmark')][string]$CacheRoot,
        [string]$ProfileId,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$PassThru,
        [switch]$AllowInvalidSignature,
        [PowerScap.Engine.Oval.CollectorRegistry]$Collectors,
        [ValidateSet('Html', 'Cklb', 'Oval', 'Arf', 'All')][string[]]$Formats = @('Html', 'Cklb'),
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
        $reports = New-Object 'System.Collections.Generic.List[PowerScap.Engine.Reports.BenchmarkReport]'
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

        $end = Get-Date
        $short = $content.BenchmarkId -replace '^xccdf_.*?_benchmark_', ''
        $short = ($short -replace '[^\w\-\.]', '_')
        if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
        # Never overwrite an earlier run that landed in the same second.
        $stem = Join-Path $OutputPath ('{0}_{1}_{2:yyyyMMdd_HHmmss}' -f $target.HostName, $short, $start)
        $n = 1; $base = $stem
        while (Test-Path -LiteralPath "${stem}_XCCDF-Results.xml") { $n++; $stem = "${base}_$n" }

        $file = "${stem}_XCCDF-Results.xml"
        [PowerScap.Engine.Xccdf.ResultsWriter]::WriteXccdf($content, $profile, $results, $scores, $target, $file, $start, $end, $remarks)
        Write-Verbose "Results written to $file"

        $report = [PowerScap.Engine.Reports.BenchmarkReport]::Build($content, $profile, $results, $scores, $target, $start, $end)
        $report.Signature = "$signature"
        $report.Files['XCCDF'] = $file
        $want = @($Formats | ForEach-Object { $_.ToLowerInvariant() })
        $all = $want -contains 'all'
        if ($all -or $want -contains 'html') {
            $report.Files['All-Settings'] = "${stem}_All-Settings.html"
            $report.Files['Non-Compliance'] = "${stem}_Non-Compliance.html"
            [PowerScap.Engine.Reports.HtmlReport]::Write($report, $report.Files['All-Settings'], $false)
            [PowerScap.Engine.Reports.HtmlReport]::Write($report, $report.Files['Non-Compliance'], $true)
        }
        if ($all -or $want -contains 'cklb') {
            $report.Files['Checklist'] = "${stem}_Checklist.cklb"
            [PowerScap.Engine.Reports.CklbWriter]::Write([PowerScap.Engine.Reports.BenchmarkReport[]]@($report), $report.Files['Checklist'])
        }
        if ($all -or $want -contains 'oval' -or $want -contains 'arf') {
            $oval = [PowerScap.Engine.Reports.OvalResultsWriter]::Build($results, $content, $target, $end)
            if ($all -or $want -contains 'oval') {
                $i = 0
                foreach ($kv in $oval.GetEnumerator()) {
                    $i++
                    $name = if ($oval.Count -gt 1) { "${stem}_OVAL-Results-$i.xml" } else { "${stem}_OVAL-Results.xml" }
                    $kv.Value.Save($name)
                    $report.Files["OVAL$(if ($oval.Count -gt 1) { "-$i" })"] = $name
                }
            }
            if ($all -or $want -contains 'arf') {
                $report.Files['ARF'] = "${stem}_ARF.xml"
                [PowerScap.Engine.Reports.ArfWriter]::Write($report, $file, $oval, $report.Files['ARF'])
            }
        }
        $reports.Add($report)

        if ($PassThru) {
            [pscustomobject]@{
                BenchmarkId = $content.BenchmarkId
                ProfileId   = $ProfileId
                Signature   = $signature
                Scores      = $scores
                Results     = $results
                Path        = $file
                Report      = $report
                Files       = $report.Files
            }
        }
    }

    end {
        if ($reports.Count -gt 1) {
            $stamp = '{0:yyyyMMdd_HHmmss}' -f $reports[0].Start
            $summary = Join-Path $OutputPath ('{0}_{1}_Summary.html' -f $reports[0].Target.HostName, $stamp)
            [PowerScap.Engine.Reports.SummaryReport]::Write($reports, $summary)
            Write-Verbose "Summary written to $summary"
        }
    }
}

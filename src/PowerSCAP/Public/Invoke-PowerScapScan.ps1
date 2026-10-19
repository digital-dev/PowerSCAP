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
    .PARAMETER NoReview
        Leaves out the layers beyond SCAP: PowerSCAP's checks for manual rules and saved answers. Reports and the
        checklist then show the SCAP results only. XCCDF, OVAL and ARF results are SCAP-only either way.
    .PARAMETER NoHistory
        Does not add the scan to the scan history the GUI shows (%ProgramData%\PowerSCAP\history).
    .PARAMETER AllowUnelevated
        Runs without administrator rights. Checks that need elevation will report errors; intended for testing.
    .EXAMPLE
        Invoke-PowerScapScan -ContentPath .\U_MS_Windows_11_STIG_SCAP_1-4_Benchmark.zip -OutputPath .\out -PassThru
    .EXAMPLE
        Get-PowerScapBenchmark -Latest | Invoke-PowerScapScan -OutputPath .\out
    #>
    # Default to the cached-benchmark set: piped cache entries bind by value; files bind to -ContentPath by FullName.
    [CmdletBinding(DefaultParameterSetName = 'Benchmark')]
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
        [switch]$NoHistory,
        [switch]$NoReview,
        [switch]$AllowUnelevated
    )

    begin {
        $ErrorActionPreference = 'Stop'
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $AllowUnelevated -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'PowerSCAP must run elevated.'
        }
        $OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
        $flags = [PowerScap.Engine.Scan.OutputFormats]::None
        foreach ($f in $Formats) { $flags = $flags -bor [PowerScap.Engine.Scan.OutputFormats]$f }
        # One collector set per call: each folder and registry key is read once, however many benchmarks need it.
        $runner = [PowerScap.Engine.Scan.ScanRunner]::new($Collectors)
        if (-not $NoHistory) { $runner.HistoryRoot = [PowerScap.Engine.Scan.ScanHistory]::DefaultRoot() }
        if ($NoReview) { $runner.ManualChecks = $false; $runner.AnswersRoot = $null }
        $reports = New-Object 'System.Collections.Generic.List[PowerScap.Engine.Reports.BenchmarkReport]'
    }

    process {
        $path = if ($PSCmdlet.ParameterSetName -eq 'Benchmark') { (Get-PowerScapCache $CacheRoot).PathOf($Benchmark) } else { (Resolve-Path -LiteralPath $ContentPath).ProviderPath }
        $request = New-Object PowerScap.Engine.Scan.ScanRequest -Property @{
            ContentPath = $path; ProfileId = $ProfileId; OutputPath = $OutputPath
            Formats = $flags; AllowInvalidSignature = [bool]$AllowInvalidSignature
        }
        $warnings = New-Object 'System.Collections.Generic.List[string]'
        $handler = [Action[string]] { param($m) $warnings.Add($m) }
        $runner.add_Warning($handler)
        try {
            try { $outcome = $runner.Run($request, $null, [Threading.CancellationToken]::None) }
            catch [PowerScap.Engine.Scan.ScanException] { throw $_.Exception.Message }
        }
        finally { $runner.remove_Warning($handler) }
        $report = $outcome.Report
        foreach ($w in $warnings) { Write-Warning $w }
        Write-Verbose "Results written to $($report.Files['XCCDF'])"
        $reports.Add($report)

        if ($PassThru) {
            [pscustomobject]@{
                BenchmarkId = $report.BenchmarkId
                ProfileId   = $report.ProfileId
                Signature   = $outcome.Signature
                Scores      = $report.Scores
                Results     = $outcome.Results
                Path        = $report.Files['XCCDF']
                Report      = $report
                Files       = $report.Files
            }
        }
    }

    end {
        $summary = [PowerScap.Engine.Scan.ScanRunner]::WriteSummary($reports, $OutputPath)
        if ($summary) { Write-Verbose "Summary written to $summary" }
    }
}

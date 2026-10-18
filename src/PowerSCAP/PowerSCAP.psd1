@{
    RootModule        = 'PowerSCAP.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '6f3c1d8e-2b7a-4c55-9a1e-0d4b7e5c2f91'
    Author            = 'digital-dev'
    Copyright         = '(c) PowerSCAP contributors. Licensed under GPL-3.0.'
    Description       = 'Local SCAP compliance scanner for Windows: DISA STIG benchmarks, SCC-style HTML reports, STIG Viewer checklists, XCCDF/OVAL/ARF results and a WPF desktop app.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Import-PowerScapEngine', 'Invoke-PowerScapScan',
        'Get-PowerScapSystemProfile', 'Find-PowerScapBenchmark', 'Save-PowerScapBenchmark',
        'Import-PowerScapBenchmark', 'Get-PowerScapBenchmark', 'Test-PowerScapBenchmarkUpdate',
        'Start-PowerScapGui', 'New-PowerScapShortcut'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('SCAP', 'STIG', 'XCCDF', 'OVAL', 'Compliance', 'Security', 'DISA', 'Windows')
            LicenseUri = 'https://github.com/digital-dev/PowerSCAP/blob/main/LICENSE'
            ProjectUri = 'https://github.com/digital-dev/PowerSCAP'
        }
    }
}

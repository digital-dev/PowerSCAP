$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$http = New-Object PowerScapTests.FakeTransport
$http.Map('search/results', [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures\ncp\search-scap14.json')))
$catalog = (New-Object PowerScap.Engine.Ncp.NcpClient($http)).Search('', [int[]]@(29))

function New-Profile([string[]]$Targets) {
    $p = New-Object PowerScap.Engine.Profile.SystemProfile
    foreach ($t in $Targets) {
        $d = New-Object PowerScap.Engine.Profile.DetectedProduct
        $d.Name = $t; $d.NcpTarget = $t
        $p.Products.Add($d)
    }
    $p
}

Describe 'BenchmarkMatcher' {
    It 'matches every benchmark for a typical Windows 11 workstation' {
        $p = New-Profile 'Microsoft Windows 11', 'Microsoft Windows 10', 'Microsoft Edge', 'Google Chrome', 'Mozilla Firefox', 'Microsoft .NET Framework 4.0', 'Microsoft Windows Defender', 'Windows Firewall'
        $ids = @([PowerScap.Engine.Profile.BenchmarkMatcher]::Match($p, $catalog) | ForEach-Object { $_.Checklist.Id } | Sort-Object)
        $ids -join ',' | Should Be '356,432,483,686,807,986,1028'
    }

    It 'matches only what is installed' {
        $m = @([PowerScap.Engine.Profile.BenchmarkMatcher]::Match((New-Profile 'Google Chrome'), $catalog))
        $m.Count | Should Be 1
        $m[0].Checklist.Id | Should Be 483
        $m[0].Resource.FileName | Should Be 'U_Google_Chrome_V2R11_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip'
    }

    It 'skips checklists for another operating system even when they list a detected product' {
        # NCP lists 'Microsoft Windows Defender' among the Windows 2008 STIG's targets.
        $p = New-Profile 'Microsoft Windows 11', 'Microsoft Windows Defender'
        $ids = @([PowerScap.Engine.Profile.BenchmarkMatcher]::Match($p, $catalog) | ForEach-Object { $_.Checklist.Id } | Sort-Object)
        $ids -join ',' | Should Be '807,1028'
    }

    It 'matches an operating system checklist on that operating system' {
        $ids = @([PowerScap.Engine.Profile.BenchmarkMatcher]::Match((New-Profile 'Microsoft Windows Server 2008', 'Microsoft Windows Defender'), $catalog) | ForEach-Object { $_.Checklist.Id } | Sort-Object)
        $ids -join ',' | Should Be '228,807'
    }

    It 'tells operating systems from components in real NCP target names' {
        foreach ($os in 'Microsoft Windows 11', 'Microsoft Windows Server 2008 R2', 'Microsoft Windows 7 32-bit (X86)', 'Microsoft Windows 8.1 (x64)', 'Microsoft Windows XP Pro SP2', 'Red Hat Enterprise Linux 9.0', 'Apple macOS 14.0') {
            [PowerScap.Engine.Profile.BenchmarkMatcher]::IsOperatingSystem($os) | Should Be $true
        }
        foreach ($component in 'Microsoft Windows Defender', 'Microsoft Windows Mail', 'Microsoft Windows Media Player', 'Windows Firewall', 'Microsoft Edge', 'Microsoft .NET Framework 4.0') {
            [PowerScap.Engine.Profile.BenchmarkMatcher]::IsOperatingSystem($component) | Should Be $false
        }
    }

    It 'matches target names case-insensitively' {
        @([PowerScap.Engine.Profile.BenchmarkMatcher]::Match((New-Profile 'google chrome'), $catalog)).Count | Should Be 1
    }

    It 'matches nothing for products without content' {
        @([PowerScap.Engine.Profile.BenchmarkMatcher]::Match((New-Profile 'Microsoft Windows 10'), $catalog)).Count | Should Be 0
    }
}

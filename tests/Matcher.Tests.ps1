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

    It 'matches target names case-insensitively' {
        @([PowerScap.Engine.Profile.BenchmarkMatcher]::Match((New-Profile 'google chrome'), $catalog)).Count | Should Be 1
    }

    It 'matches nothing for products without content' {
        @([PowerScap.Engine.Profile.BenchmarkMatcher]::Match((New-Profile 'Microsoft Windows 10'), $catalog)).Count | Should Be 0
    }
}

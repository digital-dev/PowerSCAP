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

    It 'matches every Windows benchmark of a checklist that carries several' {
        $c = New-Object PowerScap.Engine.Ncp.NcpChecklist -Property @{ Id = 952; Name = 'Microsoft IIS 10.0 Server STIG' }
        $c.Targets.Add('Microsoft IIS 10')
        foreach ($f in 'U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip', 'U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip') {
            $c.Resources.Add((New-Object PowerScap.Engine.Ncp.NcpResource -Property @{ Title = $f; Location = "https://example.test/$f"; TypeName = 'SCAP 1.4 Content' }))
        }
        $list = New-Object 'System.Collections.Generic.List[PowerScap.Engine.Ncp.NcpChecklist]'; $list.Add($c)
        $m = @([PowerScap.Engine.Profile.BenchmarkMatcher]::Match((New-Profile 'Microsoft IIS 10'), $list))
        ($m | ForEach-Object Name) -join ',' | Should Be 'Microsoft IIS 10.0 Server STIG - MS IIS 10-0 Server,Microsoft IIS 10.0 Server STIG - MS IIS 10-0 Site'
    }

    It 'matches OneDrive under its NCP target name' {
        # NCP checklist 739 (the NIWC enhanced OneDrive benchmark) as NCP lists it.
        $c = New-Object PowerScap.Engine.Ncp.NcpChecklist -Property @{ Id = 739; Name = 'Microsoft One Drive for Business 2016 STIG' }
        $c.Targets.Add('Microsoft One Drive for Business 2016')
        $f = 'U_MS_OneDrive_V2R4_STIG_SCAP_1-4_Benchmark-enhancedV12-signed.zip'
        $c.Resources.Add((New-Object PowerScap.Engine.Ncp.NcpResource -Property @{ Title = $f; Location = "https://example.test/$f"; TypeName = 'SCAP 1.4 Content' }))
        $list = New-Object 'System.Collections.Generic.List[PowerScap.Engine.Ncp.NcpChecklist]'; $list.Add($c)
        $m = @([PowerScap.Engine.Profile.BenchmarkMatcher]::Match((New-Profile 'Microsoft Windows 11', 'Microsoft One Drive for Business 2016'), $list))
        $m.Count | Should Be 1
        $m[0].Name | Should Be 'Microsoft One Drive for Business 2016 STIG'
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
        # Checklist 228 carries two benchmarks: domain controller and member server.
        $ids -join ',' | Should Be '228,228,807'
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

    It 'matches NCP targets that carry stray spaces or other casing' {
        # NCP spells the Server 2025 target "Microsoft Windows server 2025 " (lower-case s, trailing space).
        $c = New-Object PowerScap.Engine.Ncp.NcpChecklist
        $c.Id = 9001; $c.Name = 'Microsoft Windows Server 2025'
        $c.Targets.Add('Microsoft Windows server 2025 ')
        $p = New-Profile ([PowerScap.Engine.Profile.SystemProfile]::OperatingSystemTarget('Microsoft Windows Server 2025 Datacenter'))
        [PowerScap.Engine.Profile.BenchmarkMatcher]::ProductFor($p, $c.Targets) | Should Not BeNullOrEmpty
        [PowerScap.Engine.Profile.BenchmarkMatcher]::ProductFor((New-Profile 'Microsoft Windows Server 2022'), $c.Targets) | Should BeNullOrEmpty
    }

    It 'matches nothing for products without content' {
        @([PowerScap.Engine.Profile.BenchmarkMatcher]::Match((New-Profile 'Microsoft Windows 10'), $catalog)).Count | Should Be 0
    }
}

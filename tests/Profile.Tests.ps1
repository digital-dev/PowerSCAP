$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force

Describe 'SystemProfile' {
    $p = [PowerScap.Engine.Profile.SystemProfile]::Collect()
    $targets = @($p.Products | ForEach-Object { $_.NcpTarget })

    It 'describes this machine' {
        $p.OsBuild | Should Match '^10\.0\.\d+$'
        $p.ComputerName | Should Be $env:COMPUTERNAME
        $p.OsCaption | Should Be (Get-CimInstance Win32_OperatingSystem).Caption
    }

    It 'detects Windows, Defender and Firewall' {
        $targets -contains 'Windows Firewall' | Should Be $true
        $targets -contains 'Microsoft Windows Defender' | Should Be $true
        if ($p.OsCaption -match 'Windows 11') { $targets -contains 'Microsoft Windows 11' | Should Be $true }
    }

    It 'detects Edge when installed' {
        $edge = Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
        $targets -contains 'Microsoft Edge' | Should Be $edge
    }

    It 'detects .NET Framework 4' {
        $targets -contains 'Microsoft .NET Framework 4.0' | Should Be $true
    }

    It 'reports the domain or workgroup' {
        $p.DomainOrWorkgroup | Should Not BeNullOrEmpty
        $p.DomainJoined | Should Be (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    }

    It 'detects Microsoft 365 Apps when Click-to-Run Office is installed' {
        $ids = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue).ProductReleaseIds
        $expected = [bool]($ids -and ($ids -split ',' | Where-Object { $_.Trim() -like 'O365*' }))
        $targets -contains 'Microsoft Office 365 ProPlus' | Should Be $expected
    }

    It 'lists each NCP target once' {
        @($targets | Group-Object | Where-Object Count -gt 1).Count | Should Be 0
    }
}

Describe 'Product detection rules' {
    $S = [PowerScap.Engine.Profile.SystemProfile]

    It 'maps <caption> to <target>' -TestCases @(
        @{ caption = 'Microsoft Windows 11 Pro'; target = 'Microsoft Windows 11' }
        @{ caption = 'Microsoft Windows 10 Enterprise LTSC'; target = 'Microsoft Windows 10' }
        @{ caption = 'Microsoft Windows Server 2025 Datacenter'; target = 'Microsoft Windows server 2025' }
        @{ caption = 'Microsoft Windows Server 2022 Standard'; target = 'Microsoft Windows Server 2022' }
        @{ caption = 'Microsoft Windows Server 2019 Datacenter'; target = 'Microsoft Windows Server 2019' }
        @{ caption = 'Microsoft Windows Server 2016 Standard'; target = 'Microsoft Windows Server 2016' }
        @{ caption = 'Microsoft Windows Server 2012 R2 Standard'; target = 'Microsoft Windows Server 2012 R2' }
        @{ caption = 'Microsoft Windows Server 2008 R2 Enterprise'; target = 'Microsoft Windows Server 2008 R2' }
        @{ caption = 'Microsoft Windows 8.1 Pro'; target = $null }
    ) {
        param($caption, $target)
        $S::OperatingSystemTarget($caption) | Should Be $target
    }

    It 'maps Click-to-Run Microsoft 365 products to the Office 365 ProPlus STIG, and only those' {
        $S::OfficeTarget('O365HomePremRetail') | Should Be 'Microsoft Office 365 ProPlus'
        $S::OfficeTarget('VisioProRetail,O365ProPlusRetail') | Should Be 'Microsoft Office 365 ProPlus'
        $S::OfficeTarget('ProPlus2021Volume') | Should BeNullOrEmpty
        $S::OfficeTarget($null) | Should BeNullOrEmpty
    }

    It 'maps IIS, SQL Server and Exchange versions to the releases NCP has content for' {
        $S::IisTarget(10, 0) | Should Be 'Microsoft IIS 10'
        $S::IisTarget(8, 5) | Should Be 'IIS 8.5'
        $S::IisTarget(7, 5) | Should BeNullOrEmpty
        $S::SqlServerTarget('13.2.5026.0') | Should Be 'Microsoft SQL Server 2016'
        $S::SqlServerTarget('16.0.1000.6') | Should Be 'Microsoft SQL Server 2022'
        $S::SqlServerTarget('15.0.2000.5') | Should BeNullOrEmpty
        $S::ExchangeTarget(15, 2) | Should Be 'Microsoft Exchange Server 2019'
        $S::ExchangeTarget(15, 1) | Should BeNullOrEmpty
    }

    It 'recognizes Adobe Acrobat, Apache and McAfee by their installed-program names' {
        $programs = New-Object 'System.Collections.Generic.List[System.Collections.Generic.KeyValuePair[string,string]]'
        foreach ($p in @(@('Adobe Acrobat Reader - 64-bit', '25.1'), @('Adobe Acrobat (64-bit)', '25.1'), @('Apache HTTP Server 2.4.62', '2.4.62'),
                        @('McAfee VirusScan Enterprise', '8.8.0.2190'), @('Adobe Acrobat Reader DC', '24.0'), @('Adobe Creative Cloud', '6.0'))) {
            $programs.Add((New-Object 'System.Collections.Generic.KeyValuePair[string,string]'($p[0], $p[1])))
        }
        $found = $S::ProductsFromPrograms($programs)
        @($found | ForEach-Object NcpTarget | Sort-Object) -join '|' |
            Should Be 'Adobe Acrobat Pro DC Continuous Track|Adobe Acrobat Reader|Apache HTTP Server 2.4.0|Mcafee Virusscan Enterprise 8.8.0'
    }
}

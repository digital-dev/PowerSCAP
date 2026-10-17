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
}

$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$fixture = Join-Path $PSScriptRoot 'fixtures\ncp\search-scap14.json'

function New-Grid([object[]]$Checklists, [int]$Total = -1) {
    if ($Total -lt 0) { $Total = $Checklists.Count }
    @{ response = @(@{ grid = @{ resultsPerPage = $Checklists.Count; startIndex = 0; totalResults = $Total; checklists = $Checklists } }) } | ConvertTo-Json -Depth 10
}

function New-Checklist([int]$Id, [string]$Name = "C$Id", [object[]]$Resources = @(), $Targets = @('T')) {
    @{ checklistId = $Id; name = $Name; version = 'Ver 1, Rel 1'; authority = 'A'; lastModified = '2026-01-02T03:04:05.000'; targets = $Targets; resources = $Resources }
}

function New-Resource([string]$Title, [string]$Type = 'SCAP 1.4 Content') {
    @{ checklistResourceId = 1; title = $Title; location = "https://example.test/x/$Title"; resourceTypeName = $Type }
}

Describe 'NcpClient' {
    It 'parses checklists, targets and resources' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.Map('search/results', [IO.File]::ReadAllText($fixture))
        $list = (New-Object PowerScap.Engine.Ncp.NcpClient($http)).Search('', [int[]]@(29))
        $list.Count | Should Be 7
        $w = $list | Where-Object { $_.Id -eq 1028 }
        $w.Name | Should Be 'Microsoft Windows 11 STIG'
        $w.Targets[0] | Should Be 'Microsoft Windows 11'
        $w.LastModified | Should Be ([datetime]'2026-10-06T13:57:42.310')
    }

    It 'picks the Windows SCAP 1.4 resource' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.Map('search/results', [IO.File]::ReadAllText($fixture))
        $list = (New-Object PowerScap.Engine.Ncp.NcpClient($http)).Search('', [int[]]@(29))
        [PowerScap.Engine.Ncp.NcpClient]::PickScapResource(($list | Where-Object { $_.Id -eq 356 })).FileName | Should Be 'U_MOZ_Firefox_Windows_V6R8_STIG_SCAP_1-4_Benchmark-enhancedV13-signed.zip'
        [PowerScap.Engine.Ncp.NcpClient]::PickScapResource(($list | Where-Object { $_.Id -eq 1028 })).FileName | Should Be 'U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip'
    }

    It 'falls back to SCAP 1.3' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.Map('search/results', (New-Grid @(New-Checklist 5 -Resources @((New-Resource 'a.zip' 'Standalone XCCDF 1.1.4'), (New-Resource 'b.zip' 'SCAP 1.3 Content')))))
        $c = (New-Object PowerScap.Engine.Ncp.NcpClient($http)).Search('', [int[]]@(17))[0]
        [PowerScap.Engine.Ncp.NcpClient]::PickScapResource($c).FileName | Should Be 'b.zip'
    }

    It 'deduplicates and tolerates null targets and resources' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.Map('search/results', (New-Grid @((New-Checklist 356 -Resources @(New-Resource 'f.zip')), (New-Checklist 356 -Resources @(New-Resource 'f.zip')), (New-Checklist 9 -Resources $null -Targets $null))))
        $list = (New-Object PowerScap.Engine.Ncp.NcpClient($http)).Search('', [int[]]@(29))
        @($list | Where-Object { $_.Id -eq 356 }).Count | Should Be 1
        $empty = $list | Where-Object { $_.Id -eq 9 }
        $empty.Targets.Count | Should Be 0
        $empty.Resources.Count | Should Be 0
        [PowerScap.Engine.Ncp.NcpClient]::PickScapResource($empty) | Should Be $null
    }

    It 'pages until totalResults' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.Map('offset=0&', (New-Grid @((New-Checklist 1), (New-Checklist 2)) -Total 3))
        $http.Map('offset=2&', (New-Grid @(New-Checklist 3) -Total 3))
        $client = New-Object PowerScap.Engine.Ncp.NcpClient($http)
        $client.PageSize = 2
        $client.Search('', [int[]]@(29)).Count | Should Be 3
        $http.Requests.Count | Should Be 2
    }

    It 'reports an unreachable NCP as NcpException' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.Fail('search/results', 'The remote name could not be resolved')
        { (New-Object PowerScap.Engine.Ncp.NcpClient($http)).Search('', [int[]]@(29)) } | Should Throw 'could not be resolved'
    }

    It 'reports a non-JSON answer as NcpException naming the URL' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.Map('search/results', '<html>error</html>')
        try { (New-Object PowerScap.Engine.Ncp.NcpClient($http)).Search('', [int[]]@(29)); $msg = '' }
        catch { $msg = $_.Exception.InnerException.Message; $type = $_.Exception.InnerException.GetType().Name }
        $type | Should Be 'NcpException'
        $msg | Should Match 'ncp\.nist\.gov'
    }
}

Describe 'NCP live' -Tag Online {
    It 'finds the Windows 11 STIG' {
        $client = New-Object PowerScap.Engine.Ncp.NcpClient((New-Object PowerScap.Engine.Ncp.HttpTransport))
        $list = $client.Search('Windows 11', [int[]]@(29))
        @($list | Where-Object { $_.Targets -contains 'Microsoft Windows 11' }).Count -gt 0 | Should Be $true
    }
}

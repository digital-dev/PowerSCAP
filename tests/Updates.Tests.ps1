$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$fixture = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures\ncp\search-scap14.json'))

function New-Entry([int]$ChecklistId, [string]$FileName, [string]$ETag = '"etag-1"', [switch]$Imported) {
    $e = New-Object PowerScap.Engine.Cache.CacheEntry
    if (-not $Imported) { $e.ChecklistId = $ChecklistId }
    $e.FileName = $FileName; $e.ETag = $ETag; $e.Imported = [bool]$Imported; $e.AddedUtc = [datetime]::UtcNow
    $e
}

function Invoke-Check($http, [object[]]$Entries) {
    $checker = New-Object PowerScap.Engine.Cache.UpdateChecker((New-Object PowerScap.Engine.Ncp.NcpClient($http)), $http)
    $list = New-Object 'System.Collections.Generic.List[PowerScap.Engine.Cache.CacheEntry]'
    foreach ($e in $Entries) { foreach ($x in @($e)) { $list.Add($x) } }
    $checker.Check($list)
}

Describe 'UpdateChecker' {
    $win11 = 'U_MS_Windows_11_V2R10_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip'

    It 'reports Current when the cached file is the published one' {
        $http = New-Object PowerScapTests.FakeTransport; $http.Map('search/results', $fixture)
        $r = @(Invoke-Check $http @(New-Entry 1028 $win11))
        $r[0].State.ToString() | Should Be 'Current'
    }

    It 'reports a new release by file name' {
        $http = New-Object PowerScapTests.FakeTransport; $http.Map('search/results', $fixture)
        $r = @(Invoke-Check $http @(New-Entry 1028 'U_MS_Windows_11_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip'))
        $r[0].State.ToString() | Should Be 'UpdateAvailable'
        $r[0].Reason | Should Be "new release $win11"
        $r[0].Latest.FileName | Should Be $win11
    }

    It 'reports a republished file by ETag' {
        $http = New-Object PowerScapTests.FakeTransport; $http.Map('search/results', $fixture); $http.ETag = '"etag-2"'
        $r = @(Invoke-Check $http @(New-Entry 1028 $win11))
        $r[0].State.ToString() | Should Be 'UpdateAvailable'
        $r[0].Reason | Should Be 'republished'
    }

    It 'reports checklists no longer in the catalog' {
        $http = New-Object PowerScapTests.FakeTransport; $http.Map('search/results', $fixture)
        (@(Invoke-Check $http @(New-Entry 99999 'x.zip')))[0].State.ToString() | Should Be 'NotInCatalog'
    }

    It 'reports CheckFailed when NCP is unreachable, without throwing' {
        $http = New-Object PowerScapTests.FakeTransport; $http.Fail('search/results', 'offline')
        $r = @(Invoke-Check $http @((New-Entry 1028 $win11), (New-Entry 483 'c.zip')))
        $r.Count | Should Be 2
        @($r | Where-Object { $_.State.ToString() -ne 'CheckFailed' }).Count | Should Be 0
    }

    It 'checks only the newest entry per checklist and skips imports' {
        $http = New-Object PowerScapTests.FakeTransport; $http.Map('search/results', $fixture)
        $old = New-Entry 1028 'U_MS_Windows_11_V2R9_STIG_SCAP_1-4_Benchmark-enhancedV17-signed.zip'; $old.AddedUtc = [datetime]::UtcNow.AddDays(-30)
        $r = @(Invoke-Check $http @($old, (New-Entry 1028 $win11), (New-Entry 0 'mine.zip' -Imported)))
        $r.Count | Should Be 1
        $r[0].State.ToString() | Should Be 'Current'
    }

    It 'follows each benchmark of a checklist that carries several (IIS Server and Site)' {
        $res = @(
            @{ checklistResourceId = 1; title = 'U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip'; location = 'https://example.test/U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip'; resourceTypeName = 'SCAP 1.4 Content' },
            @{ checklistResourceId = 2; title = 'U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip'; location = 'https://example.test/U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip'; resourceTypeName = 'SCAP 1.4 Content' })
        $grid = @{ response = @(@{ grid = @{ totalResults = 1; checklists = @(@{ checklistId = 952; name = 'Microsoft IIS 10.0 Server STIG'; version = '3'; targets = @('Microsoft IIS 10'); resources = $res }) } }) } | ConvertTo-Json -Depth 10
        $http = New-Object PowerScapTests.FakeTransport; $http.Map('search/results', $grid)
        $server = New-Entry 952 'U_MS_IIS_10-0_Server_V3R6_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip'
        $site = New-Entry 952 'U_MS_IIS_10-0_Site_V2R13_STIG_SCAP_1-4_Benchmark-enhancedV18-signed.zip'
        $r = @(Invoke-Check $http @($server, $site))
        $r.Count | Should Be 2
        ($r | Where-Object { $_.Cached -eq $server }).State.ToString() | Should Be 'Current'
        $u = $r | Where-Object { $_.Cached -eq $site }
        $u.State.ToString() | Should Be 'UpdateAvailable'
        $u.Latest.FileName | Should Be 'U_MS_IIS_10-0_Site_V2R14_STIG_SCAP_1-4_Benchmark-enhancedV19-signed.zip'
    }

    It 'does not touch the cache' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('powerscap-upd-' + [guid]::NewGuid().ToString('N'))
        try {
            $http = New-Object PowerScapTests.FakeTransport; $http.Map('search/results', $fixture)
            $cache = New-Object PowerScap.Engine.Cache.ContentCache($root, $http)
            $cache.Import((Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml')) | Out-Null
            $before = [IO.File]::ReadAllBytes((Join-Path $root 'manifest.json'))
            Invoke-Check $http @($cache.List()) | Out-Null
            [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $root 'manifest.json'))) | Should Be ([Convert]::ToBase64String($before))
        } finally { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

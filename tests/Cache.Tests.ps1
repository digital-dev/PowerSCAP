$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

$miniDs = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'

# A zip holding mini-ds; $Salt changes the bytes so each salt is a distinct release.
function New-BenchmarkZip([string]$Dir, [string]$Salt = '') {
    $zip = Join-Path $Dir "bench$Salt.zip"
    $text = [IO.File]::ReadAllText($miniDs)
    if ($Salt) { $text += "<!-- $Salt -->" }
    $a = [IO.Compression.ZipFile]::Open($zip, 'Create')
    try {
        $w = New-Object IO.StreamWriter($a.CreateEntry('mini-ds.xml').Open())
        $w.Write($text); $w.Dispose()
    } finally { $a.Dispose() }
    $zip
}

function New-Checklist([int]$Id = 1028) {
    $c = New-Object PowerScap.Engine.Ncp.NcpChecklist
    $c.Id = $Id; $c.Name = 'Microsoft Windows 11 STIG'; $c.Version = 'Ver 2, Rel 11'; $c.LastModified = [datetime]'2026-10-06'
    $c
}

function New-Resource([string]$File = 'U_Test-signed.zip') {
    $r = New-Object PowerScap.Engine.Ncp.NcpResource
    $r.Title = $File; $r.Location = "https://example.test/Current/$File"; $r.TypeName = 'SCAP 1.4 Content'
    $r
}

Describe 'ContentCache' {
    $work = Join-Path ([IO.Path]::GetTempPath()) ('powerscap-cache-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $work | Out-Null
    $src = Join-Path $work 'src'; New-Item -ItemType Directory $src | Out-Null
    $zipA = New-BenchmarkZip $src 'a'
    $zipB = New-BenchmarkZip $src 'b'
    $benchmarkId = ([PowerScap.Engine.Content.ScapContentLoader]::Load($zipA)).BenchmarkId
    $n = 0
    function New-Cache([object]$Http) {
        $script:n++
        $root = Join-Path $work "cache$script:n"
        if (-not $Http) { $Http = New-Object PowerScapTests.FakeTransport }
        New-Object PowerScap.Engine.Cache.ContentCache($root, $Http)
    }

    It 'downloads, validates and records a benchmark' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.MapFile('U_Test-signed.zip', $zipA)
        $http.ETag = '"abc"'
        $cache = New-Cache $http
        $e = $cache.Download((New-Checklist), (New-Resource))
        $e.BenchmarkId | Should Be $benchmarkId
        $e.ETag | Should Be '"abc"'
        $e.ChecklistId | Should Be 1028
        $e.FileName | Should Be 'U_Test-signed.zip'
        Test-Path $cache.PathOf($e) | Should Be $true
        $cache.List().Count | Should Be 1
    }

    It 'keeps old versions' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.MapFile('v1.zip', $zipA); $http.MapFile('v2.zip', $zipB)
        $cache = New-Cache $http
        $e1 = $cache.Download((New-Checklist), (New-Resource 'v1.zip'))
        $e2 = $cache.Download((New-Checklist), (New-Resource 'v2.zip'))
        $cache.List().Count | Should Be 2
        Test-Path $cache.PathOf($e1) | Should Be $true
        Test-Path $cache.PathOf($e2) | Should Be $true
        $cache.List()[0].FileName | Should Be 'v2.zip'
    }

    It 'does not duplicate identical content' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.MapFile('U_Test-signed.zip', $zipA)
        $cache = New-Cache $http
        $cache.Download((New-Checklist), (New-Resource)) | Out-Null
        $cache.Download((New-Checklist), (New-Resource)) | Out-Null
        $cache.List().Count | Should Be 1
    }

    It 'rejects a download that is not SCAP content' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.Map('U_Test-signed.zip', '<html>404</html>')
        $cache = New-Cache $http
        { $cache.Download((New-Checklist), (New-Resource)) } | Should Throw
        $cache.List().Count | Should Be 0
        @(Get-ChildItem (Join-Path $cache.Root '.partial') -ErrorAction SilentlyContinue).Count | Should Be 0
    }

    It 'rejects an interrupted download' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.MapFile('U_Test-signed.zip', $zipA)
        $http.PartialThenFail = $true
        $cache = New-Cache $http
        { $cache.Download((New-Checklist), (New-Resource)) } | Should Throw 'connection reset'
        $cache.List().Count | Should Be 0
        @(Get-ChildItem (Join-Path $cache.Root '.partial') -ErrorAction SilentlyContinue).Count | Should Be 0
    }

    It 'leaves the cache unchanged, and says why, when it may not change the manifest' {
        # An elevated session's manifest cannot be replaced unelevated; a read-only manifest fails the same way.
        $cache = New-Cache
        $cache.Import($zipA) | Out-Null
        $manifest = Join-Path $cache.Root 'manifest.json'
        Set-ItemProperty $manifest -Name IsReadOnly -Value $true
        try {
            { $cache.Import($zipB) } | Should Throw 'can only be changed by an administrator'
            $cache.List().Count | Should Be 1
            @(Get-ChildItem $cache.Root -Recurse -File | Where-Object { $_.Name -ne 'manifest.json' }).Count | Should Be 1
        }
        finally { Set-ItemProperty $manifest -Name IsReadOnly -Value $false }
    }

    It 'imports a local file' {
        $cache = New-Cache
        $e = $cache.Import($zipA)
        $e.Imported | Should Be $true
        $e.ChecklistId | Should Be $null
        $e.BenchmarkId | Should Be $benchmarkId
        $cache.List().Count | Should Be 1
    }

    It 'rejects importing a file that is not SCAP content' {
        $cache = New-Cache
        $bad = Join-Path $work 'bad.xml'; Set-Content $bad '<nope/>'
        { $cache.Import($bad) } | Should Throw
        $cache.List().Count | Should Be 0
    }

    It 'survives a corrupt manifest' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.MapFile('U_Test-signed.zip', $zipA)
        $cache = New-Cache $http
        $cache.Download((New-Checklist), (New-Resource)) | Out-Null
        Set-Content (Join-Path $cache.Root 'manifest.json') '{not json'
        $list = $cache.List()
        $list.Count | Should Be 1
        $list[0].BenchmarkId | Should Be $benchmarkId
        $list[0].ChecklistId | Should Be 1028
        @(Get-ChildItem $cache.Root -Filter 'manifest.json.bad-*').Count | Should Be 1
    }

    It 'flags missing files' {
        $cache = New-Cache
        $e = $cache.Import($zipA)
        Remove-Item $cache.PathOf($e)
        $cache.List()[0].Missing | Should Be $true
    }

    It 'lists without network' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.Fail('http', 'offline')
        $cache = New-Cache $http
        $cache.Import($zipA) | Out-Null
        $cache.List().Count | Should Be 1
    }

    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

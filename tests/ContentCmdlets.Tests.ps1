$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
Add-Type -AssemblyName System.Security

$miniDs = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'
$fixture = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures\ncp\search-scap14.json'))

function Set-Transport($http) { & (Get-Module PowerSCAP) { param($h) $script:PowerScapHttp = $h } $http }

Describe 'Content cmdlets' {
    $work = Join-Path ([IO.Path]::GetTempPath()) ('powerscap-cmd-' + [guid]::NewGuid().ToString('N'))
    $cacheRoot = Join-Path $work 'cache'
    $out = Join-Path $work 'out'
    New-Item -ItemType Directory $out -Force | Out-Null

    It 'saves a matched benchmark into the cache' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.Map('search/results', $fixture)
        $zip = Join-Path $work 'mini.zip'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $a = [IO.Compression.ZipFile]::Open($zip, 'Create')
        try { [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($a, $miniDs, 'mini-ds.xml') | Out-Null } finally { $a.Dispose() }
        $http.MapFile('Google_Chrome', $zip)
        Set-Transport $http
        $match = Find-PowerScapBenchmark -MatchSystem | Where-Object { $_.Checklist.Id -eq 483 }
        if (-not $match) { Set-TestInconclusive 'Chrome not installed'; return }
        $e = $match | Save-PowerScapBenchmark -CacheRoot $cacheRoot
        $e.ChecklistId | Should Be 483
        $e.FileName | Should Be 'U_Google_Chrome_V2R11_STIG_SCAP_1-4_Benchmark-enhancedV16-signed.zip'
        @(Get-PowerScapBenchmark -CacheRoot $cacheRoot).Count | Should Be 1
    }

    It 'keeps going when one download fails, and reports it' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.Map('search/results', $fixture)
        $http.MapFile('Google_Chrome', (Join-Path $work 'mini.zip'))
        $http.Fail('MS_Edge', 'HTTP 404 Not Found')
        Set-Transport $http
        $list = @(Find-PowerScapBenchmark | Where-Object { $_.Id -in 986, 483 } | Sort-Object Id -Descending)   # Edge (fails) first
        $saved = @($list | Save-PowerScapBenchmark -CacheRoot (Join-Path $work 'cache2') -ErrorVariable failures -ErrorAction SilentlyContinue)
        $saved.Count | Should Be 1
        $saved[0].ChecklistId | Should Be 483
        $reported = @($failures | Where-Object { $_.FullyQualifiedErrorId -like 'DownloadFailed*' })
        $reported.Count | Should Be 1
        "$($reported[0])" | Should Match 'Microsoft Edge STIG.*404'
    }

    It 'lists cached benchmarks offline' {
        $http = New-Object PowerScapTests.FakeTransport
        $http.Fail('http', 'offline')
        Set-Transport $http
        Import-PowerScapBenchmark -Path $miniDs -CacheRoot $cacheRoot | Out-Null
        @(Get-PowerScapBenchmark -CacheRoot $cacheRoot -Latest).Count -ge 1 | Should Be $true
    }

    It 'scans a cached benchmark from the pipeline' {
        $entry = Get-PowerScapBenchmark -CacheRoot $cacheRoot | Where-Object { $_.Imported } | Select-Object -First 1
        $scan = $entry | Invoke-PowerScapScan -CacheRoot $cacheRoot -ProfileId 'xccdf_test_profile_p1' -OutputPath $out -PassThru -AllowUnelevated
        $scan.Results.Count -gt 0 | Should Be $true
        $scan.Signature.State.ToString() | Should Be 'Unsigned'
    }

    It 'refuses tampered content and records an override' {
        $cert = New-SelfSignedCertificate -Subject 'CN=PowerSCAP Test Signer' -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable -KeySpec Signature
        try {
            $doc = New-Object Xml.XmlDocument; $doc.PreserveWhitespace = $true; $doc.Load($miniDs)
            $signed = New-Object Security.Cryptography.Xml.SignedXml($doc)
            $signed.SigningKey = $cert.PrivateKey
            $ref = New-Object Security.Cryptography.Xml.Reference(''); $ref.AddTransform((New-Object Security.Cryptography.Xml.XmlDsigEnvelopedSignatureTransform))
            $signed.AddReference($ref)
            $ki = New-Object Security.Cryptography.Xml.KeyInfo; $ki.AddClause((New-Object Security.Cryptography.Xml.KeyInfoX509Data($cert))); $signed.KeyInfo = $ki
            $signed.ComputeSignature()
            $doc.DocumentElement.AppendChild($doc.ImportNode($signed.GetXml(), $true)) | Out-Null
            $title = $doc.GetElementsByTagName('title', 'http://checklists.nist.gov/xccdf/1.2')[0]
            $title.InnerText += ' (edited)'
            $tampered = Join-Path $work 'tampered.xml'
            $doc.Save($tampered)
        }
        finally { Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue }

        { Invoke-PowerScapScan -ContentPath $tampered -ProfileId 'xccdf_test_profile_p1' -OutputPath $out -AllowUnelevated } | Should Throw 'Signature check failed for tampered.xml'
        $scan = Invoke-PowerScapScan -ContentPath $tampered -ProfileId 'xccdf_test_profile_p1' -OutputPath $out -AllowUnelevated -AllowInvalidSignature -PassThru
        [xml]$xml = Get-Content $scan.Path -Raw
        $remark = $xml.GetElementsByTagName('remark', 'http://checklists.nist.gov/xccdf/1.2') | Select-Object -Last 1
        $remark.InnerText | Should Match '^Signature verification failed and was overridden by the operator'
    }

    Set-Transport $null
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

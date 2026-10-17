$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
Add-Type -AssemblyName System.Security, System.IO.Compression, System.IO.Compression.FileSystem

$content = Join-Path $PSScriptRoot 'content'
$miniDs = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'

function Read-ZipXml([string]$Zip) {
    $a = [IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        $doc = New-Object Xml.XmlDocument; $doc.PreserveWhitespace = $true
        $s = ($a.Entries | Where-Object { $_.FullName -like '*.xml' } | Select-Object -First 1).Open()
        try { $doc.Load($s) } finally { $s.Dispose() }
        $doc
    } finally { $a.Dispose() }
}

# Signs a document in place with an enveloped C14N signature; returns the cert used.
function Add-TestSignature([Xml.XmlDocument]$Doc, $Cert) {
    $signed = New-Object Security.Cryptography.Xml.SignedXml($Doc)
    $signed.SigningKey = $Cert.PrivateKey
    $ref = New-Object Security.Cryptography.Xml.Reference('')
    $ref.AddTransform((New-Object Security.Cryptography.Xml.XmlDsigEnvelopedSignatureTransform))
    $signed.AddReference($ref)
    $ki = New-Object Security.Cryptography.Xml.KeyInfo
    $ki.AddClause((New-Object Security.Cryptography.Xml.KeyInfoX509Data($Cert)))
    $signed.KeyInfo = $ki
    $signed.ComputeSignature()
    $Doc.DocumentElement.AppendChild($Doc.ImportNode($signed.GetXml(), $true)) | Out-Null
}

Describe 'SignatureVerifier' {
    It 'reports unsigned content' {
        [PowerScap.Engine.Content.SignatureVerifier]::Verify($miniDs).State.ToString() | Should Be 'Unsigned'
    }

    It 'verifies a self-signed fixture and reports the untrusted chain, then detects tampering' {
        $cert = New-SelfSignedCertificate -Subject 'CN=PowerSCAP Test Signer' -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable -KeySpec Signature
        try {
            $doc = New-Object Xml.XmlDocument; $doc.PreserveWhitespace = $true; $doc.Load($miniDs)
            Add-TestSignature $doc $cert
            $r = [PowerScap.Engine.Content.SignatureVerifier]::Verify($doc)
            $r.State.ToString() | Should Be 'Valid'
            $r.Signer | Should Be 'CN=PowerSCAP Test Signer'
            $r.ChainTrusted | Should Be $false
            $title = $doc.GetElementsByTagName('title', 'http://checklists.nist.gov/xccdf/1.2')[0]
            $title.InnerText = $title.InnerText + ' (edited)'
            [PowerScap.Engine.Content.SignatureVerifier]::Verify($doc).State.ToString() | Should Be 'Invalid'
        }
        finally { Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue }
    }
}

Describe 'SignatureVerifier on NIWC content' -Tag Content {
    foreach ($zip in Get-ChildItem $content -Filter *.zip) {
        It "validates $($zip.Name)" {
            $r = [PowerScap.Engine.Content.SignatureVerifier]::Verify($zip.FullName)
            $r.State.ToString() | Should Be 'Valid'
            $r.Signer | Should Match 'NIWC'
        }
    }

    It 'records the signature in the cache' {
        $zip = (Get-ChildItem $content -Filter '*Edge*.zip' | Select-Object -First 1).FullName
        $root = Join-Path ([IO.Path]::GetTempPath()) ('powerscap-sig-' + [guid]::NewGuid().ToString('N'))
        try {
            $cache = New-Object PowerScap.Engine.Cache.ContentCache($root, (New-Object PowerScapTests.FakeTransport))
            $e = $cache.Import($zip)
            $e.Signature.State.ToString() | Should Be 'Valid'
            $cache.List()[0].Signature.Signer | Should Match 'NIWC'
        } finally { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'detects tampering in a NIWC data stream' {
        $doc = Read-ZipXml (Get-ChildItem $content -Filter '*Edge*.zip' | Select-Object -First 1).FullName
        $title = $doc.GetElementsByTagName('title', 'http://checklists.nist.gov/xccdf/1.2') | Select-Object -Skip 3 -First 1
        $title.InnerText = $title.InnerText + ' (edited)'
        [PowerScap.Engine.Content.SignatureVerifier]::Verify($doc).State.ToString() | Should Be 'Invalid'
    }
}

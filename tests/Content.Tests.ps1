$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
$mini = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'

Describe 'ScapContentLoader (mini data stream)' {
    $c = [PowerScap.Engine.Content.ScapContentLoader]::Load($mini)

    It 'resolves check hrefs through the catalog' {
        $c.CheckComponents.Keys -contains 'oval.xml' | Should Be $true
        $c.CheckComponents['oval.xml'].DocumentElement.LocalName | Should Be 'oval_definitions'
    }

    It 'follows a catalog entry written without the catalog namespace (NIWC OneDrive data stream)' {
        $xml = [IO.File]::ReadAllText($mini).Replace('<cat:uri name="oval.xml" uri="#scap_test_cref_oval"/>', '<ds:uri name="oval.xml" uri="#scap_test_cref_oval"/>')
        $file = Join-Path ([IO.Path]::GetTempPath()) ('powerscap-cat-' + [guid]::NewGuid().ToString('N') + '.xml')
        try {
            [IO.File]::WriteAllText($file, $xml)
            ([PowerScap.Engine.Content.ScapContentLoader]::Load($file)).CheckComponents.Keys -contains 'oval.xml' | Should Be $true
        } finally { Remove-Item $file -ErrorAction SilentlyContinue }
    }

    It 'reads the benchmark id' {
        $c.BenchmarkId | Should Be 'xccdf_test_benchmark_mini'
        $c.Benchmark.DocumentElement.LocalName | Should Be 'Benchmark'
    }

    It 'throws a clear error for a missing file' {
        { [PowerScap.Engine.Content.ScapContentLoader]::Load('C:\nope\missing.xml') } | Should Throw 'not found'
    }
}

Describe 'ScapContentLoader (real NIWC content)' -Tag Content {
    $zip = Get-ChildItem (Join-Path $PSScriptRoot 'content') -Filter '*Windows_11*.zip' -ErrorAction SilentlyContinue | Select-Object -First 1

    It 'loads real NIWC Windows 11 content and resolves every check href' {
        $zip | Should Not BeNullOrEmpty
        $c = [PowerScap.Engine.Content.ScapContentLoader]::Load($zip.FullName)
        $c.BenchmarkId | Should Be 'xccdf_mil.disa.stig_benchmark_Microsoft_Windows_11_STIG'
        $ns = New-Object System.Xml.XmlNamespaceManager($c.Benchmark.NameTable)
        $ns.AddNamespace('x', 'http://checklists.nist.gov/xccdf/1.2')
        $hrefs = $c.Benchmark.SelectNodes('//x:check-content-ref/@href', $ns) | ForEach-Object { $_.Value } | Sort-Object -Unique
        foreach ($h in $hrefs) { $c.CheckComponents.Keys -contains $h | Should Be $true }
    }
}

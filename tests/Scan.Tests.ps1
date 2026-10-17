$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
$mini = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Describe 'Invoke-PowerScapScan' {
    $out = Join-Path $env:TEMP ('PowerScapScanTest_' + [guid]::NewGuid().ToString('N'))

    $scan = Invoke-PowerScapScan -ContentPath $mini -ProfileId 'xccdf_test_profile_p1' -OutputPath $out -PassThru -AllowUnelevated
    $file = Get-ChildItem $out -Filter '*_XCCDF-Results.xml' | Select-Object -First 1
    [xml]$xml = Get-Content $file.FullName -Raw
    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('x', 'http://checklists.nist.gov/xccdf/1.2')

    It 'names the file <host>_<benchmark>_<timestamp>_XCCDF-Results.xml' {
        $file.Name | Should Match ('^' + [regex]::Escape($env:COMPUTERNAME) + '_mini_\d{8}_\d{6}_XCCDF-Results\.xml$')
    }

    It 'writes one rule-result per selected rule' {
        $xml.SelectNodes('//x:TestResult/x:rule-result', $ns).Count | Should Be 2
    }

    It 'records pass and fail results' {
        $xml.SelectSingleNode("//x:rule-result[@idref='xccdf_test_rule_r1']/x:result", $ns).InnerText | Should Be 'pass'
        $xml.SelectSingleNode("//x:rule-result[@idref='xccdf_test_rule_r2']/x:result", $ns).InnerText | Should Be 'fail'
    }

    It 'writes the default score matching -PassThru' {
        $fileScore = [double]$xml.SelectSingleNode("//x:TestResult/x:score[@system='urn:xccdf:scoring:default']", $ns).InnerText
        $passScore = ($scan.Scores | Where-Object System -eq 'urn:xccdf:scoring:default').Value
        $fileScore | Should Be $passScore
        $fileScore | Should Be 50
    }

    It 'records the target host and profile' {
        $xml.SelectSingleNode('//x:TestResult/x:target', $ns).InnerText | Should Be $env:COMPUTERNAME
        $xml.SelectSingleNode('//x:TestResult/x:profile', $ns).GetAttribute('idref') | Should Be 'xccdf_test_profile_p1'
    }

    Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Invoke-PowerScapScan elevation' {
    It 'refuses to run unelevated without -AllowUnelevated' -Skip:$isAdmin {
        { Invoke-PowerScapScan -ContentPath $mini -OutputPath $env:TEMP } | Should Throw 'PowerSCAP must run elevated.'
    }
}

$repo = Split-Path $PSScriptRoot -Parent
$tool = Join-Path $repo 'tools\Compare-XccdfResults.ps1'

function New-ResultsFile([string]$Path, [hashtable]$Results) {
    $rr = ($Results.GetEnumerator() | Sort-Object Name | ForEach-Object {
        "<rule-result idref=""$($_.Name)""><result>$($_.Value)</result></rule-result>"
    }) -join ''
    Set-Content -Path $Path -Encoding UTF8 -Value @"
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_t_benchmark_b"><TestResult id="xccdf_t_testresult_1">$rr</TestResult></Benchmark>
"@
}

Describe 'Compare-XccdfResults' {
    $dir = Join-Path $env:TEMP ('PowerScapParity_' + [guid]::NewGuid().ToString('N'))
    New-Item $dir -ItemType Directory | Out-Null
    New-ResultsFile "$dir\ref.xml" @{ r1 = 'pass'; r2 = 'fail'; r3 = 'notapplicable' }
    New-ResultsFile "$dir\same.xml" @{ r1 = 'pass'; r2 = 'fail'; r3 = 'notapplicable' }
    New-ResultsFile "$dir\changed.xml" @{ r1 = 'pass'; r2 = 'pass'; r3 = 'notapplicable' }
    New-ResultsFile "$dir\missing.xml" @{ r1 = 'pass'; r2 = 'fail' }

    It 'reports no mismatches for identical results' {
        $rows = & $tool -Reference "$dir\ref.xml" -Actual "$dir\same.xml"
        @($rows | Where-Object { -not $_.Match }).Count | Should Be 0
        $LASTEXITCODE | Should Be 0
    }

    It 'reports exactly the rule whose result changed' {
        $rows = & $tool -Reference "$dir\ref.xml" -Actual "$dir\changed.xml"
        $bad = @($rows | Where-Object { -not $_.Match })
        $bad.Count | Should Be 1
        $bad[0].RuleId | Should Be 'r2'
        $bad[0].Reference | Should Be 'fail'
        $bad[0].Actual | Should Be 'pass'
        $LASTEXITCODE | Should Be 1
    }

    It 'reports rules missing from the actual results' {
        $rows = & $tool -Reference "$dir\ref.xml" -Actual "$dir\missing.xml"
        ($rows | Where-Object RuleId -eq 'r3').Actual | Should Be '(missing)'
    }

    Remove-Item $dir -Recurse -Force
}

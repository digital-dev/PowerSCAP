$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force

$validate = Join-Path $repo 'tools\Test-ScapSchema.ps1'
$mini = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'
$machineOutputs = '(XCCDF-Results|OVAL-Results(-\d+)?|ARF)\.xml$'

function Test-Outputs([string]$Folder) {
    $files = @(Get-ChildItem $Folder -File | Where-Object { $_.Name -match $machineOutputs })
    $files.Count | Should BeGreaterThan 0
    foreach ($r in ($files | & $validate)) {
        # Name the file and its first errors, so a failure says what to fix.
        ('{0}: {1}' -f (Split-Path $r.Path -Leaf), (($r.Errors | Select-Object -First 3) -join ' | ')) |
            Should Be ('{0}: ' -f (Split-Path $r.Path -Leaf))
    }
}

Describe 'Output files are valid against the official schemas (XCCDF 1.2, OVAL 5.12.3, ARF 1.1)' {
    $out = Join-Path ([IO.Path]::GetTempPath()) ('powerscap-schema-' + [guid]::NewGuid().ToString('N'))

    It 'mini benchmark, every profile: XCCDF results, OVAL results and ARF' {
        foreach ($p in 'xccdf_test_profile_p1', 'xccdf_test_profile_p2', 'xccdf_test_profile_p3') {
            Invoke-PowerScapScan -ContentPath $mini -ProfileId $p -OutputPath (Join-Path $out $p) -Formats All -AllowUnelevated -NoHistory | Out-Null
            Test-Outputs (Join-Path $out $p)
        }
    }

    It 'reports a file that breaks the schema' {
        $bad = Join-Path $out 'bad_XCCDF-Results.xml'
        $xml = [IO.File]::ReadAllText((Get-ChildItem (Join-Path $out 'xccdf_test_profile_p1') -Filter '*_XCCDF-Results.xml')[0].FullName)
        [IO.File]::WriteAllText($bad, ($xml -replace '<TestResult ', '<TestResult bogus="1" '))
        $r = & $validate -Path $bad
        $r.Valid | Should Be $false
        ($r.Errors -join ' ') | Should Match 'bogus'
    }

    Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Real benchmarks produce valid output files' -Tag Content {
    $zips = @(Get-ChildItem (Join-Path $PSScriptRoot 'content') -Filter '*.zip' -ErrorAction SilentlyContinue)
    $out = Join-Path ([IO.Path]::GetTempPath()) ('powerscap-schema-' + [guid]::NewGuid().ToString('N'))

    It 'every benchmark in tests\content' -Skip:($zips.Count -eq 0) {
        foreach ($z in $zips) {
            $dir = Join-Path $out $z.BaseName
            Invoke-PowerScapScan -ContentPath $z.FullName -OutputPath $dir -Formats Oval, Arf -AllowUnelevated -NoHistory | Out-Null
            Test-Outputs $dir
        }
    }

    Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
}

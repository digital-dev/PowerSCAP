$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force

$mini = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'

Describe 'Scan outputs' {
    $out = Join-Path $env:TEMP ('powerscap-out-' + [guid]::NewGuid().ToString('N'))

    It 'writes XCCDF results, HTML reports and a checklist by default' {
        $scan = Invoke-PowerScapScan -ContentPath $mini -ProfileId 'xccdf_test_profile_p1' -OutputPath $out -AllowUnelevated -PassThru
        @($scan.Files.Keys | Sort-Object) -join ',' | Should Be 'All-Settings,Checklist,Non-Compliance,XCCDF'
        foreach ($f in $scan.Files.Values) { Test-Path $f | Should Be $true }
        $scan.Files['All-Settings'] | Should Match '_All-Settings\.html$'
        $scan.Files['Checklist'] | Should Match '_Checklist\.cklb$'
    }

    It 'writes OVAL results and ARF with -Formats All' {
        $scan = Invoke-PowerScapScan -ContentPath $mini -ProfileId 'xccdf_test_profile_p1' -OutputPath $out -AllowUnelevated -PassThru -Formats All
        $scan.Files.ContainsKey('ARF') | Should Be $true
        @($scan.Files.Keys | Where-Object { $_ -like 'OVAL*' }).Count -ge 1 | Should Be $true
        ([xml](Get-Content $scan.Files['ARF'] -Raw)).DocumentElement.LocalName | Should Be 'asset-report-collection'
    }

    It 'never overwrites a run from the same second' {
        $a = Invoke-PowerScapScan -ContentPath $mini -ProfileId 'xccdf_test_profile_p1' -OutputPath $out -AllowUnelevated -PassThru
        $b = Invoke-PowerScapScan -ContentPath $mini -ProfileId 'xccdf_test_profile_p1' -OutputPath $out -AllowUnelevated -PassThru
        $a.Path | Should Not Be $b.Path
        Test-Path $a.Path | Should Be $true
    }

    It 'writes a summary page when several benchmarks are scanned in one call' {
        $sub = Join-Path $out 'multi'
        $copy = Join-Path $out 'mini-copy.xml'; Copy-Item $mini $copy
        @((Get-Item $mini), (Get-Item $copy)) | Invoke-PowerScapScan -ProfileId 'xccdf_test_profile_p1' -OutputPath $sub -AllowUnelevated
        $summary = @(Get-ChildItem $sub -Filter '*_Summary.html')
        $summary.Count | Should Be 1
        $html = Get-Content $summary[0].FullName -Raw
        ([regex]::Matches($html, '<tr><td><b>')).Count | Should Be 2
        $html | Should Match '_All-Settings\.html'
    }

    Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
}

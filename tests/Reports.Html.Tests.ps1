$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force

function New-Rule([string]$Id, [string]$Result, [string]$Severity = 'medium', [string]$Details = 'Rule Result : x') {
    $r = New-Object PowerScap.Engine.Reports.RuleReport
    $r.RuleId = "xccdf_test_rule_$Id"; $r.GroupId = "V-$Id"; $r.StigId = "TEST-$Id"; $r.Title = "Rule $Id"
    $r.Severity = $Severity; $r.Cat = @{ high = 'CAT I'; medium = 'CAT II'; low = 'CAT III' }[$Severity]
    $r.Result = $Result; $r.Source = 'SCAP'; $r.Details = $Details; $r.Discussion = 'Why it matters.'
    $r
}

Describe 'HtmlReport' {
    $report = New-Object PowerScap.Engine.Reports.BenchmarkReport
    $report.Title = 'Test Benchmark'; $report.StigName = 'Test STIG'; $report.BenchmarkId = 'xccdf_test_benchmark_t'; $report.Version = '1'
    $report.Target = [PowerScap.Engine.Xccdf.TargetInfo]::Collect()
    $report.Start = Get-Date; $report.End = $report.Start
    $report.Rules.Add((New-Rule '1' 'Pass' 'high'))
    $report.Rules.Add((New-Rule '2' 'Fail' 'medium' "Collected Item/State Result : false`n    : value equals '<script>alert(1)</script>'"))
    $report.Rules.Add((New-Rule '3' 'NotApplicable' 'low'))
    $report.Rules.Add((New-Rule '4' 'Error' 'low'))
    $report.Rules.Add((New-Rule '5' 'NotChecked' 'medium'))

    $all = [PowerScap.Engine.Reports.HtmlReport]::Render($report, $false)
    $non = [PowerScap.Engine.Reports.HtmlReport]::Render($report, $true)

    It 'All-Settings lists every rule' {
        $scap = $all.Substring(0, $all.IndexOf('<section class="cat beyond">'))
        ([regex]::Matches($scap, '<details class="rule"')).Count | Should Be 5
    }

    It 'lists manual rules again in a separate Beyond SCAP section' {
        $beyond = $all.Substring($all.IndexOf('<section class="cat beyond">'))
        ([regex]::Matches($beyond, '<details class="rule"')).Count | Should Be 1
        $beyond | Should Match 'Not Reviewed'
    }

    It 'Non-Compliance lists only failing, error and unknown rules' {
        ([regex]::Matches($non, '<details class="rule"')).Count | Should Be 2
        $non | Should Match 'V-2'
        $non | Should Match 'V-4'
        $non | Should Not Match '>V-1<'
    }

    It 'escapes text taken from content and collected values' {
        $all | Should Not Match '<script>alert'
        $all | Should Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
    }

    It 'is well-formed (parses as XML)' {
        $doc = New-Object Xml.XmlDocument
        $settings = New-Object Xml.XmlReaderSettings; $settings.DtdProcessing = 'Ignore'
        $reader = [Xml.XmlReader]::Create((New-Object IO.StringReader($all)), $settings)
        { $doc.Load($reader) } | Should Not Throw
    }

    It 'shows score tiles and open CAT counts' {
        $all | Should Match 'Open findings'
        $all | Should Match '<span class="n">1</span> <span class="l">CAT II open'
    }
}

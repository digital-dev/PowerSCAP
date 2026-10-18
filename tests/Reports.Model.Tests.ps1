$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$edgeZip = Get-ChildItem (Join-Path $PSScriptRoot 'content') -Filter '*MS_Edge*.zip' -ErrorAction SilentlyContinue | Select-Object -First 1

Describe 'Report model' -Tag Content {
    $content = [PowerScap.Engine.Content.ScapContentLoader]::Load($edgeZip.FullName)
    $profileId = ($content.Benchmark.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'Profile' } | Select-Object -First 1).GetAttribute('id')
    $profile = [PowerScap.Engine.Xccdf.ProfileResolver]::Resolve($content, $profileId)
    $results = [PowerScap.Engine.Xccdf.RuleEvaluator]::Evaluate($content, $profile, [PowerScap.Engine.Oval.CollectorRegistry]::CreateDefault(), $null)
    $scores = [PowerScap.Engine.Xccdf.Scoring]::Compute($profile, $results)
    $report = [PowerScap.Engine.Reports.BenchmarkReport]::Build($content, $profile, $results, $scores, [PowerScap.Engine.Xccdf.TargetInfo]::Collect(), (Get-Date), (Get-Date))
    $rule = $report.Rules | Where-Object { $_.RuleId -like '*SV-235719r*' }

    It 'has one rule per selected rule' {
        $report.Rules.Count | Should Be @($results | Where-Object { $_.Result.ToString() -ne 'NotSelected' }).Count
    }

    It 'reads the STIG checklist metadata from the benchmark' {
        $report.StigName | Should Be 'Microsoft Edge Security Technical Implementation Guide'
        $report.StigId | Should Be 'MS_Edge_STIG'
        $report.StigReleaseInfo | Should Be 'Release: 5 Benchmark Date: 01 Apr 2026'
        $report.StigVersion | Should Be '2'
        $report.Classification | Should Be 'UNCLASSIFIED'
    }

    It 'describes a rule with its STIG fields' {
        $rule.GroupId | Should Be 'V-235719'
        $rule.GroupTitle | Should Be 'SRG-APP-000039'
        $rule.StigId | Should Be 'EDGE-00-000001'
        $rule.Cat | Should Be 'CAT III'
        $rule.Discussion | Should Match '^This action configures the proxy settings'
        $rule.CheckText | Should Match 'ProxySettings'
        $rule.FixText | Should Match '^Set the policy value'
        $rule.Ccis -join ',' | Should Be 'CCI-001414'
        $rule.DpmsIdentifier | Should Be '5280'
        $rule.DescriptionTags['Documentable'] | Should Be 'false'
    }

    It 'renders finding details with the test, requirements and collected values' {
        $rule.Details | Should Match 'Test ID\s+: oval:'
        $rule.Details | Should Match "Object Requirement\s+: check = 'hive' must be equal to 'HKEY_LOCAL_MACHINE'"
        $rule.Details | Should Match 'Rule Result\s+: '
    }

    It 'labels results as SCAP' {
        @($report.Rules | Where-Object { $_.Source -ne 'SCAP' }).Count | Should Be 0
    }
}

Describe 'Finding details' {
    $doc = New-OvalDocument -Objects '<ind:family_object id="oval:t:obj:fam" version="1"/>'
    $content = New-Object PowerScap.Engine.Content.ScapContent
    $content.CheckComponents['x.xml'] = $doc

    function New-Result([int]$ItemCount, [string]$Message) {
        $test = New-Object PowerScap.Engine.Oval.TestResult
        $test.TestId = 'oval:t:tst:1'; $test.TestType = 'family_test'; $test.Check = 'all'; $test.CheckExistence = 'at_least_one_exists'
        $test.Result = if ($Message) { 'Error' } else { 'True' }
        $test.Object = New-Object PowerScap.Engine.Oval.CollectedObject('oval:t:obj:fam')
        if ($Message) { $test.Object.Flag = 'Error'; $test.Object.Messages.Add($Message) }
        for ($i = 0; $i -lt $ItemCount; $i++) {
            $item = New-Object PowerScap.Engine.Oval.OvalItem($i, 'family_item')
            $item.Add('family', "<script>alert($i)</script>") | Out-Null
            $ir = New-Object PowerScap.Engine.Oval.ItemResult; $ir.Item = $item; $ir.Result = 'True'
            $test.Items.Add($ir); $test.Object.Items.Add($item)
        }
        $def = New-Object PowerScap.Engine.Oval.DefinitionResult; $def.DefinitionId = 'oval:t:def:1'; $def.Result = $test.Result; $def.Tests.Add($test)
        $r = New-Object PowerScap.Engine.Xccdf.RuleResult
        $r.Result = if ($Message) { 'Error' } else { 'Pass' }
        $r.CheckSystem = [PowerScap.Engine.Xccdf.XccdfNs]::OvalSystem; $r.CheckHref = 'x.xml'; $r.CheckName = 'oval:t:def:1'
        $r.OvalResults.Add($def)
        $r
    }

    It 'caps long item lists at 50 with a count of the rest' {
        $text = (New-Object PowerScap.Engine.Reports.FindingDetails($content)).Render((New-Result 120))
        ([regex]::Matches($text, 'Collected Item/State Result')).Count | Should Be 50
        $text | Should Match '\.\.\. 70 more items'
        $text | Should Match "Object ID\s+: oval:t:obj:fam \(family_object\)"
    }

    It 'includes collector messages for errors' {
        $text = (New-Object PowerScap.Engine.Reports.FindingDetails($content)).Render((New-Result 0 'Access is denied: HKEY_LOCAL_MACHINE\SECURITY'))
        $text | Should Match 'Rule Result\s+: Error'
        $text | Should Match 'Access is denied: HKEY_LOCAL_MACHINE\\SECURITY'
        $text | Should Match 'Collected Flag\s+: error'
    }
}

$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
. (Join-Path $PSScriptRoot 'TestHelpers.ps1')
$fixture = Join-Path $PSScriptRoot 'fixtures\oval\definitions.xml'

Describe 'OvalEvaluator' {
    $doc = [PowerScap.Engine.Content.ScapContentLoader]::LoadXml($fixture)
    $reg = New-Object PowerScap.Engine.Oval.CollectorRegistry
    $reg.Register((New-Object PowerScapTests.FakeCollector))
    $ev = New-Object PowerScap.Engine.Oval.OvalEvaluator($doc, $reg, $null)

    function D($id) { $ev.Evaluate($id).Result.ToString() }

    It 'existence-only test (no state) is True'                 { D 'oval:t:def:exists' | Should Be 'True' }
    It 'state mismatch with check=all is False'                 { D 'oval:t:def:mismatch' | Should Be 'False' }
    It 'negated extend_definition flips the result'             { D 'oval:t:def:extend_negated' | Should Be 'True' }
    It 'OR of error and true is True'                           { D 'oval:t:def:or_error_true' | Should Be 'True' }
    It 'false applicability_check criterion is NotApplicable'   { D 'oval:t:def:not_applicable' | Should Be 'NotApplicable' }
    It 'var_check at least one against a 2-value variable'      { D 'oval:t:def:var_check' | Should Be 'True' }
    It 'object with no collector gives Unknown'                 { D 'oval:t:def:not_collected' | Should Be 'Unknown' }
    It 'none_exist with no items is True'                       { D 'oval:t:def:none_exist' | Should Be 'True' }

    It 'records test results with their items' {
        $r = $ev.Evaluate('oval:t:def:mismatch')
        $r.Tests.Count | Should Be 1
        $r.Tests[0].TestId | Should Be 'oval:t:tst:all_are_a'
        $r.Tests[0].Items.Count | Should Be 2
        ($r.Tests[0].Items | ForEach-Object { $_.Result.ToString() }) -join ',' | Should Be 'True,False'
    }

    It 'an unknown definition id is an Error result, not an exception' {
        D 'oval:t:def:nope' | Should Be 'Error'
    }
}

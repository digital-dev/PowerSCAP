$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
$mini = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'

Describe 'ProfileResolver (mini)' {
    $content = [PowerScap.Engine.Content.ScapContentLoader]::Load($mini)
    $p2 = [PowerScap.Engine.Xccdf.ProfileResolver]::Resolve($content, 'xccdf_test_profile_p2')
    function Rule($id) { $p2.Rules | Where-Object { $_.RuleId -eq $id } }

    It 'extends the parent profile'            { (Rule 'xccdf_test_rule_r1').Selected | Should Be $true }
    It 'deselects a rule'                      { (Rule 'xccdf_test_rule_r2').Selected | Should Be $false }
    It 'refines a rule weight'                 { (Rule 'xccdf_test_rule_r1').Weight | Should Be 5 }
    It 'keeps unrefined weights'               { (Rule 'xccdf_test_rule_r4').Weight | Should Be 10 }
    It 'refines a value by selector'           { $p2.Values['xccdf_test_value_v1'] | Should Be '20' }
    It 'records the group path'                { (Rule 'xccdf_test_rule_r3').GroupPath -join '/' | Should Be 'xccdf_test_group_g2' }
    It 'leaves the default value without refinement' {
        $p1 = [PowerScap.Engine.Xccdf.ProfileResolver]::Resolve($content, 'xccdf_test_profile_p1')
        $p1.Values['xccdf_test_value_v1'] | Should Be '10'
    }
    It 'rejects an unknown profile id' {
        { [PowerScap.Engine.Xccdf.ProfileResolver]::Resolve($content, 'nope') } | Should Throw 'Profile not found'
    }
}

Describe 'CpeApplicability (mini)' {
    $content = [PowerScap.Engine.Content.ScapContentLoader]::Load($mini)
    $cpe = New-Object PowerScap.Engine.Xccdf.CpeApplicability($content, [PowerScap.Engine.Oval.CollectorRegistry]::CreateDefault())
    $ids = { param($x) $l = New-Object 'System.Collections.Generic.List[string]'; $l.Add($x); , $l }

    It 'a platform whose check is false is not applicable' { $cpe.IsApplicable((& $ids '#plat_false')) | Should Be $false }
    It 'a platform whose check is true is applicable'      { $cpe.IsApplicable((& $ids '#plat_true')) | Should Be $true }
    It 'an unknown CPE name is not applicable'             { $cpe.IsApplicable((& $ids 'cpe:/o:nobody:nothing')) | Should Be $false }
    It 'no platforms means applicable' {
        $cpe.IsApplicable((New-Object 'System.Collections.Generic.List[string]')) | Should Be $true
    }
}

Describe 'ProfileResolver (real Windows 11 content)' -Tag Content {
    $zip = Get-ChildItem (Join-Path $PSScriptRoot 'content') -Filter '*Windows_11*.zip' | Select-Object -First 1
    $content = [PowerScap.Engine.Content.ScapContentLoader]::Load($zip.FullName)

    It 'MAC-1 Classified selects 257 rules, matching SCC' {
        $p = [PowerScap.Engine.Xccdf.ProfileResolver]::Resolve($content, 'xccdf_mil.disa.stig_profile_MAC-1_Classified')
        @($p.Rules | Where-Object Selected).Count | Should Be 257
    }
}

$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force
$mini = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'

function New-Results([hashtable]$counts, [double]$weight = 10) {
    $profile = New-Object PowerScap.Engine.Xccdf.ResolvedProfile
    $list = New-Object 'System.Collections.Generic.List[PowerScap.Engine.Xccdf.RuleResult]'
    $n = 0
    foreach ($kv in $counts.GetEnumerator()) {
        for ($i = 0; $i -lt $kv.Value; $i++) {
            $rule = New-Object PowerScap.Engine.Xccdf.ResolvedRule
            $rule.RuleId = "r$((++$n))"; $rule.Weight = $weight; $rule.Selected = $true
            $profile.Rules.Add($rule)
            $rr = New-Object PowerScap.Engine.Xccdf.RuleResult
            $rr.Rule = $rule; $rr.Result = [PowerScap.Engine.Xccdf.XccdfResult]$kv.Key
            $list.Add($rr)
        }
    }
    @{ Profile = $profile; Results = $list }
}

function Get-Score($scores, $system) { $scores | Where-Object { $_.System -eq "urn:xccdf:scoring:$system" } }

Describe 'Scoring' {
    $x = New-Results @{ Pass = 194; Fail = 40; NotApplicable = 13; NotChecked = 10 }
    $scores = [PowerScap.Engine.Xccdf.Scoring]::Compute($x.Profile, $x.Results)

    It 'default matches SCC (82.9059829059829 of 100)' {
        [math]::Round((Get-Score $scores 'default').Value, 10) | Should Be 82.9059829060
        (Get-Score $scores 'default').Maximum | Should Be 100
    }
    It 'flat matches SCC (1940 of 2340)' {
        (Get-Score $scores 'flat').Value | Should Be 1940
        (Get-Score $scores 'flat').Maximum | Should Be 2340
    }
    It 'flat-unweighted matches SCC (194 of 234)' {
        (Get-Score $scores 'flat-unweighted').Value | Should Be 194
        (Get-Score $scores 'flat-unweighted').Maximum | Should Be 234
    }
    It 'absolute is 0 when anything fails' { (Get-Score $scores 'absolute').Value | Should Be 0 }

    It 'errors count as not passing (SCC Firewall: 17 pass + 3 error = 85)' {
        $y = New-Results @{ Pass = 17; Error = 3 }
        (Get-Score ([PowerScap.Engine.Xccdf.Scoring]::Compute($y.Profile, $y.Results)) 'default').Value | Should Be 85
    }
    It 'absolute is 1 when everything passes' {
        $z = New-Results @{ Pass = 5; NotApplicable = 2 }
        (Get-Score ([PowerScap.Engine.Xccdf.Scoring]::Compute($z.Profile, $z.Results)) 'absolute').Value | Should Be 1
    }
}

Describe 'RuleEvaluator (mini)' {
    $content = [PowerScap.Engine.Content.ScapContentLoader]::Load($mini)
    $reg = [PowerScap.Engine.Oval.CollectorRegistry]::CreateDefault()
    function Eval($profileId) {
        $p = [PowerScap.Engine.Xccdf.ProfileResolver]::Resolve($content, $profileId)
        $r = [PowerScap.Engine.Xccdf.RuleEvaluator]::Evaluate($content, $p, $reg, $null)
        $h = @{}; foreach ($x in $r) { $h[$x.Rule.RuleId] = $x.Result.ToString() }; $h
    }

    $p1 = Eval 'xccdf_test_profile_p1'
    $p2 = Eval 'xccdf_test_profile_p2'
    $p3 = Eval 'xccdf_test_profile_p3'

    It 'true definition passes'                  { $p1['xccdf_test_rule_r1'] | Should Be 'Pass' }
    It 'false definition fails'                  { $p1['xccdf_test_rule_r2'] | Should Be 'Fail' }
    It 'unselected rule is NotSelected'          { $p1['xccdf_test_rule_r3'] | Should Be 'NotSelected' }
    It 'inapplicable platform is NotApplicable'  { $p2['xccdf_test_rule_r3'] | Should Be 'NotApplicable' }
    It 'applicable platform is evaluated'        { $p2['xccdf_test_rule_r4'] | Should Be 'Pass' }
    It 'negated check flips fail to pass'        { $p3['xccdf_test_rule_r5'] | Should Be 'Pass' }
    It 'OCIL-only rule is NotChecked'            { $p3['xccdf_test_rule_r6'] | Should Be 'NotChecked' }
    It 'OVAL not evaluated maps to NotChecked'   { $p3['xccdf_test_rule_r7'] | Should Be 'NotChecked' }
}

$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force

function New-Rule([string]$StigId, [string]$Result = 'NotChecked', [string]$Check = 'Check the thing.', [string]$RuleId = 'SV-1r1_rule') {
    New-Object PowerScap.Engine.Reports.RuleReport -Property @{ StigId = $StigId; RuleId = $RuleId; Result = $Result; CheckText = $Check; Cat = 'CAT II'; Source = 'SCAP' }
}
function New-Report([object[]]$Rules) {
    $r = New-Object PowerScap.Engine.Reports.BenchmarkReport
    $r.BenchmarkId = 'xccdf_test_benchmark_b'
    $r.Target = New-Object PowerScap.Engine.Xccdf.TargetInfo -Property @{ HostName = 'WS01' }
    foreach ($x in $Rules) { $r.Rules.Add($x) }
    $r
}

Describe 'Review model' {
    It 'keeps the SCAP result and shows the review only for manual rules' {
        $scap = New-Rule 'A-1' 'Fail'
        $scap.Review = New-Object PowerScap.Engine.Reports.RuleReview -Property @{ Status = 'Pass'; Source = 'Answer' }
        $scap.EffectiveResult.ToString() | Should Be 'Fail'
        $scap.EffectiveSource | Should Be 'SCAP'
        $manual = New-Rule 'A-2'
        $manual.EffectiveSource | Should Be 'Manual'
        $manual.Review = New-Object PowerScap.Engine.Reports.RuleReview -Property @{ Status = 'NotApplicable'; Source = 'Script' }
        $manual.Result.ToString() | Should Be 'NotChecked'
        $manual.EffectiveResult.ToString() | Should Be 'NotApplicable'
        $manual.EffectiveSource | Should Be 'Script'
    }

    It 'counts STIG completeness apart from the SCAP results' {
        $a = New-Rule 'A-1' 'Pass'; $b = New-Rule 'A-2'; $c = New-Rule 'A-3'; $d = New-Rule 'A-4'
        $c.Review = New-Object PowerScap.Engine.Reports.RuleReview -Property @{ Status = 'Fail'; Source = 'Script' }
        $d.Review = New-Object PowerScap.Engine.Reports.RuleReview -Property @{ Status = 'NotChecked'; Source = 'Script'; Evidence = 'x' }
        $report = New-Report @($a, $b, $c, $d)
        $report.Completeness | Should Be 50
        $report.OpenEffective('CAT II') | Should Be 1
        $report.Open('CAT II') | Should Be 0
    }
}

Describe 'AnswerStore' {
    $root = Join-Path $env:TEMP ('powerscap-answers-' + [guid]::NewGuid().ToString('N'))
    $store = New-Object PowerScap.Engine.Reports.AnswerStore($root)

    It 'saves an answer and applies it on a later scan of the same rule' {
        $rule = New-Rule 'WN11-00-000070' -Check 'Review the Administrators group.' -RuleId 'SV-253269r958702_rule'
        $saved = $store.Save('WS01', 'xccdf_test_benchmark_b', $rule, 'Pass', 'Only the ISSO-approved admin.', 'CORP\reviewer')
        $saved.Status | Should Be 'pass'
        $later = New-Report @((New-Rule 'WN11-00-000070' -Check 'Review the Administrators group.' -RuleId 'SV-253269r958702_rule'))
        $store.Apply($later) | Should Be 1
        $review = $later.Rules[0].Review
        $review.Source | Should Be 'Answer'
        $review.Author | Should Be 'CORP\reviewer'
        $review.Comment | Should Be 'Only the ISSO-approved admin.'
        $review.NeedsReReview | Should Be $false
        $later.Rules[0].EffectiveResult.ToString() | Should Be 'Pass'
        $review.Label | Should Match '^Answered by CORP\\reviewer \d{4}-\d{2}-\d{2}$'
    }

    It 'flags an answer for re-review when the rule is revised or its check text changes' {
        $revised = New-Report @((New-Rule 'WN11-00-000070' -Check 'Review the Administrators group.' -RuleId 'SV-253269r999999_rule'))
        $store.Apply($revised) | Should Be 1
        $revised.Rules[0].Review.NeedsReReview | Should Be $true
        $revised.Rules[0].EffectiveResult.ToString() | Should Be 'NotChecked'
        $reworded = New-Report @((New-Rule 'WN11-00-000070' -Check 'Review the Administrators group and its nested groups.' -RuleId 'SV-253269r958702_rule'))
        $store.Apply($reworded) | Should Be 1
        $reworded.Rules[0].Review.NeedsReReview | Should Be $true
    }

    It 'never applies an answer to a rule SCAP decided' {
        $decided = New-Report @((New-Rule 'WN11-00-000070' 'Fail' -Check 'Review the Administrators group.' -RuleId 'SV-253269r958702_rule'))
        $store.Apply($decided) | Should Be 0
        $decided.Rules[0].Review | Should BeNullOrEmpty
    }

    It 'keeps answers per machine and lets one be withdrawn' {
        (New-Object PowerScap.Engine.Reports.AnswerStore($root)).Get('WS02', 'xccdf_test_benchmark_b', 'WN11-00-000070') | Should BeNullOrEmpty
        $store.Remove('WS01', 'xccdf_test_benchmark_b', 'WN11-00-000070') | Should Be $true
        $store.Get('WS01', 'xccdf_test_benchmark_b', 'WN11-00-000070') | Should BeNullOrEmpty
    }

    It 'accepts only Not a Finding, Open or Not Applicable as an answer' {
        { $store.Save('WS01', 'b', (New-Rule 'X-1'), 'NotChecked', '', 'me') } | Should Throw 'An answer is'
    }

    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'OCIL questions' {
    It 'finds a manual rule''s question through questionnaire, test action and question' {
        $content = New-Object PowerScap.Engine.Content.ScapContent
        $content.Ocil = [xml]@'
<ocil xmlns="http://scap.nist.gov/schema/ocil/2.0">
  <questionnaires><questionnaire id="ocil:t:questionnaire:1"><title>t</title><actions><test_action_ref>ocil:t:testaction:1</test_action_ref></actions></questionnaire></questionnaires>
  <test_actions><choice_question_test_action id="ocil:t:testaction:1" question_ref="ocil:t:question:1"/></test_actions>
  <questions><choice_question id="ocil:t:question:1"><question_text>Is the thing configured?</question_text></choice_question></questions>
</ocil>
'@
        $rule = ([xml]@'
<Rule xmlns="http://checklists.nist.gov/xccdf/1.2" id="r"><check system="http://scap.nist.gov/schema/ocil/2"><check-content-ref href="x-ocil.xml" name="ocil:t:questionnaire:1"/></check></Rule>
'@).DocumentElement
        (New-Object PowerScap.Engine.Reports.OcilQuestions($content)).For($rule) | Should Be 'Is the thing configured?'
        $other = ([xml]'<Rule xmlns="http://checklists.nist.gov/xccdf/1.2" id="r2"/>').DocumentElement
        (New-Object PowerScap.Engine.Reports.OcilQuestions($content)).For($other) | Should BeNullOrEmpty
    }
}

Describe 'Manual checks' {
    function New-Facts {
        $f = New-Object PowerScap.Engine.Review.ManualCheckFacts
        $f.Now = [datetime]'2026-10-18'
        $f
    }
    function User($name, $sidTail, $enabled, $last) {
        $u = New-Object PowerScap.Engine.Native.LocalUser
        $u.Name = $name; $u.Enabled = $enabled
        $u.Sid = New-Object Security.Principal.SecurityIdentifier("S-1-5-21-1-2-3-$sidTail")
        if ($last) { $u.LastLogon = [datetime]$last }
        $u
    }
    function Run($stigId, $facts) { [PowerScap.Engine.Review.ManualCheckLibrary]::For($stigId).Check($facts) }

    It 'Wi-Fi Direct: any adapter, hidden ones included, is a finding' {
        $f = New-Facts; $f.NetworkAdapters = [string[]]@('Intel(R) Wi-Fi 6E AX211', 'Microsoft Wi-Fi Direct Virtual Adapter #3')
        (Run 'WN11-00-000400' $f).Status.ToString() | Should Be 'Fail'
        $f.NetworkAdapters = [string[]]@('Intel(R) Wi-Fi 6E AX211')
        (Run 'WN11-00-000400' $f).Status.ToString() | Should Be 'Pass'
    }

    It 'unused accounts: enabled, not built-in, no logon within 35 days' {
        $f = New-Facts
        $f.LocalUsers = [PowerScap.Engine.Native.LocalUser[]]@((User 'admin' 500 $false $null), (User 'me' 1001 $true '2026-10-17'), (User 'old' 1002 $true '2026-08-01'))
        $o = Run 'WN11-00-000065' $f
        $o.Status.ToString() | Should Be 'Fail'
        $o.Evidence | Should Match 'not logged on within 35 days: old'
        $f.LocalUsers = [PowerScap.Engine.Native.LocalUser[]]@((User 'me' 1001 $true '2026-10-17'), (User 'old' 1002 $false '2026-08-01'), (User 'guest' 501 $true $null))
        (Run 'WN11-00-000065' $f).Status.ToString() | Should Be 'Pass'
        $f.LocalUsers = [PowerScap.Engine.Native.LocalUser[]]@((User 'new' 1003 $true $null))
        (Run 'WN11-00-000065' $f).Status.ToString() | Should Be 'Fail'
    }

    It 'local accounts: not applicable off a domain; on one, only built-in and administrator accounts' {
        $f = New-Facts; $f.DomainJoined = $false
        (Run 'WN11-00-000085' $f).Status.ToString() | Should Be 'NotApplicable'
        $f.DomainJoined = $true
        $f.LocalUsers = [PowerScap.Engine.Native.LocalUser[]]@((User 'Administrator' 500 $false $null), (User 'localadmin' 1001 $true $null), (User 'bob' 1002 $true $null))
        $f.GroupMembers['S-1-5-32-544'] = [string[]]@('WS01\localadmin', 'CORP\Domain Admins')
        $o = Run 'WN11-00-000085' $f
        $o.Status.ToString() | Should Be 'Fail'
        $o.Evidence | Should Match 'bob'
        $o.Evidence | Should Not Match 'localadmin'
    }

    It 'shares: not applicable with only system shares; others need review' {
        $f = New-Facts
        $f.Shares = [PowerScap.Engine.Review.ShareInfo[]]@(
            (New-Object PowerScap.Engine.Review.ShareInfo -Property @{ Name = 'ADMIN$'; Type = [uint32]2147483648 }),
            (New-Object PowerScap.Engine.Review.ShareInfo -Property @{ Name = 'C$'; Type = [uint32]2147483648 }),
            (New-Object PowerScap.Engine.Review.ShareInfo -Property @{ Name = 'IPC$'; Type = [uint32]2147483651 }))
        (Run 'WN11-00-000060' $f).Status.ToString() | Should Be 'NotApplicable'
        $f.Shares = [PowerScap.Engine.Review.ShareInfo[]](@($f.Shares) + (New-Object PowerScap.Engine.Review.ShareInfo -Property @{ Name = 'Projects'; Type = [uint32]0; Path = 'D:\Projects' }))
        $o = Run 'WN11-00-000060' $f
        $o.Status.ToString() | Should Be 'NotChecked'
        $o.Evidence | Should Match 'Projects  D:\\Projects'
    }

    It 'Backup Operators: empty is not a finding; members need review' {
        $f = New-Facts; $f.GroupMembers['S-1-5-32-551'] = [string[]]@()
        (Run 'WN11-00-000075' $f).Status.ToString() | Should Be 'Pass'
        $f.GroupMembers['S-1-5-32-551'] = [string[]]@('WS01\backup')
        (Run 'WN11-00-000075' $f).Status.ToString() | Should Be 'NotChecked'
    }

    It 'allowlisting: neither AppLocker nor WDAC in use is a finding' {
        $f = New-Facts; $f.AppLockerEnforced = [string[]]@(); $f.WdacUserModeEnforced = $false
        (Run 'WN11-00-000035' $f).Status.ToString() | Should Be 'Fail'
        $f.AppLockerEnforced = [string[]]@('Exe', 'Appx')
        (Run 'WN11-00-000035' $f).Status.ToString() | Should Be 'NotChecked'
        $f.AppLockerEnforced = [string[]]@(); $f.WdacUserModeEnforced = $true
        (Run 'WN11-00-000035' $f).Status.ToString() | Should Be 'NotChecked'
    }

    It 'hypervisors: not applicable when none is installed' {
        $f = New-Facts; $f.Hypervisors = [string[]]@()
        (Run 'WN11-00-000080' $f).Status.ToString() | Should Be 'NotApplicable'
        $f.Hypervisors = [string[]]@('VMware Workstation')
        (Run 'WN11-00-000080' $f).Status.ToString() | Should Be 'NotChecked'
    }

    It 'firewall inbound exceptions: not applicable for servers and non-domain workstations' {
        $f = New-Facts; $f.IsServer = $true
        (Run 'WNFWA-000100' $f).Status.ToString() | Should Be 'NotApplicable'
        $f.IsServer = $false; $f.DomainJoined = $false
        (Run 'WNFWA-000100' $f).Status.ToString() | Should Be 'NotApplicable'
        $f.DomainJoined = $true
        (Run 'WNFWA-000100' $f).Status.ToString() | Should Be 'NotChecked'
    }

    It 'optional browser allowlists: not used is not applicable; a configured list needs review' {
        $f = New-Facts
        $f.PolicyLists['HKLM\SOFTWARE\Policies\Microsoft\Edge\AutoplayAllowlist'] = $null
        (Run 'EDGE-00-000064' $f).Status.ToString() | Should Be 'NotApplicable'
        $f.PolicyLists['HKLM\SOFTWARE\Policies\Microsoft\Edge\AutoplayAllowlist'] = [string[]]@('1 = myagency.mil')
        $o = Run 'EDGE-00-000064' $f
        $o.Status.ToString() | Should Be 'NotChecked'
        $o.Evidence | Should Match 'myagency.mil'
    }

    It 'leaves a rule not reviewed, with the reason, when a fact could not be read' {
        $f = New-Facts; $f.Errors['network adapters'] = 'Access denied'
        $o = Run 'WN11-00-000400' $f
        $o.Status.ToString() | Should Be 'NotChecked'
        $o.Evidence | Should Be 'Could not read network adapters: Access denied'
    }

    It 'applies checks only to manual rules' {
        $f = New-Facts; $f.NetworkAdapters = [string[]]@('Microsoft Wi-Fi Direct Virtual Adapter')
        $report = New-Report @((New-Rule 'WN11-00-000400' 'Pass'), (New-Rule 'WN11-00-000400'), (New-Rule 'NO-SUCH-CHECK'))
        [PowerScap.Engine.Review.ManualCheckLibrary]::Apply($report, $f, (Get-Date)) | Should Be 1
        $report.Rules[0].Review | Should BeNullOrEmpty
        $report.Rules[1].Review.Label | Should Be 'PowerSCAP automated'
        $report.Rules[1].EffectiveResult.ToString() | Should Be 'Fail'
        $report.Rules[2].Review | Should BeNullOrEmpty
    }

    It 'reads this machine''s facts without failing' {
        $f = [PowerScap.Engine.Review.ManualCheckFacts]::Collect()
        $f.LocalUsers.Count | Should BeGreaterThan 0
        $f.NetworkAdapters.Count | Should BeGreaterThan 0
        $f.DomainJoined | Should Be (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    }
}

Describe 'Review layers in scans and outputs' {
    $mini = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'
    $root = Join-Path $env:TEMP ('powerscap-review-' + [guid]::NewGuid().ToString('N'))
    function Scan {
        $runner = [PowerScap.Engine.Scan.ScanRunner]::new($null)
        $runner.AnswersRoot = Join-Path $root 'answers'
        # Profile p3 holds the fixture's manual (OCIL) rules.
        $request = New-Object PowerScap.Engine.Scan.ScanRequest -Property @{ ContentPath = $mini; ProfileId = 'xccdf_test_profile_p3'; OutputPath = (Join-Path $root 'out'); Formats = 'Html, Cklb' }
        $runner.Run($request, $null, [Threading.CancellationToken]::None).Report
    }

    It 'applies a saved answer on the next scan, in the report, the checklist and completeness, but not in XCCDF' {
        $first = Scan
        $manual = $first.Rules | Where-Object IsManual | Select-Object -First 1
        $manual | Should Not BeNullOrEmpty
        $before = $first.Completeness
        (New-Object PowerScap.Engine.Reports.AnswerStore((Join-Path $root 'answers'))).Save($first.Target.HostName, $first.BenchmarkId, $manual, 'Fail', 'Seen on the console.', 'WS01\reviewer') | Out-Null

        Start-Sleep -Milliseconds 1100
        $second = Scan
        $rule = $second.Rules | Where-Object RuleId -eq $manual.RuleId
        $rule.Result.ToString() | Should Be 'NotChecked'
        $rule.EffectiveSource | Should Be 'Answered'
        $second.Completeness | Should BeGreaterThan $before

        $c = [PowerScap.Engine.Reports.CklbReader]::Read($second.Files['Checklist'])
        $back = $c.Stigs[0].Rules | Where-Object RuleId -eq $manual.RuleId
        [PowerScap.Engine.Reports.CklbWriter]::Status($back.Result) | Should Be 'open'
        $back.Comments | Should Be 'Seen on the console.'
        $back.Details | Should Match 'Review: Answered by WS01\\reviewer \d{4}-\d{2}-\d{2} - Open'

        [xml]$x = Get-Content $second.Files['XCCDF'] -Raw
        $ns = New-Object Xml.XmlNamespaceManager($x.NameTable); $ns.AddNamespace('x', 'http://checklists.nist.gov/xccdf/1.2')
        $x.SelectSingleNode("//x:rule-result[@idref='$($manual.RuleId)']/x:result", $ns).InnerText | Should Be 'notchecked'

        $html = Get-Content $second.Files['All-Settings'] -Raw
        $html | Should Match 'Beyond SCAP'
        $html | Should Match 'STIG completeness'
        (Get-Content $second.Files['Non-Compliance'] -Raw) | Should Match 'Seen on the console\.'
    }

    It 'rewrites a run''s report and checklist after an answer changes' {
        $report = Scan
        $manual = $report.Rules | Where-Object IsManual | Select-Object -First 1
        $manual.Review = New-Object PowerScap.Engine.Reports.RuleReview -Property @{ Status = 'NotApplicable'; Source = 'Answer'; Author = 'me'; When = (Get-Date); Comment = 'Not used here.' }
        [PowerScap.Engine.Scan.ScanRunner]::RewriteReviewedOutputs($report)
        $c = [PowerScap.Engine.Reports.CklbReader]::Read($report.Files['Checklist'])
        [PowerScap.Engine.Reports.CklbWriter]::Status(($c.Stigs[0].Rules | Where-Object RuleId -eq $manual.RuleId).Result) | Should Be 'not_applicable'
        (Get-Content $report.Files['All-Settings'] -Raw) | Should Match 'Not used here\.'
    }

    It 'skips the layers on request (SCAP results only)' {
        $runner = [PowerScap.Engine.Scan.ScanRunner]::new($null)
        $runner.ManualChecks = $false; $runner.AnswersRoot = $null
        $request = New-Object PowerScap.Engine.Scan.ScanRequest -Property @{ ContentPath = $mini; ProfileId = 'xccdf_test_profile_p1'; OutputPath = (Join-Path $root 'plain'); Formats = 'Cklb' }
        $report = $runner.Run($request, $null, [Threading.CancellationToken]::None).Report
        @($report.Rules | Where-Object { $_.Review }).Count | Should Be 0
    }

    It 'keeps HTML well-formed when collected values hold characters XML cannot carry' {
        $r = New-Object PowerScap.Engine.Reports.BenchmarkReport
        $r.Target = New-Object PowerScap.Engine.Xccdf.TargetInfo -Property @{ HostName = 'WS01' }
        $rule = New-Rule 'A-1' 'Fail'
        $rule.Details = "value: a$([char]0)b$([char]7)c"
        $r.Rules.Add($rule)
        $html = [PowerScap.Engine.Reports.HtmlReport]::Render($r, $false)
        { [xml]$html } | Should Not Throw
        $html | Should Match 'value: a\?b\?c'
    }

    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}

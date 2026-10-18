$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force

$edgeZip = Get-ChildItem (Join-Path $PSScriptRoot 'content') -Filter '*MS_Edge*.zip' -ErrorAction SilentlyContinue | Select-Object -First 1
$sccCklb = Get-ChildItem (Join-Path $env:USERPROFILE 'SCC\Sessions\2026-10-15_210812\Results\SCAP\Checklists') -Filter '*MS_Edge*.cklb' -ErrorAction SilentlyContinue | Select-Object -First 1

Describe 'CklbWriter' -Tag Content {
    $content = [PowerScap.Engine.Content.ScapContentLoader]::Load($edgeZip.FullName)
    $profileId = ($content.Benchmark.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'Profile' } | Select-Object -First 1).GetAttribute('id')
    $profile = [PowerScap.Engine.Xccdf.ProfileResolver]::Resolve($content, $profileId)
    $results = [PowerScap.Engine.Xccdf.RuleEvaluator]::Evaluate($content, $profile, [PowerScap.Engine.Oval.CollectorRegistry]::CreateDefault(), $null)
    $report = [PowerScap.Engine.Reports.BenchmarkReport]::Build($content, $profile, $results, [PowerScap.Engine.Xccdf.Scoring]::Compute($profile, $results), [PowerScap.Engine.Xccdf.TargetInfo]::Collect(), (Get-Date), (Get-Date))
    $list = New-Object 'System.Collections.Generic.List[PowerScap.Engine.Reports.BenchmarkReport]'; $list.Add($report)
    $json = [PowerScap.Engine.Reports.CklbWriter]::Render($list)
    $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer; $ser.MaxJsonLength = [int]::MaxValue
    $d = $ser.DeserializeObject($json)
    $stig = $d['stigs'][0]
    $rule = $stig['rules'] | Where-Object { $_['group_id'] -eq 'V-235719' }

    It 'has the STIG Viewer top-level keys' {
        foreach ($k in 'title', 'id', 'target_data', 'stigs', 'cklb_version') { $d.ContainsKey($k) | Should Be $true }
        $d['cklb_version'] | Should Be '1.0'
        $d['target_data']['host_name'] | Should Be $env:COMPUTERNAME
    }

    It 'describes the STIG as SCC does' {
        $stig['stig_name'] | Should Be 'Microsoft Edge Security Technical Implementation Guide'
        $stig['display_name'] | Should Be 'Microsoft Edge'
        $stig['stig_id'] | Should Be 'MS_Edge_STIG'
        $stig['release_info'] | Should Be 'Release: 5 Benchmark Date: 01 Apr 2026'
        $stig['version'] | Should Be '2'
        $stig['reference_identifier'] | Should Be '5280'
        $stig['size'] | Should Be $report.Rules.Count
    }

    It 'describes a rule as SCC does' {
        $rule['rule_id'] | Should Be 'SV-235719r1156558'
        $rule['rule_id_src'] | Should Be 'SV-235719r1156558_rule'
        $rule['rule_version'] | Should Be 'EDGE-00-000001'
        $rule['group_title'] | Should Be 'SRG-APP-000039'
        $rule['severity'] | Should Be 'low'
        $rule['weight'] | Should Be '10.0'
        @($rule['ccis']) -join ',' | Should Be 'CCI-001414'
        $rule['documentable'] | Should Be 'false'
        $rule['check_content_ref']['name'] | Should Be 'oval:navy.navwar.niwcatlantic.scc.edge:def:235719'
        $rule['finding_details'] | Should Match 'Result: (pass|fail)'
    }

    It 'maps results to STIG Viewer statuses' {
        foreach ($r in $report.Rules) {
            $c = $stig['rules'] | Where-Object { $_['rule_id_src'] -eq ($r.RuleId -replace '^.*?(SV-)', 'SV-') }
            $expected = @{ Pass = 'not_a_finding'; Fail = 'open'; NotApplicable = 'not_applicable' }[$r.Result.ToString()]
            if (-not $expected) { $expected = 'not_reviewed' }
            $c['status'] | Should Be $expected
        }
        @($stig['rules'] | Where-Object { $_['status'] -eq 'not_reviewed' }).Count -gt 0 | Should Be $true   # manual rules
    }

    It 'has every rule field SCC writes' -Skip:(-not $sccCklb) {
        $scc = $ser.DeserializeObject([IO.File]::ReadAllText($sccCklb.FullName))
        $missing = @($scc['stigs'][0]['rules'][0].Keys | Where-Object { -not $rule.ContainsKey($_) })
        $missing -join ',' | Should Be ''
        $missingStig = @($scc['stigs'][0].Keys | Where-Object { -not $stig.ContainsKey($_) })
        $missingStig -join ',' | Should Be ''
    }
}

Describe 'CklbReader' {
    $mini = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'
    $work = Join-Path $env:TEMP ('powerscap-cklb-' + [guid]::NewGuid().ToString('N'))

    It 'reads back a checklist PowerSCAP wrote, with the same rules and statuses' {
        $request = New-Object PowerScap.Engine.Scan.ScanRequest -Property @{ ContentPath = $mini; ProfileId = 'xccdf_test_profile_p1'; OutputPath = $work; Formats = 'Cklb' }
        $outcome = [PowerScap.Engine.Scan.ScanRunner]::new($null).Run($request, $null, [Threading.CancellationToken]::None)
        $c = [PowerScap.Engine.Reports.CklbReader]::Read($outcome.Report.Files['Checklist'])
        $c.HostName | Should Be $env:COMPUTERNAME
        $c.Stigs.Count | Should Be 1
        $rules = $c.Stigs[0].Rules
        $rules.Count | Should Be $outcome.Report.Rules.Count
        foreach ($r in $outcome.Report.Rules) {
            $back = $rules | Where-Object RuleId -eq $r.RuleId
            [PowerScap.Engine.Reports.CklbWriter]::Status($back.Result) | Should Be ([PowerScap.Engine.Reports.CklbWriter]::Status($r.Result))
            $back.Details | Should Match 'PowerSCAP'
        }
    }

    It 'reads checklists from other tools: several STIGs, STIG Viewer statuses, comments and CCIs' {
        New-Item -ItemType Directory $work -Force | Out-Null
        $file = Join-Path $work 'other.cklb'
        @'
{ "title": "From STIG Viewer", "cklb_version": "1.0",
  "target_data": { "host_name": "WS01", "ip_address": "10.0.0.5", "role": "Workstation" },
  "stigs": [
    { "stig_name": "Example A STIG", "version": "2", "release_info": "Release: 4", "rules": [
      { "group_id": "V-1", "rule_id_src": "SV-1r1_rule", "rule_version": "EX-01", "rule_title": "One", "severity": "high",
        "status": "open", "comments": "Waiver requested", "finding_details": "seen", "ccis": ["CCI-000001", "CCI-000002"] },
      { "group_id": "V-2", "rule_version": "EX-02", "rule_title": "Two", "severity": "medium", "status": "not_a_finding" } ] },
    { "stig_name": "Example B STIG", "rules": [
      { "group_id": "V-3", "rule_title": "Three", "severity": "low", "status": "not_applicable" },
      { "group_id": "V-4", "rule_title": "Four", "severity": "low", "status": "not_reviewed" } ] } ] }
'@ | Set-Content $file -Encoding UTF8
        $c = [PowerScap.Engine.Reports.CklbReader]::Read($file)
        $c.HostName | Should Be 'WS01'
        @($c.Stigs | ForEach-Object Name) -join '|' | Should Be 'Example A STIG|Example B STIG'
        $one = $c.Stigs[0].Rules[0]
        $one.Comments | Should Be 'Waiver requested'
        $one.Cat | Should Be 'CAT I'
        $one.Ccis -join ',' | Should Be 'CCI-000001,CCI-000002'
        @($c.Stigs | ForEach-Object { $_.Rules } | ForEach-Object { [PowerScap.Engine.Reports.CklbWriter]::Status($_.Result) }) -join '|' |
            Should Be 'open|not_a_finding|not_applicable|not_reviewed'
    }

    It 'lists checklists newest first, by STIG name and tool, each once' {
        $list = New-Object 'System.Collections.Generic.List[string]'
        $other = Join-Path $work 'other.cklb'
        (Get-Item $other).LastWriteTime = (Get-Date).AddDays(-2)
        $outside = Join-Path $env:TEMP ('powerscap-elsewhere-' + [guid]::NewGuid().ToString('N') + '.cklb')
        Copy-Item (Get-ChildItem $work -Filter '*_Checklist.cklb' | Select-Object -First 1).FullName $outside
        $list.Add($outside); $list.Add($other)
        Set-Content (Join-Path $work 'notes.cklb') -Value 'not a checklist' -Encoding ASCII
        $found = [PowerScap.Engine.Reports.CklbReader]::Find([string[]]@($work), $list)
        Remove-Item (Join-Path $work 'notes.cklb'), $outside
        $found.Count | Should Be 3
        $found[0].When | Should Not BeLessThan $found[1].When
        $canonical = [PowerScap.Engine.Reports.CklbReader]::Canonical($other)
        ($found | Where-Object { $_.Path -eq $canonical }).Title | Should Be 'Example A STIG + 1 more'
        ($found | Where-Object { $_.Path -eq $canonical }).Tool | Should Be 'Checklist'
        @($found | Where-Object Tool -eq 'PowerSCAP').Count | Should Be 2
        $found[-1].Path | Should Be $canonical
        # A short (8.3) spelling of a listed file is the same file.
        $short = (New-Object -ComObject Scripting.FileSystemObject).GetFile($other).ShortPath
        $again = [PowerScap.Engine.Reports.CklbReader]::Find([string[]]@($work), [string[]]@($short))
        @($again | Where-Object { $_.Path -eq $canonical }).Count | Should Be 1
    }

    It 'keeps only the newest checklist of each STIG per machine and tool, plus one opened on purpose' {
        function L($title, $hostName, $tool, $minutesAgo, $path) {
            New-Object PowerScap.Engine.Reports.ChecklistListing -Property @{ Title = $title; HostName = $hostName; Tool = $tool; When = (Get-Date).AddMinutes(-$minutesAgo); Path = $path }
        }
        $all = [PowerScap.Engine.Reports.ChecklistListing[]]@(
            (L 'Edge STIG' 'WS01' 'PowerSCAP' 5 'C:\r\edge-new.cklb'),
            (L 'Edge STIG' 'WS01' 'PowerSCAP' 60 'C:\r\edge-old.cklb'),
            (L 'Edge STIG' 'WS01' 'SCC' 30 'C:\r\edge-scc.cklb'),
            (L 'Edge STIG' 'WS02' 'PowerSCAP' 90 'C:\r\edge-ws02.cklb'),
            (L 'Chrome STIG' 'WS01' 'PowerSCAP' 10 'C:\r\chrome-new.cklb'),
            (L 'Chrome STIG' 'WS01' 'PowerSCAP' 120 'C:\r\chrome-old.cklb'))
        $latest = [PowerScap.Engine.Reports.CklbReader]::Latest($all, [string[]]@())
        @($latest | ForEach-Object { Split-Path $_.Path -Leaf }) -join ',' | Should Be 'edge-new.cklb,chrome-new.cklb,edge-scc.cklb,edge-ws02.cklb'
        $kept = [PowerScap.Engine.Reports.CklbReader]::Latest($all, [string[]]@('C:\r\chrome-old.cklb'))
        @($kept | ForEach-Object { Split-Path $_.Path -Leaf }) -join ',' | Should Be 'edge-new.cklb,chrome-new.cklb,edge-scc.cklb,edge-ws02.cklb,chrome-old.cklb'
    }

    It 'says plainly when a file is not a checklist' {
        $bad = Join-Path $work 'bad.cklb'
        Set-Content $bad -Value 'not json' -Encoding ASCII
        { [PowerScap.Engine.Reports.CklbReader]::Read($bad) } | Should Throw 'Not a .cklb checklist'
        Set-Content $bad -Value '{ "title": "x" }' -Encoding ASCII
        { [PowerScap.Engine.Reports.CklbReader]::Read($bad) } | Should Throw 'no "stigs" list'
    }

    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

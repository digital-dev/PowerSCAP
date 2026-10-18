$repo = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $repo 'src\PowerSCAP') -Force

$mini = Join-Path $PSScriptRoot 'fixtures\content\mini-ds.xml'

Describe 'ScanRunner' {
    $root = Join-Path $env:TEMP ('powerscap-runner-' + [guid]::NewGuid().ToString('N'))
    $out = Join-Path $root 'out'
    $hist = Join-Path $root 'history'
    function New-Request([string]$Formats = 'Html, Cklb') {
        New-Object PowerScap.Engine.Scan.ScanRequest -Property @{ ContentPath = $mini; ProfileId = 'xccdf_test_profile_p1'; OutputPath = $out; Formats = $Formats }
    }

    It 'writes nothing when the scan is cancelled' {
        $cts = New-Object Threading.CancellationTokenSource
        $cts.Cancel()
        $runner = [PowerScap.Engine.Scan.ScanRunner]::new($null)
        { $runner.Run((New-Request), $null, $cts.Token) } | Should Throw 'cancel'
        Test-Path $out | Should Be $false
    }

    It 'reports progress up to the last rule' {
        $seen = New-Object 'System.Collections.Generic.List[object]'
        $progress = New-Object 'PowerScap.Engine.Scan.SyncProgress[PowerScap.Engine.Xccdf.ScanProgress]'([Action[PowerScap.Engine.Xccdf.ScanProgress]] { param($p) $seen.Add($p) })
        $runner = [PowerScap.Engine.Scan.ScanRunner]::new($null)
        $o = $runner.Run((New-Request 'None'), $progress, [Threading.CancellationToken]::None)
        $seen.Count | Should BeGreaterThan 1
        $seen[-1].Done | Should Be $seen[-1].Total
        @($o.Report.Files.Keys) -join ',' | Should Be 'XCCDF'
    }

    It 'saves the scan to history and loads it back intact' {
        $runner = [PowerScap.Engine.Scan.ScanRunner]::new($null)
        $runner.HistoryRoot = $hist
        $o = $runner.Run((New-Request), $null, [Threading.CancellationToken]::None)
        $h = New-Object PowerScap.Engine.Scan.ScanHistory($hist)
        $list = $h.List()
        $list.Count | Should Be 1
        $list[0].BenchmarkId | Should Be $o.Report.BenchmarkId
        $list[0].Open | Should Be 1
        $back = $h.Load($list[0].ReportPath)
        $back.Rules.Count | Should Be $o.Report.Rules.Count
        ($back.Rules | ForEach-Object { "$($_.RuleId)=$($_.Result)" }) -join ';' | Should Be (($o.Report.Rules | ForEach-Object { "$($_.RuleId)=$($_.Result)" }) -join ';')
        $back.DefaultScore | Should Be $o.Report.DefaultScore
        $back.Target.HostName | Should Be $env:COMPUTERNAME
        $back.Start.ToString('s') | Should Be $o.Report.Start.ToString('s')
        $back.Files['all-settings'] | Should Be $o.Report.Files['All-Settings']
    }

    It 'finds the previous scan of the same benchmark' {
        Start-Sleep -Milliseconds 1100
        $runner = [PowerScap.Engine.Scan.ScanRunner]::new($null)
        $runner.HistoryRoot = $hist
        $o = $runner.Run((New-Request), $null, [Threading.CancellationToken]::None)
        $h = New-Object PowerScap.Engine.Scan.ScanHistory($hist)
        $h.List().Count | Should Be 2
        $h.Previous($o.Report).Start | Should BeLessThan $o.Report.Start
    }

    It 'skips history files it cannot read' {
        Set-Content (Join-Path $hist 'broken.json') -Value '{ not json' -Encoding ASCII
        (New-Object PowerScap.Engine.Scan.ScanHistory($hist)).List().Count | Should Be 2
    }

    It 'lists a benchmark''s profiles in document order' {
        $content = [PowerScap.Engine.Content.ScapContentLoader]::Load($mini)
        $p = [PowerScap.Engine.Scan.ScanRunner]::Profiles($content)
        ($p | ForEach-Object Key) -join ',' | Should Be 'xccdf_test_profile_p3,xccdf_test_profile_p1,xccdf_test_profile_p2'
    }

    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}
